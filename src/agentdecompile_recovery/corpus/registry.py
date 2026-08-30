"""Register binaries into a corpus without rewriting the pipeline.

The corpus file is the operator surface: add a binary, optionally name a
STABS/DWARF donor, set per-pair match thresholds. Product names never go in
as defaults.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .contract import (
    DEFAULT_ATLAS_PORT,
    DEFAULT_DASHBOARD_PORT,
    DEFAULT_REPORT_PORT,
    SCHEMA,
)

DEBUG_KINDS = ("stabs", "dwarf", "none")


@dataclass
class BinaryEntry:
    id: str
    path: str
    debug: str = "none"
    role: str = "member"
    label: str = ""
    arch: str = ""
    bits: int = 0
    format: str = ""
    game: str = ""
    exclude: bool = False

    def __post_init__(self) -> None:
        if self.debug not in DEBUG_KINDS:
            raise ValueError(f"debug must be one of {DEBUG_KINDS}, got {self.debug!r}")
        if self.role not in ("donor", "member"):
            raise ValueError(f"role must be donor or member, got {self.role!r}")
        if not self.id.strip():
            raise ValueError("binary id is required")


@dataclass
class PairThreshold:
    left: str
    right: str
    min_confidence: float = 0.55
    reason: str = ""


@dataclass
class CorpusManifest:
    id: str
    binaries: list[BinaryEntry] = field(default_factory=list)
    donor_id: str | None = None
    pair_thresholds: list[PairThreshold] = field(default_factory=list)
    dashboard_port: int = DEFAULT_DASHBOARD_PORT
    atlas_port: int = DEFAULT_ATLAS_PORT
    report_port: int = DEFAULT_REPORT_PORT
    known_globals: dict[str, str] = field(default_factory=dict)
    schema: str = SCHEMA

    def binary(self, binary_id: str) -> BinaryEntry:
        for entry in self.binaries:
            if entry.id == binary_id:
                return entry
        raise KeyError(binary_id)

    def donor(self) -> BinaryEntry | None:
        if self.donor_id:
            return self.binary(self.donor_id)
        for entry in self.binaries:
            if entry.role == "donor" or entry.debug in ("stabs", "dwarf"):
                return entry
        return None

    def threshold_for(self, left: str, right: str) -> float:
        for pair in self.pair_thresholds:
            if {pair.left, pair.right} == {left, right}:
                return float(pair.min_confidence)
        return 0.55

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "id": self.id,
            "donorId": self.donor_id,
            "dashboardPort": self.dashboard_port,
            "atlasPort": self.atlas_port,
            "reportPort": self.report_port,
            "binaries": [asdict(item) for item in self.binaries],
            "pairThresholds": [asdict(item) for item in self.pair_thresholds],
            "knownGlobals": dict(self.known_globals),
            "claimBoundary": (
                "Registry membership is not recovery. A binary is recovered only "
                "when later stages write compile and verify receipts."
            ),
        }


def load_corpus(path: Path) -> CorpusManifest:
    raw = json.loads(path.read_text(encoding="utf-8"))
    binaries = [BinaryEntry(**row) for row in raw.get("binaries") or []]
    pairs = []
    for row in raw.get("pairThresholds") or raw.get("pair_thresholds") or []:
        pairs.append(
            PairThreshold(
                left=row.get("left") or row["left"],
                right=row.get("right") or row["right"],
                min_confidence=float(row.get("min_confidence", row.get("minConfidence", 0.55))),
                reason=str(row.get("reason") or ""),
            )
        )
    return CorpusManifest(
        id=str(raw.get("id") or path.stem),
        binaries=binaries,
        donor_id=raw.get("donorId") or raw.get("donor_id"),
        pair_thresholds=pairs,
        dashboard_port=int(raw.get("dashboardPort", DEFAULT_DASHBOARD_PORT)),
        atlas_port=int(raw.get("atlasPort", DEFAULT_ATLAS_PORT)),
        report_port=int(raw.get("reportPort", DEFAULT_REPORT_PORT)),
        known_globals=dict(raw.get("knownGlobals") or raw.get("known_globals") or {}),
        schema=str(raw.get("schema") or SCHEMA),
    )


def save_corpus(path: Path, corpus: CorpusManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(corpus.to_json(), indent=2) + "\n", encoding="utf-8")


def new_corpus(corpus_id: str, *, work_dir: Path | None = None) -> CorpusManifest:
    return CorpusManifest(id=corpus_id)


def add_binary(
    corpus: CorpusManifest,
    *,
    binary_id: str,
    path: Path | str,
    debug: str = "none",
    role: str | None = None,
    label: str = "",
    donor: bool = False,
) -> CorpusManifest:
    """Add or replace one binary. `donor=True` marks STABS/DWARF layout source."""
    resolved_role = role or ("donor" if donor or debug in ("stabs", "dwarf") else "member")
    if donor:
        resolved_role = "donor"
        corpus.donor_id = binary_id
    entry = BinaryEntry(
        id=binary_id,
        path=str(path),
        debug=debug,
        role=resolved_role,
        label=label,
    )
    corpus.binaries = [item for item in corpus.binaries if item.id != binary_id]
    corpus.binaries.append(entry)
    if resolved_role == "donor":
        corpus.donor_id = binary_id
    return corpus
