"""Evidence-ranked module path resolution for recovered source dumps."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


FALLBACK_MODULE = "recovered/unmapped"


@dataclass
class ModuleEvidence:
    entry: int
    module: str
    provenance: str
    score: float


@dataclass
class ModuleResolver:
    """Resolve module paths from ranked evidence (assert strings, RTTI, call graph).

    Optional ``va_bands`` maps (end_exclusive, module) sorted by end address for
    legacy PE banding when an operator supplies a profile JSON — never hardcoded
    to a particular product.
    """

    assert_paths_by_entry: dict[int, str] = field(default_factory=dict)
    rtti_module_by_entry: dict[int, str] = field(default_factory=dict)
    call_graph: dict[int, list[int]] = field(default_factory=dict)
    va_bands: list[tuple[int, str]] = field(default_factory=list)

    def resolve(self, entry: int) -> ModuleEvidence:
        if entry in self.assert_paths_by_entry:
            module = normalize_code_path(self.assert_paths_by_entry[entry])
            return ModuleEvidence(entry=entry, module=module, provenance="assert-string", score=1.0)
        if entry in self.rtti_module_by_entry:
            module = normalize_code_path(self.rtti_module_by_entry[entry])
            return ModuleEvidence(entry=entry, module=module, provenance="rtti-class", score=0.8)
        vote = self._callgraph_vote(entry)
        if vote is not None:
            return vote
        band = self._va_band(entry)
        if band is not None:
            return ModuleEvidence(entry=entry, module=band, provenance="va-band", score=0.2)
        return ModuleEvidence(entry=entry, module=FALLBACK_MODULE, provenance="fallback", score=0.0)

    def _va_band(self, entry: int) -> str | None:
        for end, module in self.va_bands:
            if entry < end:
                return module
        return None

    def _callgraph_vote(self, entry: int) -> ModuleEvidence | None:
        neighbors = self.call_graph.get(entry) or []
        modules: list[str] = []
        for neighbor in neighbors:
            if neighbor in self.assert_paths_by_entry:
                modules.append(normalize_code_path(self.assert_paths_by_entry[neighbor]))
            elif neighbor in self.rtti_module_by_entry:
                modules.append(normalize_code_path(self.rtti_module_by_entry[neighbor]))
        if not modules:
            return None
        counts = Counter(modules)
        top, top_n = counts.most_common(1)[0]
        if len(counts) > 1 and list(counts.values()).count(top_n) > 1:
            return None
        return ModuleEvidence(entry=entry, module=top, provenance="callgraph-vote", score=0.5)


def normalize_code_path(raw: str) -> str:
    """Normalize embedded source paths to Port/CODE module directories."""
    text = raw.replace("\\", "/")
    for prefix in ("../CODE/", "CODE/", "Port/CODE/", "src/", "source/", "Source/"):
        if prefix in text:
            text = text.split(prefix, 1)[1]
            break
    text = text.lstrip("./")
    if text.endswith((".cpp", ".c", ".h", ".hpp", ".cc", ".cxx")):
        parts = text.rsplit("/", 1)
        if len(parts) == 2:
            return parts[0]
        stem = parts[0].rsplit(".", 1)[0]
        return f"recovered/{stem}"
    return text.rstrip("/")


# Private alias kept for older internal imports.
_normalize_code_path = normalize_code_path


def passes_readability_gate(*, name: str | None, module: str | None, module_provenance: str | None) -> bool:
    """Port/CODE requires an evidence-backed name and non-fallback module."""
    if not name or str(name).startswith("FUN_"):
        return False
    if not module or module == FALLBACK_MODULE:
        return False
    if module_provenance in {None, "", "fallback"}:
        return False
    return True


def infer_repair_class(*, name: str | None, module: str | None, module_provenance: str | None) -> str:
    """Suggest a v1-safe advisory repair action for sub-gate functions."""
    if not name or str(name).startswith("FUN_"):
        return "rename"
    if not module or module == FALLBACK_MODULE or module_provenance in {None, "", "fallback"}:
        return "module-refresh"
    return "re-enrich"


def load_va_bands(raw: Any) -> list[tuple[int, str]]:
    """Parse optional VA band config: list of {end, module} or [end, module]."""
    if not raw:
        return []
    bands: list[tuple[int, str]] = []
    if isinstance(raw, dict):
        raw = [{"end": k, "module": v} for k, v in raw.items()]
    if not isinstance(raw, list):
        return []
    for item in raw:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            bands.append((int(item[0], 0) if isinstance(item[0], str) else int(item[0]), str(item[1])))
        elif isinstance(item, dict) and "end" in item and "module" in item:
            end = item["end"]
            bands.append((int(end, 0) if isinstance(end, str) else int(end), str(item["module"])))
    return sorted(bands, key=lambda pair: pair[0])
