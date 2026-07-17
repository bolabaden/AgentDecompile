"""Claim-report helper for honest recovery outcomes.

Every reconstruct/recover run should be able to emit a machine-readable claim
summary that separates verified artifacts from advisory ones.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import atomic_write_json


CLAIM_CLASSES = (
    "objdiff-verified-semantic",
    "byte-authoritative",
    "advisory-decompiler",
    "context-hint",
    "unverified-candidate",
)

NON_CLAIMS = (
    "byte-authority packages are not semantic source recovery",
    "decompiler/LLM candidates are advisory until objdiff-verified-semantic",
    "context notes and Ghidra dumps do not establish parity by themselves",
    "bare verified/ trees and acceptedCandidates counts alone are not objdiff proof",
)

_OBJDIFF_PROOF_TIERS = {
    "target-object-objdiff-match",
    "target-object-objdiff",
    "synthetic-target-object-objdiff",
}


def _count_files(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for path in directory.rglob("*") if path.is_file())


def _is_objdiff_receipt(data: dict[str, Any], *, path: Path | None = None) -> bool:
    """True only when a sidecar/manifest row carries objdiff-zero proof."""

    if path is not None and "objdiff" in path.name.lower():
        # Conventional receipt name under verified/ (e.g. objdiff-verified.json).
        if isinstance(data.get("count"), int) and data["count"] > 0:
            return True
        functions = data.get("functions")
        if isinstance(functions, list) and functions:
            return True

    proof = str(data.get("proofTier") or data.get("verificationTier") or "")
    if proof in _OBJDIFF_PROOF_TIERS or "objdiff" in proof.lower():
        if "differences" in data:
            try:
                return int(data.get("differences")) == 0
            except (TypeError, ValueError):
                return False
        return data.get("status") in {"matched", "source-parity-accepted", "code-slice-matched"}
    status = str(data.get("status") or "")
    if status in {"matched", "source-parity-accepted"} and "differences" in data:
        try:
            return int(data.get("differences")) == 0
        except (TypeError, ValueError):
            return False
    return False


def _count_objdiff_verified(work_dir: Path) -> int:
    """Count receipt-backed objdiff accepts; ignore bare source files."""

    count = 0
    search_roots = (
        work_dir / "verified",
        work_dir / "recovered-source" / "functions",
    )
    for root in search_roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict) or not _is_objdiff_receipt(data, path=path):
                continue
            if "objdiff" in path.name.lower() and isinstance(data.get("count"), int):
                count += max(int(data["count"]), 1)
            else:
                count += 1
    return count


def build_claim_report(
    *,
    work_dir: Path,
    terminal_status: str = "partial",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a claim summary from conventional reconstruct layout."""

    work_dir = work_dir.resolve()
    verified_dir = work_dir / "verified"
    advisory_dir = work_dir / "advisory"
    byte_dir = work_dir / "byte-authority"
    acquisition = work_dir / "acquisition" / "acquire.json"

    verified_count = _count_files(verified_dir)
    advisory_count = _count_files(advisory_dir)
    byte_count = _count_files(byte_dir) if byte_dir.exists() else 0
    objdiff_verified = _count_objdiff_verified(work_dir)

    accepted = 0
    synth_path = work_dir / "source-synthesis" / "summary.json"
    if synth_path.exists():
        try:
            synth = json.loads(synth_path.read_text(encoding="utf-8"))
            accepted = int(synth.get("acceptedCandidates") or synth.get("accepted") or 0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            accepted = 0

    claims: list[dict[str, Any]] = []
    # Bare verified/ trees and acceptedCandidates alone must not become semantic claims.
    if objdiff_verified:
        claims.append(
            {
                "class": "objdiff-verified-semantic",
                "count": objdiff_verified,
                "path": str(verified_dir) if verified_dir.exists() else str(work_dir / "recovered-source" / "functions"),
            }
        )
    unverified = max(0, verified_count - objdiff_verified) + (accepted if not objdiff_verified else 0)
    if unverified and not objdiff_verified:
        claims.append(
            {
                "class": "unverified-candidate",
                "count": unverified,
                "path": str(verified_dir) if verified_dir.exists() else None,
                "note": "verified/ or acceptedCandidates without objdiff proof receipts",
            }
        )
    if advisory_count:
        claims.append(
            {
                "class": "advisory-decompiler",
                "count": advisory_count,
                "path": str(advisory_dir),
            }
        )
    if byte_count:
        claims.append(
            {
                "class": "byte-authoritative",
                "count": byte_count,
                "path": str(byte_dir),
            }
        )
    if acquisition.exists():
        claims.append(
            {
                "class": "context-hint",
                "count": 1,
                "path": str(acquisition),
            }
        )

    report: dict[str, Any] = {
        "schema": "agentdecompile.claim-report.v1",
        "terminalStatus": terminal_status,
        "workDir": str(work_dir),
        "counts": {
            "verified": verified_count,
            "advisory": advisory_count,
            "byteAuthoritative": byte_count,
            "acceptedCandidates": accepted,
            "objdiffVerified": objdiff_verified,
        },
        "claims": claims,
        "nonClaims": list(NON_CLAIMS),
        "claimClasses": list(CLAIM_CLASSES),
        "claimBoundary": (
            "This report summarizes orchestration outcomes and artifact classes. "
            "Only receipt-backed objdiff-verified-semantic entries are accepted semantic matches."
        ),
    }
    try:
        from .proof_ladder import build_proof_ladder

        ladder = build_proof_ladder(work_dir)
        report["proofLadder"] = {
            "status": ladder.get("status"),
            "denominator": ladder.get("denominator"),
            "numerator": ladder.get("numerator"),
            "coverage": ladder.get("coverage"),
            "coveragePercent": ladder.get("coveragePercent"),
            "rung": ladder.get("rung"),
            "nextRung": ladder.get("nextRung"),
            "claimBoundary": ladder.get("claimBoundary"),
        }
    except (OSError, TypeError, ValueError, ImportError, KeyError):
        # Ladder is additive honesty metadata; never block claim report emission.
        report["proofLadder"] = None
    if extra:
        report["extra"] = extra
    return report


def write_claim_report(work_dir: Path, terminal_status: str = "partial") -> Path:
    from .proof_ladder import write_proof_ladder

    write_proof_ladder(work_dir)
    report = build_claim_report(work_dir=work_dir, terminal_status=terminal_status)
    out = work_dir / "claim-report.json"
    atomic_write_json(out, report)
    return out
