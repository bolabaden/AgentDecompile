"""On-disk verified/ vs advisory/ segregation for reconstruct work dirs.

Claim-report and recovery-status already count these trees. This module is the
writer side so partial runs actually populate them.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .state import atomic_write_json

OBJDIFF_PROOF_TIER = "target-object-objdiff-match"


def publish_verified_artifact(
    run_dir: Path,
    *,
    stem: str,
    source: Path,
    metadata: dict[str, Any],
) -> dict[str, str]:
    """Copy an objdiff-zero accept into ``run_dir/verified/`` with a receipt sidecar."""

    verified = run_dir / "verified"
    verified.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix if source.suffix else ".c"
    dest_source = verified / f"{stem}{suffix}"
    dest_meta = verified / f"{stem}.json"
    receipt = verified / f"{stem}.objdiff-verified.json"
    shutil.copy2(source, dest_source)
    payload = dict(metadata)
    payload.setdefault("schema", "agentdecompile.verified-artifact.v1")
    payload.setdefault("proofTier", OBJDIFF_PROOF_TIER)
    payload.setdefault("status", "source-parity-accepted")
    payload["source"] = str(dest_source)
    payload["claimBoundary"] = (
        "Receipt-backed objdiff-zero accept only; not whole-program semantic parity."
    )
    atomic_write_json(dest_meta, payload)
    atomic_write_json(
        receipt,
        {
            "schema": "agentdecompile.objdiff-verified.v1",
            "proofTier": OBJDIFF_PROOF_TIER,
            "status": payload.get("status"),
            "differences": int(payload.get("differences") or 0),
            "count": 1,
            "functions": [{"name": payload.get("name"), "entry": payload.get("entry") or payload.get("address")}],
            "source": str(dest_source),
            "metadata": str(dest_meta),
        },
    )
    return {"source": str(dest_source), "metadata": str(dest_meta), "receipt": str(receipt)}


def publish_advisory_artifact(
    run_dir: Path,
    *,
    stem: str,
    source: Path,
    metadata: dict[str, Any],
) -> dict[str, str]:
    """Copy an unverified/decompiler candidate into ``run_dir/advisory/``."""

    advisory = run_dir / "advisory"
    advisory.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix if source.suffix else ".c"
    dest_source = advisory / f"{stem}{suffix}"
    dest_meta = advisory / f"{stem}.json"
    shutil.copy2(source, dest_source)
    payload = dict(metadata)
    payload.setdefault("schema", "agentdecompile.advisory-artifact.v1")
    payload.setdefault("status", "generated-unverified")
    payload["source"] = str(dest_source)
    payload["claimBoundary"] = (
        "Advisory candidate only; compile + objdiff-zero required before verified/ promotion."
    )
    atomic_write_json(dest_meta, payload)
    return {"source": str(dest_source), "metadata": str(dest_meta)}


def is_objdiff_zero_accept(row: dict[str, Any]) -> bool:
    try:
        differences = int(row.get("differences", -1))
    except (TypeError, ValueError):
        differences = -1
    status = str(row.get("status") or "")
    proof = str(row.get("proofTier") or row.get("verificationTier") or "")
    if status == "matched" and differences == 0:
        return True
    if status == "source-parity-accepted" and proof == OBJDIFF_PROOF_TIER:
        return True
    return False
