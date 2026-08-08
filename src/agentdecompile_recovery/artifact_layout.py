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
# docs/CRITICAL_PATH.md: verified/ holds full-object proofs, verified/code-slice/
# holds slice proofs (still verified, not advisory).
CODE_SLICE_DIR_NAME = "code-slice"

_VERIFIED_CLAIM_BOUNDARY = (
    "Receipt-backed objdiff-zero accept only; not whole-program semantic parity."
)
_CODE_SLICE_CLAIM_BOUNDARY = (
    "Code-slice evidence only: objdiff zero against target slice bytes, not a full "
    "target-object match, and not whole-program semantic parity."
)


def _merge_claim_boundary(caller: Any, publisher: str) -> str:
    """Compose claim boundaries by conjunction so publishing can never weaken one.

    Both strings are limits on what the artifact proves, so keeping both narrows
    the claim. Publishing may add a limit; it must never drop the caller's.
    """

    text = str(caller or "").strip()
    if not text:
        return publisher
    if publisher.lower() in text.lower():
        return text
    if not text.endswith((".", ";", "!", "?")):
        text = f"{text}."
    return f"{text} {publisher}"


def publish_verified_artifact(
    run_dir: Path,
    *,
    stem: str,
    source: Path,
    metadata: dict[str, Any],
) -> dict[str, str]:
    """Copy an objdiff-zero accept into ``run_dir/verified/`` with a receipt sidecar.

    Full target-object accepts land at ``verified/``; anything weaker that still
    carries slice evidence lands at ``verified/code-slice/``.
    """

    payload = dict(metadata)
    payload.setdefault("schema", "agentdecompile.verified-artifact.v1")
    payload.setdefault("proofTier", OBJDIFF_PROOF_TIER)
    payload.setdefault("status", "source-parity-accepted")
    full_object = is_objdiff_zero_accept(payload)
    verified = run_dir / "verified" if full_object else run_dir / "verified" / CODE_SLICE_DIR_NAME
    verified.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix if source.suffix else ".c"
    dest_source = verified / f"{stem}{suffix}"
    dest_meta = verified / f"{stem}.json"
    receipt = verified / f"{stem}.objdiff-verified.json"
    shutil.copy2(source, dest_source)
    payload["source"] = str(dest_source)
    payload["claimBoundary"] = _merge_claim_boundary(
        metadata.get("claimBoundary"),
        _VERIFIED_CLAIM_BOUNDARY if full_object else _CODE_SLICE_CLAIM_BOUNDARY,
    )
    atomic_write_json(dest_meta, payload)
    atomic_write_json(
        receipt,
        {
            "schema": "agentdecompile.objdiff-verified.v1",
            # Mirror the metadata tier. A caller-supplied weaker tier must never be
            # restamped here as full target-object parity.
            "proofTier": payload["proofTier"],
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


def _differences(row: dict[str, Any]) -> int:
    try:
        return int(row.get("differences", -1))
    except (TypeError, ValueError):
        return -1


def is_objdiff_zero_accept(row: dict[str, Any]) -> bool:
    differences = _differences(row)
    status = str(row.get("status") or "")
    proof = str(row.get("proofTier") or row.get("verificationTier") or "")
    if status == "matched" and differences == 0:
        return True
    if status == "source-parity-accepted" and proof == OBJDIFF_PROOF_TIER:
        return True
    return False


def is_code_slice_accept(row: dict[str, Any]) -> bool:
    """True for a slice proof: objdiff zero against target slice bytes, not a target object.

    Weaker than :func:`is_objdiff_zero_accept` by construction, and routed to
    ``verified/code-slice/`` rather than the full-object ``verified/`` root.
    """

    return str(row.get("status") or "") == "code-slice-matched" and _differences(row) == 0
