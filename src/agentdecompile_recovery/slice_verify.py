"""Symbolized ELF/Mach-O bounded slice verify for Phase 5c.

Produces honest weaker-than-PE-objdiff receipts. Stripped or unsized bins
return ``unsupported-slice-verify`` without failing inventory.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .source_parity_synthesize import render_target_bytes_asm, render_target_bytes_macho_asm
from .sourcegen import build_target_slice
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.slice-verify.v1"
CLAIM_BOUNDARY = (
    "slice verify is raw byte roundtrip evidence for one symbolized function; "
    "it is weaker than PE objdiff-verified-semantic proof and does not count "
    "toward the proof ladder numerator"
)


def write_slice_verify_summary(
    work_dir: Path,
    inventory: dict[str, Any],
    candidates_doc: dict[str, Any],
) -> dict[str, Any]:
    """Run bounded slice verify and write ``slice-verify/summary.json``."""

    work_dir = work_dir.resolve()
    out_dir = work_dir / "slice-verify"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = verify_symbolized_slice(work_dir, inventory, candidates_doc, out_dir=out_dir)
    atomic_write_json(out_dir / "summary.json", summary)
    return summary


def verify_symbolized_slice(
    work_dir: Path,
    inventory: dict[str, Any],
    candidates_doc: dict[str, Any],
    *,
    out_dir: Path | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    fmt = str(inventory.get("format") or "")
    base: dict[str, Any] = {
        "schema": SCHEMA,
        "writtenAt": now(),
        "workDir": str(work_dir.resolve()),
        "format": fmt,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    if fmt not in {"elf", "macho"}:
        return {**base, "status": "skipped", "reason": f"slice verify is ELF/Mach-O only; got {fmt!r}"}

    eligible, reason = is_symbolized_slice_eligible(inventory)
    if not eligible:
        return {**base, "status": "unsupported-slice-verify", "reason": reason}

    candidate_rows = candidates_doc.get("candidates")
    if not isinstance(candidate_rows, list):
        candidate_rows = []
    candidate = select_slice_candidate(candidate_rows)
    if candidate is None:
        return {
            **base,
            "status": "unsupported-slice-verify",
            "reason": "no symbolized candidate with resolvable size > 0",
        }

    target_slice = build_target_slice(inventory, candidate, None)
    if target_slice.get("status") != "complete":
        return {
            **base,
            "status": target_slice.get("status") or "slice-extract-failed",
            "reason": target_slice.get("reason") or "could not extract target bytes",
            "candidate": {"name": candidate.get("name"), "address": candidate.get("address")},
            "targetSlice": {k: target_slice.get(k) for k in ("status", "reason", "address", "size", "section")},
        }

    out_dir = out_dir or (work_dir / "slice-verify")
    out_dir.mkdir(parents=True, exist_ok=True)
    data = bytes.fromhex(str(target_slice["bytesHex"]))
    target_bytes_path = out_dir / "target.text.bin"
    target_bytes_path.write_bytes(data)

    clang = shutil.which("clang")
    objcopy = shutil.which("objcopy")
    if not clang or not objcopy:
        missing = [name for name, path in (("clang", clang), ("objcopy", objcopy)) if not path]
        return {
            **base,
            "status": "blocked:toolchain",
            "reason": f"missing tools: {', '.join(missing)}",
            "candidate": {"name": candidate.get("name"), "address": candidate.get("address"), "size": candidate.get("size")},
        }

    symbol = _asm_symbol(fmt, candidate)
    asm_source = (
        render_target_bytes_macho_asm(symbol, data)
        if fmt == "macho"
        else render_target_bytes_asm(symbol, data)
    )
    asm_path = out_dir / "candidate.S"
    obj_path = out_dir / "candidate.o"
    candidate_text_path = out_dir / "candidate.text.bin"
    asm_path.write_text(asm_source, encoding="utf-8")

    compile_proc = subprocess.run(
        [clang, "-c", str(asm_path), "-o", str(obj_path)],
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if compile_proc.returncode != 0 or not obj_path.is_file():
        return {
            **base,
            "status": "compile-failed",
            "reason": (compile_proc.stderr or compile_proc.stdout or "clang failed")[-2000:],
            "candidate": {"name": candidate.get("name"), "address": candidate.get("address"), "size": len(data)},
        }

    objcopy_proc = subprocess.run(
        [objcopy, "-O", "binary", "-j", ".text", str(obj_path), str(candidate_text_path)],
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if objcopy_proc.returncode != 0 or not candidate_text_path.is_file():
        return {
            **base,
            "status": "extract-failed",
            "reason": (objcopy_proc.stderr or objcopy_proc.stdout or "objcopy failed")[-2000:],
            "candidate": {"name": candidate.get("name"), "address": candidate.get("address"), "size": len(data)},
        }

    candidate_bytes = candidate_text_path.read_bytes()
    matched = candidate_bytes == data
    verification_tier = "code-slice" if matched else "generated"
    receipt = {
        **base,
        "status": "matched" if matched else "mismatch",
        "verificationTier": verification_tier,
        "method": "raw-byte-roundtrip",
        "candidate": {
            "name": candidate.get("name"),
            "address": candidate.get("address"),
            "size": len(data),
            "source": candidate.get("source"),
        },
        "targetSlice": {
            "address": target_slice.get("address"),
            "size": target_slice.get("size"),
            "section": target_slice.get("section"),
            "bytesSha256": target_slice.get("bytesSha256"),
            "targetBytesPath": str(target_bytes_path),
        },
        "artifacts": {
            "asm": str(asm_path),
            "object": str(obj_path),
            "candidateText": str(candidate_text_path),
        },
        "byteLength": len(data),
        "rawMatch": matched,
    }
    atomic_write_json(out_dir / "receipt.json", receipt)
    return receipt


def is_symbolized_slice_eligible(inventory: dict[str, Any]) -> tuple[bool, str]:
    fmt = str(inventory.get("format") or "")
    if fmt not in {"elf", "macho"}:
        return False, "unsupported-format"
    symbols = inventory.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        return False, "no symbol table"
    function_symbols = [
        sym
        for sym in symbols
        if isinstance(sym, dict)
        and sym.get("type") == 2
        and int(sym.get("sectionIndex") or 0) != 0
        and int(sym.get("value") or 0) != 0
    ]
    if not function_symbols:
        return False, "no function symbols in symbol table"
    sized = [sym for sym in function_symbols if int(sym.get("size") or 0) > 0]
    if not sized:
        return False, "function symbols present but no resolvable sizes"
    return True, "eligible"


def select_slice_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred_sources = {"elf-symbol", "macho-symbol"}
    for row in candidates:
        if not isinstance(row, dict):
            continue
        if row.get("source") in preferred_sources and int(row.get("size") or 0) > 0:
            return row
    for row in candidates:
        if isinstance(row, dict) and int(row.get("size") or 0) > 0 and row.get("address") is not None:
            return row
    return None


def _asm_symbol(fmt: str, candidate: dict[str, Any]) -> str:
    name = str(candidate.get("name") or "slice_fn")
    cleaned = name.lstrip("_")
    symbol = cleaned if cleaned else "slice_fn"
    if fmt == "macho":
        return symbol if symbol.startswith("_") else f"_{symbol}"
    return symbol
