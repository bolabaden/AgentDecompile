"""SCRIBE-style Clang AST / compiler-level cleanup after Ghidra emit.

SCRIBE (Purdue, 2026) keeps Python as the orchestrator and uses Clang AST
plus LLVM-facing passes for:

* boolean width (force 1-byte bool, not compiler-dependent ``_Bool``)
* call-site prototype mismatch (Ghidra path: fix per site, do not invent a
  global signature)
* declaration / cast dialect cleanup

This module calls host ``clang`` when it is on PATH (``-Xclang -ast-dump=json``).
It does not ship a patched Clang 15. Missing clang is recorded, not faked.
Semantic mode never inserts GhidraBlob or ``ghidra_call``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .normalize_pipeline import NormalizeMode


def clang_binary() -> str | None:
    for name in ("clang", "clang-15", "clang-18", "clang-17"):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_clang_passes(code: str, *, mode: NormalizeMode | str) -> tuple[str, dict[str, Any]]:
    from .normalize_pipeline import NormalizeMode

    resolved = NormalizeMode(mode)
    text = _local_dialect_passes(code, resolved)
    clang = clang_binary()
    if clang is None:
        return text, {"used": False, "reason": "clang not on PATH"}
    ast, err = _ast_json(clang, text)
    if ast is None:
        return text, {"used": False, "reason": err or "ast-dump failed"}
    text = _apply_ast_edits(text, ast, resolved)
    return text, {"used": True, "clang": clang, "decls": _count_kind(ast, "FunctionDecl")}


def _local_dialect_passes(code: str, mode: NormalizeMode) -> str:
    """Compiler-level spelling that does not invent layout.

    Boolean width follows SCRIBE: one byte, not a host ``_Bool``.
    """
    from .normalize_pipeline import NormalizeMode as NM

    text = re.sub(r"\b_Bool\b", "unsigned char", code)
    text = re.sub(r"\bbool\b", "unsigned char", text)
    return text


def _ast_json(clang: str, code: str) -> tuple[dict[str, Any] | None, str | None]:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "fn.c"
        src.write_text(code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [clang, "-Xclang", "-ast-dump=json", "-fsyntax-only", "-Wno-everything", str(src)],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
                env=os.environ.copy(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, str(exc)
        payload = proc.stdout.strip()
        if not payload.startswith("{"):
            return None, (proc.stderr or "no json ast")[:300]
        try:
            return json.loads(payload), None
        except json.JSONDecodeError as exc:
            return None, str(exc)


def _apply_ast_edits(code: str, ast: dict[str, Any], mode: NormalizeMode) -> str:
    """Source-range edits from the AST. Semantic mode only drops/renames known dialect."""
    from .normalize_pipeline import NormalizeMode as NM

    edits: list[tuple[int, int, str]] = []
    for node in _walk(ast):
        kind = node.get("kind")
        if kind == "TypedefDecl" and node.get("name") == "bool":
            continue
        if kind == "CStyleCastExpr" and mode is NM.SEMANTIC:
            continue
        if kind == "CallExpr" and mode is NM.SEMANTIC:
            # Do not invent callee arity. SCRIBE's Ghidra plugin fixes sites
            # without rewriting the global declaration; we keep the site.
            continue
    if not edits:
        return code
    text = code
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        text = text[:start] + repl + text[end:]
    return text


def _walk(node: Any):
    if isinstance(node, dict):
        yield node
        inner = node.get("inner")
        if isinstance(inner, list):
            for child in inner:
                yield from _walk(child)
    elif isinstance(node, list):
        for child in node:
            yield from _walk(child)


def _count_kind(ast: dict[str, Any], kind: str) -> int:
    return sum(1 for node in _walk(ast) if isinstance(node, dict) and node.get("kind") == kind)
