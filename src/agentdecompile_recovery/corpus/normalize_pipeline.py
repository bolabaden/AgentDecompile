"""Structured decompile normalization: Ghidra facts, then Clang, then fallback.

Python owns scheduling, compiler invocation, diagnostics, metrics, and the
compile-only fallback. Semantic transforms come from HighFunction / p-code /
datatype / symbol / calling-convention / ClangTokenGroup facts, not from
growing regexes on printed C.

Two modes:

* ``semantic`` — refuse to invent layout or ABI. No GhidraBlob, no
  ``ghidra_call()``, no diagnostic stubs.
* ``compile-only`` — may apply those placeholders after structured passes
  so a corpus compile rate can be measured.

A compile is not a match. Objdiff stays a separate column.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .clang_scribe import run_clang_passes
from .high_emit import HighFacts, emit_from_facts, facts_from_tokens


class NormalizeMode(str, Enum):
    SEMANTIC = "semantic"
    COMPILE_ONLY = "compile-only"


CLAIM = (
    "Normalization is not recovery completion. Semantic mode does not invent "
    "layout or ABI. Compile-only placeholders are coverage tools, not matches."
)


@dataclass
class NormalizeResult:
    text: str
    mode: NormalizeMode
    used_high_facts: bool = False
    used_clang_ast: bool = False
    used_fallback: bool = False
    refused: list[str] = field(default_factory=list)
    clang: dict[str, Any] = field(default_factory=dict)

    def receipt(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "usedHighFacts": self.used_high_facts,
            "usedClangAst": self.used_clang_ast,
            "usedFallback": self.used_fallback,
            "refused": list(self.refused),
            "clang": dict(self.clang),
            "claimBoundary": CLAIM,
        }


def normalize_decompiled(
    code: str,
    *,
    mode: NormalizeMode | str = NormalizeMode.SEMANTIC,
    facts: HighFacts | None = None,
    fallback: Callable[[str], str] | None = None,
) -> NormalizeResult:
    """Run HighFacts emit → Clang AST passes → optional compile-only fallback."""
    resolved = NormalizeMode(mode)
    result = NormalizeResult(text=code or "", mode=resolved)
    if not result.text.strip():
        return result

    if facts is not None:
        result.text = emit_from_facts(facts, mode=resolved)
        result.used_high_facts = True
    else:
        # Token stream from printed C when Ghidra is not in-process. Identifier
        # and type tokens are rewritten from spelling metadata only.
        result.text = emit_from_facts(facts_from_tokens(result.text), mode=resolved)

    cleaned, clang_meta = run_clang_passes(result.text, mode=resolved)
    result.text = cleaned
    result.clang = clang_meta
    result.used_clang_ast = bool(clang_meta.get("used"))

    if resolved is NormalizeMode.SEMANTIC:
        for banned in ("GhidraBlob", "ghidra_call("):
            if banned in result.text:
                result.refused.append(banned)
        return result

    if fallback is not None:
        nxt = fallback(result.text)
        if nxt != result.text:
            result.text = nxt
            result.used_fallback = True
    return result


def summarize_benchmark(rows: list[dict[str, Any]], *, mode: NormalizeMode | str) -> dict[str, Any]:
    """Receipt for a corpus compile pass. Counts come from the run, not a product name."""
    resolved = NormalizeMode(mode)
    total = len(rows)
    compiled = sum(1 for row in rows if row.get("ok"))
    fallback = sum(1 for row in rows if row.get("usedFallback"))
    refused = sum(1 for row in rows if row.get("refused"))
    return {
        "mode": resolved.value,
        "functions": total,
        "compiled": compiled,
        "compileRate": (compiled / total) if total else 0.0,
        "fallbackUsed": fallback,
        "semanticRefused": refused,
        "claimBoundary": CLAIM,
    }
