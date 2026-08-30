"""Single test for recovered source vs machine-code shim.

Ported from kotorxid `kx/realc.py`. Nothing else may re-derive this test.
Real C, compile success, and byte-accuracy are three separate properties.
"""

from __future__ import annotations

import re

SHIM_RE = re.compile(
    r"""
      \bnaked\b
    | __asm
    | \b_emit\b
    | \.byte\b
    | \bKOTOR_NAKED\b
    | \bKOTOR_ASM_BEGIN\b
    | \bKOTOR_ASM_END\b
    | \bKOTOR_BYTES\b
    | \bincbin\b
    """,
    re.I | re.X,
)

SYMBOL_ALIAS_RE = re.compile(r"""(?<!\w)__asm__?\s*\(\s*"[^"\n]*"\s*\)""", re.I)
_VOLATILE_ASM_RE = re.compile(r"(?<!\w)__asm__?\s+volatile", re.I)


def _strip_symbol_aliases(source: str) -> str:
    if _VOLATILE_ASM_RE.search(source):
        return source
    return SYMBOL_ALIAS_RE.sub("", source)


def is_real_c(source: str | None) -> bool:
    return not SHIM_RE.search(_strip_symbol_aliases(source or ""))


def shim_reason(source: str | None) -> str | None:
    match = SHIM_RE.search(_strip_symbol_aliases(source or ""))
    return match.group(0) if match else None


def is_machine_code_shim(text: str | None) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    return not is_real_c(body)


def is_recovered_source(text: str | None) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    return is_real_c(body)
