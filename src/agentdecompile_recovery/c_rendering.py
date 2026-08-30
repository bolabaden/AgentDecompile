"""Shared helpers for rendering recovered metadata as valid C source."""

from __future__ import annotations

import re
from typing import Any

_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
}
_C_TYPE_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_:]*"
    r"(?:\s+[A-Za-z_][A-Za-z0-9_:]*)*"
    r"(?:\s*\*+\s*(?:const|volatile)?)*"
    r"(?:\s*\[[0-9]+\])?"
)


def c_identifier(value: Any, *, fallback: str) -> str:
    """Return a stable, keyword-safe C spelling for a recovered label."""

    text = re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))
    if not text or text[0].isdigit():
        text = f"_{text}" if text else fallback
    return f"{text}_field" if text in _C_KEYWORDS else text


def safe_c_type(value: Any, *, fallback: str) -> str:
    """Keep bounded declaration-shaped type text; reject prompt delimiters."""

    text = str(value or "").strip()
    if len(text) > 256 or _C_TYPE_RE.fullmatch(text) is None:
        return fallback
    return text


def markdown_code_block(value: Any, *, language: str = "") -> str:
    """Fence untrusted evidence with a delimiter it cannot close."""

    text = str(value or "").rstrip()
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}"


def prompt_label(value: Any, *, fallback: str, limit: int = 256) -> str:
    """Flatten untrusted text used outside fenced evidence blocks."""

    text = " ".join(str(value or "").split())[:limit]
    return text or fallback
