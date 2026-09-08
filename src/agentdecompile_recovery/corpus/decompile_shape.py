"""Name-free decompiled-C shape features for cross-architecture matching."""

from __future__ import annotations

import hashlib
import re
from collections import Counter

_AUTO_ID = re.compile(
    r"\b(?:"
    r"[a-z]{1,3}Var\d+|"
    r"[a-z]*[Ss]tack_?[0-9a-fx]+|"
    r"local_[0-9a-fx]+|"
    r"param_\d+|"
    r"[A-Z]+_[0-9a-f]{6,16}|"
    r"unaff_\w+|extraout_\w+|in_\w+|"
    r"puVar\d+|piVar\d+|pfVar\d+|pdVar\d+"
    r")\b"
)
_NUM = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+\b")
_WS = re.compile(r"\s+")
_STRLIT = re.compile(r'"(?:[^"\\]|\\.)*"')

CTRL_WORDS = ("if", "else", "while", "for", "switch", "case", "return",
              "goto", "break", "continue", "do")

OPERATORS = ["<<", ">>", "&&", "||", "==", "!=", "<=", ">=", "->",
             "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "="]


def normalize(c: str) -> str:
    """Strip everything that encodes build-specific naming or addresses."""
    c = _STRLIT.sub('"S"', c)
    c = _AUTO_ID.sub("V", c)
    c = _NUM.sub("N", c)
    return _WS.sub(" ", c).strip()


def features(code: str) -> dict:
    body = code
    norm = normalize(body)

    ctrl = Counter()
    for word in CTRL_WORDS:
        ctrl[word] = len(re.findall(rf"\b{word}\b", body))

    ops = Counter()
    scratch = body
    for op in OPERATORS:
        ops[op] = scratch.count(op)
        scratch = scratch.replace(op, " ")

    depth = maxdepth = 0
    for ch in body:
        if ch == "{":
            depth += 1
            maxdepth = max(maxdepth, depth)
        elif ch == "}":
            depth = max(0, depth - 1)

    lines = [ln for ln in body.splitlines() if ln.strip()]
    n_locals = sum(
        1
        for ln in lines
        if (t := ln.strip()).endswith(";") and "=" not in t and "(" not in t
        and not any(t.startswith(w) for w in CTRL_WORDS)
    )

    return {
        "n_tokens": len(norm.split()),
        "n_lines": len(lines),
        "max_nest": maxdepth,
        "n_calls": len(re.findall(r"\b(?!" + "|".join(CTRL_WORDS) + r"\b)\w+\s*\(", body)),
        "n_locals": n_locals,
        "n_deref": body.count("*") + body.count("->"),
        "n_index": body.count("["),
        "n_field": body.count(".") + body.count("->"),
        "ctrl": {k: v for k, v in ctrl.items() if v},
        "ops": {k: v for k, v in ops.items() if v},
        "skeleton_hash": hashlib.blake2b(norm.encode(), digest_size=8).hexdigest(),
    }
