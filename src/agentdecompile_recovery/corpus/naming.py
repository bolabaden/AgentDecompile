"""Naming precedence from kotorxid `kx/name_precedence.py`.

human > stabs > symbol > ghidra/derived > placeholder.
A placeholder may fill an empty slot. It never displaces a real name.
"""

from __future__ import annotations

import re
from typing import Any

NAME_TIERS = ("human", "stabs", "symbol", "ghidra", "placeholder")
HUMAN = "human"
STABS = "stabs"
SYMBOL = "symbol"
GHIDRA = "ghidra"
PLACEHOLDER = "placeholder"

PLACEHOLDER_RE = re.compile(
    r"""^(?:
          FUN_[0-9a-fA-F]+
        | SUB_[0-9a-fA-F]+ | sub_[0-9a-fA-F]+
        | LAB_[0-9a-fA-F]+ | loc_[0-9a-fA-F]+
        | Unwind[_@][0-9a-fA-F]+
        | switchD_[0-9a-fA-F]+
        | caseD_[0-9a-fA-F]+
        | DAT_[0-9a-fA-F]+
        | thunk_FUN_[0-9a-fA-F]+
        | FID_conflict:.+
        | unnamed_.+
        | placeholder_.+
        | entry | _entry
      )$""",
    re.X | re.IGNORECASE,
)

_TIER_NUM = {"human": 1, "stabs": 2, "symbol": 3, "ghidra": 4, "derived": 4, "placeholder": 5}


def tier_rank(tier: str) -> int:
    if tier not in _TIER_NUM:
        raise ValueError(f"unknown name tier {tier!r}; valid: {NAME_TIERS}")
    return NAME_TIERS.index("ghidra" if tier == "derived" else tier)


def is_placeholder_name(name: str | None) -> bool:
    text = (name or "").strip()
    if not text:
        return True
    return bool(PLACEHOLDER_RE.match(text))


def infer_tier(name: str | None, declared: str | None = None) -> str:
    if declared == "derived":
        return "ghidra"
    if declared in NAME_TIERS:
        return declared
    if is_placeholder_name(name):
        return "placeholder"
    return "ghidra"


def tier_of(row: dict[str, Any]) -> str:
    name = (row.get("name") or "").strip()
    origin = (row.get("name_origin") or row.get("nameOrigin") or "").strip().lower()
    if not is_placeholder_name(name) and origin in ("plate", "namespace"):
        return "human"
    if (row.get("stabs_name") or row.get("stabsName") or "").strip():
        return "stabs"
    if is_placeholder_name(name):
        return "placeholder"
    if origin == "mangled":
        return "symbol"
    if row.get("name_tier") in NAME_TIERS or row.get("name_tier") == "derived":
        return infer_tier(name, row.get("name_tier"))
    return "ghidra"


def resolved_name(row: dict[str, Any]) -> str | None:
    if tier_of(row) == "stabs":
        return (row.get("stabs_name") or row.get("stabsName") or "").strip() or None
    return (row.get("name") or "").strip() or None


def rank(row: dict[str, Any]) -> tuple:
    t = _TIER_NUM[tier_of(row)]
    has_src = 1 if (row.get("source_file") or row.get("sourceFile") or "").strip() else 0
    has_sig = 1 if (row.get("signature") or "").strip() else 0
    name = resolved_name(row) or ""
    return (t, -has_src, -has_sig, -len(name), str(row.get("binary_id") or row.get("id") or ""))


def resolve_members(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the best name for one logical function from its members."""
    if not rows:
        return {}
    ordered = sorted(rows, key=rank)
    win = ordered[0]
    wt = tier_of(win)
    return {
        "name": resolved_name(win),
        "tier": wt,
        "from_id": win.get("id"),
        "source_file": win.get("source_file") or win.get("sourceFile"),
        "stabs_name": win.get("stabs_name") or win.get("stabsName"),
        "signature": win.get("signature"),
        "n_members": len(rows),
        "runners_up": [
            {"name": resolved_name(r), "tier": tier_of(r), "id": r.get("id")} for r in ordered[1:4]
        ],
        "rescued_placeholder": bool(
            _TIER_NUM[wt] < 5 and any(_TIER_NUM[tier_of(r)] == 5 for r in rows)
        ),
    }


resolve = resolve_members


def choose_name(
    current: str | None,
    current_tier: str | None,
    incoming: str | None,
    incoming_tier: str,
) -> tuple[str, str]:
    incoming_name = (incoming or "").strip()
    if not incoming_name:
        return ((current or "").strip() or incoming_name, infer_tier(current, current_tier))

    incoming_tier = infer_tier(incoming_name, incoming_tier)
    if current is None or not str(current).strip():
        return incoming_name, incoming_tier

    current_name = str(current).strip()
    current_tier = infer_tier(current_name, current_tier)
    if incoming_tier == "placeholder" and current_tier != "placeholder":
        return current_name, current_tier
    if tier_rank(incoming_tier) < tier_rank(current_tier):
        return incoming_name, incoming_tier
    return current_name, current_tier
