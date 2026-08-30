"""Identity matching and post-compile source cross-match.

Identity uses kotorxid's multi-signal matcher when feature fields are present,
and a name/size fallback otherwise. Copying C waits until compile + real C.
"""

from __future__ import annotations

from typing import Any

from .canon import is_eh_clone
from .match_engine import match_binaries
from .source_claims import is_recovered_source


def _norm_name(value: str | None) -> str:
    return (value or "").strip()


def _usable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if not is_eh_clone(row.get("name"), row.get("plate"))]


def _has_features(rows: list[dict[str, Any]]) -> bool:
    return any(
        row.get("strings") or row.get("consts") or row.get("ext_calls") or row.get("n_blocks")
        for row in rows
    )


def bind_identities(
    functions_by_binary: dict[str, list[dict[str, Any]]],
    *,
    thresholds: dict[tuple[str, str], float] | None = None,
    default_threshold: float = 0.55,
    metas: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    ids = list(functions_by_binary)
    metas = metas or {}
    for i, left_id in enumerate(ids):
        for right_id in ids[i + 1 :]:
            left_rows = _usable(functions_by_binary[left_id])
            right_rows = _usable(functions_by_binary[right_id])
            if _has_features(left_rows) or _has_features(right_rows):
                matches = match_binaries(
                    left_rows,
                    right_rows,
                    left_meta=metas.get(left_id),
                    right_meta=metas.get(right_id),
                    tier="auto",
                )
                for match in matches:
                    bindings.append(
                        {
                            "left": {"binary": left_id, "id": match["left_id"]},
                            "right": {"binary": right_id, "id": match["right_id"]},
                            "logical_id": match["left_id"],
                            "confidence": match["score"],
                            "signals": match["signals"],
                            "provenance": [
                                f"{match['pair_class']} {match['status']}",
                                f"margin {match['margin']}",
                                f"content {match['content']}",
                            ],
                            "threshold": match["score"],
                            "kind": "identity",
                        }
                    )
                continue
            need = default_threshold
            if thresholds:
                need = thresholds.get((left_id, right_id), thresholds.get((right_id, left_id), default_threshold))
            for left in left_rows:
                for right in right_rows:
                    ln, rn = _norm_name(left.get("name")), _norm_name(right.get("name"))
                    if not ln or ln != rn:
                        continue
                    try:
                        ls, rs = float(left.get("size") or 0), float(right.get("size") or 0)
                    except (TypeError, ValueError):
                        ls = rs = 0.0
                    ratio = min(ls, rs) / max(ls, rs) if ls and rs else 0.5
                    confidence = 0.45 + 0.25 * ratio
                    if confidence < need:
                        continue
                    bindings.append(
                        {
                            "left": {"binary": left_id, "id": left.get("id"), "name": left.get("name")},
                            "right": {"binary": right_id, "id": right.get("id"), "name": right.get("name")},
                            "logical_id": left.get("logical_id") or left.get("id"),
                            "confidence": round(confidence, 4),
                            "signals": {"exact_name": 1.0, "size_ratio": ratio},
                            "provenance": ["same function name"],
                            "threshold": need,
                            "kind": "identity",
                        }
                    )
    return bindings


def propagate_compiling_source(
    functions_by_binary: dict[str, list[dict[str, Any]]],
    bindings: list[dict[str, Any]],
    compiled_ids: set[str],
) -> list[dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for binary_id, rows in functions_by_binary.items():
        for row in rows:
            index[(binary_id, str(row.get("id")))] = row

    placements: list[dict[str, Any]] = []
    for bind in bindings:
        left = index.get((bind["left"]["binary"], str(bind["left"]["id"])))
        right = index.get((bind["right"]["binary"], str(bind["right"]["id"])))
        if left is None or right is None:
            continue
        for source, dest in ((left, right), (right, left)):
            src_id = str(source.get("id"))
            body = source.get("source") or source.get("body") or ""
            if src_id not in compiled_ids or not is_recovered_source(body):
                continue
            dest["source"] = body
            dest["source_from"] = src_id
            dest["source_binary"] = next(
                bid
                for bid, rows in functions_by_binary.items()
                if any(str(item.get("id")) == src_id for item in rows)
            )
            placements.append(
                {
                    "from": src_id,
                    "to": dest.get("id"),
                    "logical_id": bind.get("logical_id"),
                    "confidence": bind.get("confidence"),
                    "provenance": list(bind.get("provenance") or []) + ["post-compile source copy"],
                }
            )
    return placements
