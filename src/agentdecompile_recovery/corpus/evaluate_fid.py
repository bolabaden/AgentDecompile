"""Evaluate pairs whose targets carry no engine names using Function-ID ground truth."""

from __future__ import annotations

from .evaluate import evaluate, evaluate_pairs


def evaluate_fid(con, pairs: list[tuple[str, str]]) -> list[dict]:
    return evaluate_pairs(con, pairs, mode="fid")


def evaluate_one_fid(con, src_path: str, dst_path: str) -> dict:
    return evaluate(con, src_path, dst_path, mode="fid")
