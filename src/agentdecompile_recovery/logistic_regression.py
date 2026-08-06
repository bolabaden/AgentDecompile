"""Logistic regression for estimating decompilation difficulty.

Trains a binary classifier on a dataset of decompiled/undecompiled functions
using assembly metrics (instruction count, branch count, label count) as
features. Functions that already have C code are labeled 0 (easier), functions
without are labeled 1 (harder). The model learns per-dataset coefficients via
gradient descent on binary cross-entropy loss after z-score normalization.

Applying the model to a function's metrics produces a 0-1 score (sigmoid of
the linear combination), where higher means harder. When the dataset lacks
both classes, falls back to hardcoded coefficients from Chris Lewis's
Snowboard Kids 2 analysis (the same fallback the upstream tool ships with).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, Protocol

from .asm_metrics import AsmMetrics, count_asm_metrics

DifficultyTier = Literal["easy", "medium", "hard"]


@dataclass
class DifficultyModel:
    means: tuple[float, float, float]
    stds: tuple[float, float, float]
    coefficients: tuple[float, float, float]
    intercept: float


class _FunctionDoc(Protocol):
    asm_code: str
    c_code: str | None


_LEWIS_FALLBACK_MODEL = DifficultyModel(
    means=(34.27065527065527, 1.6666666666666667, 1.98005698005698),
    stds=(24.763225638334454, 2.047860394102145, 2.3803926026229827),
    coefficients=(2.499706543629367, -0.46648920346754463, 0.4911494991317799),
    intercept=-0.5155412977000488,
)


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1 / (1 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1 + exp_x)


def apply_difficulty_model(metrics: AsmMetrics, model: DifficultyModel) -> float:
    features = (metrics.instruction_count, metrics.branch_count, metrics.label_count)
    logit = model.intercept
    for i in range(3):
        std = model.stds[i]
        scaled = (features[i] - model.means[i]) / std if std > 0 else 0.0
        logit += scaled * model.coefficients[i]
    return _sigmoid(logit)


def train_difficulty_model(functions: list[_FunctionDoc], platform: str) -> DifficultyModel:
    has_decompiled = False
    has_undecompiled = False
    for fn in functions:
        if fn.c_code:
            has_decompiled = True
        else:
            has_undecompiled = True
        if has_decompiled and has_undecompiled:
            break
    if not has_decompiled or not has_undecompiled:
        return _LEWIS_FALLBACK_MODEL

    n = len(functions)
    all_metrics = [count_asm_metrics(fn.asm_code, platform) for fn in functions]
    labels = [0.0 if fn.c_code else 1.0 for fn in functions]

    means = [0.0, 0.0, 0.0]
    for m in all_metrics:
        means[0] += m.instruction_count
        means[1] += m.branch_count
        means[2] += m.label_count
    means = [value / n for value in means]

    stds = [0.0, 0.0, 0.0]
    for m in all_metrics:
        feats = (m.instruction_count, m.branch_count, m.label_count)
        for j in range(3):
            diff = feats[j] - means[j]
            stds[j] += diff * diff
    stds = [math.sqrt(value / n) for value in stds]

    x = [[0.0, 0.0, 0.0] for _ in range(n)]
    for i, m in enumerate(all_metrics):
        feats = (m.instruction_count, m.branch_count, m.label_count)
        for j in range(3):
            x[i][j] = (feats[j] - means[j]) / stds[j] if stds[j] > 0 else 0.0

    w = [0.0, 0.0, 0.0]
    b = 0.0
    lr = 0.1
    iterations = 1000

    for _ in range(iterations):
        grad_w = [0.0, 0.0, 0.0]
        grad_b = 0.0

        for i in range(n):
            logit = b
            for j in range(3):
                logit += x[i][j] * w[j]
            pred = _sigmoid(logit)
            error = pred - labels[i]

            for j in range(3):
                grad_w[j] += error * x[i][j]
            grad_b += error

        for j in range(3):
            w[j] -= (lr * grad_w[j]) / n
        b -= (lr * grad_b) / n

    return DifficultyModel(
        means=tuple(means),  # type: ignore[arg-type]
        stds=tuple(stds),  # type: ignore[arg-type]
        coefficients=tuple(w),  # type: ignore[arg-type]
        intercept=b,
    )
