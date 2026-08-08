"""Tests for logistic_regression.py, ported from the upstream reference spec."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agentdecompile_recovery.asm_metrics import AsmMetrics
from agentdecompile_recovery.logistic_regression import (
    DifficultyModel,
    apply_difficulty_model,
    train_difficulty_model,
)

pytestmark = pytest.mark.unit


@dataclass
class _FunctionDoc:
    asm_code: str
    c_code: str | None = None


_LEWIS_MODEL = DifficultyModel(
    means=(34.27065527065527, 1.6666666666666667, 1.98005698005698),
    stds=(24.763225638334454, 2.047860394102145, 2.3803926026229827),
    coefficients=(2.499706543629367, -0.46648920346754463, 0.4911494991317799),
    intercept=-0.5155412977000488,
)


class TestApplyDifficultyModel:
    def test_produces_valid_score_for_zero_metrics(self):
        score = apply_difficulty_model(AsmMetrics(0, 0, 0), _LEWIS_MODEL)
        assert 0 <= score <= 1

    def test_produces_score_near_one_for_large_metrics(self):
        score = apply_difficulty_model(AsmMetrics(500, 50, 40), _LEWIS_MODEL)
        assert score > 0.9

    def test_produces_low_score_for_small_easy_looking_metrics(self):
        score = apply_difficulty_model(AsmMetrics(5, 0, 0), _LEWIS_MODEL)
        assert score < 0.3


class TestTrainDifficultyModel:
    def test_learns_coefficients_with_correct_sign_from_synthetic_data(self):
        functions = [
            _FunctionDoc("mov r0, #1\nbx lr", "int e1() { return 1; }"),
            _FunctionDoc("mov r0, #2\nbx lr", "int e2() { return 2; }"),
            _FunctionDoc("push {lr}\nmov r0, #3\npop {r0}\nbx r0", "int e3() { return 3; }"),
            _FunctionDoc(
                "push {r4, lr}\nmov r0, #1\ncmp r0, #0\nbeq .L0\nmov r1, #2\nbl sub1\n.L0:\n"
                "mov r2, #3\ncmp r2, #4\nbne .L1\nmov r3, #5\nbl sub2\n.L1:\npop {r4}\npop {r0}\nbx r0"
            ),
            _FunctionDoc(
                "push {r4, r5, lr}\nmov r0, #1\ncmp r0, #0\nbeq .L0\nmov r1, #2\nbl sub1\n.L0:\n"
                "mov r2, #3\ncmp r2, #4\nbne .L1\nmov r3, #5\nbl sub2\nmov r4, #6\nbl sub3\n.L1:\n"
                "pop {r4, r5}\npop {r0}\nbx r0"
            ),
            _FunctionDoc(
                "push {r4, r5, r6, lr}\nmov r0, #10\ncmp r0, #0\nbgt .L0\nmov r1, #20\nbl sub1\n.L0:\n"
                "mov r2, #30\ncmp r2, #0\nblt .L1\nmov r3, #40\nbl sub2\nmov r4, #50\nbl sub3\nmov r5, #60\n"
                "bl sub4\n.L1:\npop {r4, r5, r6}\npop {r0}\nbx r0"
            ),
        ]

        model = train_difficulty_model(functions, "arm")

        assert model.coefficients[0] > 0
        assert round(model.means[0], 0) != 34

    def test_falls_back_to_lewis_model_when_no_decompiled_functions(self):
        functions = [_FunctionDoc("mov r0, #1\nbx lr"), _FunctionDoc("mov r0, #2\nbx lr")]

        model = train_difficulty_model(functions, "arm")
        assert model.intercept == pytest.approx(-0.5155412977000488)

    def test_falls_back_to_lewis_model_when_all_functions_are_decompiled(self):
        functions = [
            _FunctionDoc("mov r0, #1\nbx lr", "int e1() {}"),
            _FunctionDoc("mov r0, #2\nbx lr", "int e2() {}"),
        ]

        model = train_difficulty_model(functions, "arm")
        assert model.intercept == pytest.approx(-0.5155412977000488)

    def test_computes_means_and_stds_correctly_from_the_dataset(self):
        functions = [
            _FunctionDoc("mov r0, #1\nmov r1, #2", "int a() {}"),  # 2 instructions
            _FunctionDoc("mov r0, #1\nmov r1, #2\nmov r2, #3\nmov r3, #4"),  # 4 instructions
        ]

        model = train_difficulty_model(functions, "arm")
        assert model.means[0] == pytest.approx(3, abs=1e-5)
        assert model.stds[0] == pytest.approx(1, abs=1e-5)
