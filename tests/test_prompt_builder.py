"""Tests for prompt_builder.py's create_decompile_prompt."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionCorpus,
    DecompFunctionDoc,
    VectorEntry,
)
from agentdecompile_recovery.prompt_builder import create_decompile_prompt

pytestmark = pytest.mark.unit


def _corpus() -> DecompFunctionCorpus:
    return DecompFunctionCorpus.from_dump(
        CorpusDump(
            platform="win32",
            functions=[
                DecompFunctionDoc(id="target", name="FUN_00401000", asm_code="push ebp\nret", asm_module_path="a.c"),
                DecompFunctionDoc(
                    id="similar",
                    name="similar_func",
                    c_code="int similar_func(void) { return 1; }",
                    c_module_path="a.c",
                    asm_code="push ebp\nret",
                    asm_module_path="a.s",
                ),
            ],
            vectors=[
                VectorEntry(id="target", embedding=[1.0, 0.0]),
                VectorEntry(id="similar", embedding=[0.9, 0.1]),
            ],
        )
    )


def test_raises_for_unknown_function_id():
    with pytest.raises(ValueError, match="Function not found"):
        create_decompile_prompt(corpus=_corpus(), function_id="nonexistent", platform="win32")


def test_builds_a_prompt_containing_target_and_examples():
    prompt = create_decompile_prompt(corpus=_corpus(), function_id="target", platform="win32")

    assert "FUN_00401000" in prompt
    assert "Windows (32-bit)" in prompt
    assert "similar_func" in prompt
