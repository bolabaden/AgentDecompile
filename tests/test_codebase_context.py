"""Tests for codebase_context.py's corpus-driven get_func_context."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.codebase_context import get_func_context
from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionCorpus,
    DecompFunctionDoc,
    VectorEntry,
)

pytestmark = pytest.mark.unit


def _corpus() -> DecompFunctionCorpus:
    return DecompFunctionCorpus.from_dump(
        CorpusDump(
            platform="arm",
            functions=[
                DecompFunctionDoc(
                    id="target",
                    name="target_func",
                    asm_code="bx lr",
                    asm_module_path="asm/a.s",
                    calls_functions=[],
                ),
                DecompFunctionDoc(
                    id="similar1",
                    name="similar_func",
                    c_code="int similar_func(void) { return 1; }",
                    c_module_path="src/a.c",
                    asm_code="mov r0, #1\nbx lr",
                    asm_module_path="asm/a.s",
                    calls_functions=[],
                ),
                DecompFunctionDoc(
                    id="undecompiled",
                    name="undecompiled_func",
                    asm_code="mov r0, #2\nbx lr",
                    asm_module_path="asm/a.s",
                    calls_functions=[],
                ),
                DecompFunctionDoc(
                    id="caller1",
                    name="caller_func",
                    c_code="void caller_func(void) { target_func(); }",
                    c_module_path="src/b.c",
                    asm_code="bl target\nbx lr",
                    asm_module_path="asm/b.s",
                    calls_functions=["target"],
                ),
            ],
            vectors=[
                VectorEntry(id="target", embedding=[1, 0, 0]),
                VectorEntry(id="similar1", embedding=[0.9, 0.1, 0]),
                VectorEntry(id="undecompiled", embedding=[0.8, 0.2, 0]),
                VectorEntry(id="caller1", embedding=[0, 1, 0]),
            ],
        )
    )


def test_raises_for_unknown_function_id():
    corpus = _corpus()
    with pytest.raises(ValueError, match="Function not found"):
        get_func_context(corpus, "nonexistent")


def test_includes_similar_functions_that_have_c_code():
    corpus = _corpus()
    context = get_func_context(corpus, "target")

    names = [s.name for s in context.sampling]
    assert "similar_func" in names


def test_excludes_similar_functions_without_c_code():
    corpus = _corpus()
    context = get_func_context(corpus, "target")

    names = [s.name for s in context.sampling]
    assert "undecompiled_func" not in names


def test_includes_callers_of_the_target():
    corpus = _corpus()
    context = get_func_context(corpus, "target")

    caller_sample = next(s for s in context.sampling if s.name == "caller_func")
    assert caller_sample.calls_target is True


def test_does_not_duplicate_a_caller_already_present_from_similarity_search():
    corpus = DecompFunctionCorpus.from_dump(
        CorpusDump(
            platform="arm",
            functions=[
                DecompFunctionDoc(id="target", name="target_func", asm_code="bx lr", asm_module_path="a.s", calls_functions=[]),
                DecompFunctionDoc(
                    id="both",
                    name="both_func",
                    c_code="void both_func(void) {}",
                    c_module_path="b.c",
                    asm_code="bl target\nbx lr",
                    asm_module_path="b.s",
                    calls_functions=["target"],
                ),
            ],
            vectors=[
                VectorEntry(id="target", embedding=[1, 0]),
                VectorEntry(id="both", embedding=[0.9, 0.1]),
            ],
        )
    )

    context = get_func_context(corpus, "target")
    names = [s.name for s in context.sampling]
    assert names.count("both_func") == 1


def test_passes_through_asm_declaration_and_type_definitions():
    corpus = _corpus()
    context = get_func_context(
        corpus,
        "target",
        asm_declaration="void target_func(void)",
        called_functions_declarations={"sub1": "void sub1(void)"},
        type_definitions=["struct Foo { int x; };"],
    )

    assert context.asm_declaration == "void target_func(void)"
    assert context.called_functions_declarations == {"sub1": "void sub1(void)"}
    assert context.type_definitions == ["struct Foo { int x; };"]
