"""Structured normalize pipeline: HighFacts + Clang, fallback only compile-only."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_recovery.corpus.clang_scribe import run_clang_passes
from agentdecompile_recovery.corpus.ghidra_bulk import compile_only_fallback, sanitize_body
from agentdecompile_recovery.corpus.high_emit import (
    HighFacts,
    TokenFact,
    TokenKind,
    collect_high_facts,
    emit_from_facts,
    facts_from_tokens,
)
from agentdecompile_recovery.corpus.normalize_pipeline import (
    NormalizeMode,
    normalize_decompiled,
    summarize_benchmark,
)

pytestmark = pytest.mark.unit

MEASURED = (
    "void __thiscall CExoArrayList<CExoString>::~CExoArrayList("
    "CExoArrayList<CExoString> *this) { this->field110_0x1c8 = 0; }\n"
)


def test_compile_only_flattens_measured_spellings() -> None:
    out = normalize_decompiled(MEASURED, mode=NormalizeMode.COMPILE_ONLY).text
    assert "__thiscall" not in out
    assert "__fastcall" in out
    assert "edx_unused" in out
    assert "CExoArrayList_CExoString" in out
    assert "field_1c8" in out
    assert "::" not in out
    assert "GhidraBlob" not in out
    assert "ghidra_call" not in out


def test_semantic_refuses_invented_abi_and_layout() -> None:
    src = (
        "void __thiscall Gob::Tick(Gob *this) {\n"
        "  (*this->vtable->OnBlackButtonPressed)();\n"
        "  (ptr).internal = 0;\n"
        "}\n"
    )
    result = normalize_decompiled(src, mode=NormalizeMode.SEMANTIC)
    assert result.used_fallback is False
    assert "ghidra_call(" not in result.text
    assert "GhidraBlob" not in result.text
    assert "__thiscall" in result.text
    assert "edx_unused" not in result.text
    assert "OnBlackButtonPressed" in result.text


def test_compile_only_fallback_may_use_placeholders() -> None:
    src = "(*this->vtable->OnBlackButtonPressed)(); a.internal.ints = 1;"
    result = normalize_decompiled(
        src, mode=NormalizeMode.COMPILE_ONLY, fallback=compile_only_fallback
    )
    assert result.used_fallback is True
    assert "ghidra_call()" in result.text
    assert "GhidraBlob" in result.text
    assert "OnBlackButtonPressed" not in result.text


def test_ghidra_bulk_sanitize_default_is_compile_only() -> None:
    src = "(*this->vtable->Method)();"
    assert "ghidra_call()" in sanitize_body(src)
    assert "ghidra_call" not in sanitize_body(src, mode=NormalizeMode.SEMANTIC)


def test_high_facts_emit_uses_datatype_field_names() -> None:
    facts = HighFacts(
        calling_convention="__thiscall",
        fields={"1c8": "saved_length"},
        tokens=[
            TokenFact(TokenKind.TYPE, "void"),
            TokenFact(TokenKind.SPACE, " "),
            TokenFact(TokenKind.IDENT, "__thiscall"),
            TokenFact(TokenKind.SPACE, " "),
            TokenFact(TokenKind.IDENT, "Gob::set", symbol="Gob::set"),
            TokenFact(TokenKind.SYNTAX, "("),
            TokenFact(TokenKind.TYPE, "Gob"),
            TokenFact(TokenKind.SPACE, " "),
            TokenFact(TokenKind.SYNTAX, "*"),
            TokenFact(TokenKind.IDENT, "this"),
            TokenFact(TokenKind.SYNTAX, ")"),
            TokenFact(TokenKind.SPACE, " "),
            TokenFact(TokenKind.SYNTAX, "{"),
            TokenFact(TokenKind.IDENT, "this"),
            TokenFact(TokenKind.SYNTAX, "-"),
            TokenFact(TokenKind.SYNTAX, ">"),
            TokenFact(TokenKind.FIELD, "field110_0x1c8", symbol="field110_0x1c8"),
            TokenFact(TokenKind.SYNTAX, ";"),
            TokenFact(TokenKind.SYNTAX, "}"),
        ],
        source="ghidra",
    )
    semantic = emit_from_facts(facts, mode=NormalizeMode.SEMANTIC)
    assert "saved_length" in semantic
    assert "field110_0x1c8" not in semantic
    assert "__thiscall" in semantic
    compile_only = emit_from_facts(facts, mode=NormalizeMode.COMPILE_ONLY)
    assert "__fastcall" in compile_only
    assert "edx_unused" in compile_only
    assert "Gob__set" in compile_only or "Gob_set" in compile_only


def test_semantic_expands_concat_pseudo_op() -> None:
    src = "unsigned short x = CONCAT11(hi, lo);"
    out = emit_from_facts(facts_from_tokens(src), mode=NormalizeMode.SEMANTIC)
    assert "CONCAT11" not in out
    assert "unsigned char" in out
    assert "hi" in out and "lo" in out
    compile_only = emit_from_facts(facts_from_tokens(src), mode=NormalizeMode.COMPILE_ONLY)
    assert "CONCAT11" in compile_only


def test_clang_passes_record_skip_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.clang_scribe.clang_binary",
        lambda: None,
    )
    text, meta = run_clang_passes("int f(void) { _Bool x = 1; return x; }", mode="semantic")
    assert meta["used"] is False
    assert "clang not on PATH" in meta["reason"]
    assert "unsigned char" in text
    assert "_Bool" not in text


def test_collect_high_facts_reads_markup_and_pcode() -> None:
    tok = MagicMock()
    tok.getText.return_value = "foo"
    tok.getHighSymbol.return_value = None
    group = MagicMock()
    it = MagicMock()
    it.hasNext.side_effect = [True, False]
    it.next.return_value = tok
    group.tokenIterator.return_value = it

    op = MagicMock()
    op.getMnemonic.return_value = "CALLIND"
    op.getNumInputs.return_value = 1
    vn = MagicMock()
    vn.getSize.return_value = 4
    op.getInput.return_value = vn
    op.getOutput.return_value = None
    pops = MagicMock()
    pops.hasNext.side_effect = [True, False]
    pops.next.return_value = op

    hf = MagicMock()
    hf.getPcodeOps.return_value = pops
    result = MagicMock()
    result.decompileCompleted.return_value = True
    result.getHighFunction.return_value = hf
    result.getCCodeMarkup.return_value = group

    decompiler = MagicMock()
    decompiler.decompileFunction.return_value = result
    function = MagicMock()
    function.getName.return_value = "Gob::Tick"
    function.getCallingConvention.return_value = None
    function.getCallingConventionName.return_value = "__thiscall"
    sig = MagicMock()
    sig.getReturnType.return_value.getName.return_value = "void"
    function.getSignature.return_value = sig

    st = MagicMock()
    comp = MagicMock()
    comp.getFieldName.return_value = "length"
    comp.getOffset.return_value = 4
    st.getComponents.return_value = [comp]
    structs = MagicMock()
    structs.hasNext.side_effect = [True, False]
    structs.next.return_value = st
    program = MagicMock()
    program.getDataTypeManager.return_value.getAllStructures.return_value = structs

    facts = collect_high_facts(program, function, decompiler)
    assert facts.source == "ghidra"
    assert facts.calling_convention == "__thiscall"
    assert facts.tokens[0].text == "foo"
    assert facts.pcode[0].op == "CALLIND"
    assert facts.fields["4"] == "length"


def test_benchmark_receipt_uses_run_counts_not_a_product_name() -> None:
    rows = [
        {"ok": True, "usedFallback": True, "refused": False},
        {"ok": False, "usedFallback": False, "refused": True},
    ]
    bench = summarize_benchmark(rows, mode=NormalizeMode.COMPILE_ONLY)
    assert bench["functions"] == 2
    assert bench["compiled"] == 1
    assert bench["fallbackUsed"] == 1
    assert bench["semanticRefused"] == 1
    assert "byte" in bench["claimBoundary"].lower() or "match" in bench["claimBoundary"].lower()
    assert "24240" not in str(bench)
