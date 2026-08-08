"""Unit tests for cross-build symbol identity mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.symbol_map import (
    ARITY_CONTRADICTED,
    ARITY_MATCH,
    ARITY_MATCH_DTOR,
    ARITY_UNDECIDABLE,
    DONOR_STATUSES,
    UNKNOWN_PURGE,
    check_signature_arity,
    msvc_stack_arg_bytes,
    Evidence,
    SymbolRecord,
    build_signature_index,
    callgraph_agreement,
    corroborated_engine_classes,
    is_autogen_name,
    is_eh_funclet,
    parse_demangled,
    qualified_name,
    record_to_csv_row,
    root_class,
    score_confidence,
    summarise,
    write_jsonl,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------
# name shapes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "FUN_00401000",
        "sub_12abe0",
        "thunk_FUN_00401000",
        "Unwind@00713e90",
        "FrameHandler_00734410",
        "Catch@0071b2c0",
        "DAT_0049d000",
        "switchD_00401234::caseD_0",
        "staticInitCExoArrayList_004013a0",
        "",
    ],
)
def test_autogen_names_carry_no_knowledge(name: str) -> None:
    assert is_autogen_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "AIUpdate",
        "CSWSCreature::AIUpdate",
        "ComputeUpdateRequired",
        "operator!=",
        "_internal_itoa",
        # 5 hex digits is short of the address-suffix rule, and a real name may
        # legitimately end that way.
        "crc_abcde",
    ],
)
def test_authored_names_survive(name: str) -> None:
    assert not is_autogen_name(name)


def test_eh_funclets_are_a_distinct_class_of_autogen() -> None:
    assert is_eh_funclet("Unwind@00713e90")
    assert is_eh_funclet("FrameHandler_00734410")
    assert is_autogen_name("FUN_00401000")
    # A plain FUN_ is unnamed code; an unwind funclet is compiler plumbing that
    # no donor built by another compiler can ever name.
    assert not is_eh_funclet("FUN_00401000")


def test_qualified_and_root_class() -> None:
    assert qualified_name(["CSWSCreature"], "AIUpdate") == "CSWSCreature::AIUpdate"
    assert qualified_name([], "main") == "main"
    assert qualified_name(["CExoArrayList<int>", "Nested"], "Add") == (
        "CExoArrayList<int>::Nested::Add"
    )
    assert root_class(["CSWSCreature"]) == "CSWSCreature"
    assert root_class([]) is None


# --------------------------------------------------------------------------
# engine class corroboration
# --------------------------------------------------------------------------


def test_engine_classes_must_appear_in_an_independent_build() -> None:
    target = {"CSWSCreature", "CExoString", "AnalystInvented", "std"}
    donor = {"CSWSCreature", "CExoString", "CSWSArea"}
    signature_build = {"CExoString", "CSWGuiPanel"}
    got = corroborated_engine_classes(target, donor, signature_build)
    assert got == {"CSWSCreature", "CExoString"}
    assert "AnalystInvented" not in got, "a class only the target knows is not evidence"
    assert "std" not in got


# --------------------------------------------------------------------------
# demangled signature parsing
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("demangled", "expected"),
    [
        (
            "CSWSCreature::ResolveRangedAnimations(CSWSObject*, int, int)",
            ("CSWSCreature::ResolveRangedAnimations", "(CSWSObject*, int, int)"),
        ),
        ("CResWave::OnResourceFreed()", ("CResWave::OnResourceFreed", "()")),
        (
            "CClientExoApp::SendLoadGameRequest(unsigned long, CExoString const&)",
            (
                "CClientExoApp::SendLoadGameRequest",
                "(unsigned long, CExoString const&)",
            ),
        ),
        (
            "CSWGuiObject::GetExtent() const",
            ("CSWGuiObject::GetExtent", "() const"),
        ),
        (
            "CExoArrayList<CSWSItem*>::Insert(CSWSItem*, int)",
            ("CExoArrayList<CSWSItem*>::Insert", "(CSWSItem*, int)"),
        ),
    ],
)
def test_parse_demangled(demangled: str, expected: tuple[str, str]) -> None:
    assert parse_demangled(demangled) == expected


def test_parse_demangled_rejects_data_symbols() -> None:
    assert parse_demangled("vtable for CSWSCreature") is None
    assert parse_demangled("typeinfo name for CExoString") is None
    assert parse_demangled("") is None


def test_function_pointer_parameter_keeps_the_outer_parameter_list() -> None:
    # The naive "first (" split would truncate this to "(void (*)".
    got = parse_demangled("CExoApp::SetCallback(void (*)(int), int)")
    assert got == ("CExoApp::SetCallback", "(void (*)(int), int)")


def test_signature_index_records_overloads() -> None:
    idx = build_signature_index(
        [
            "CSWGuiObject::SetExtent(CSWGuiExtent const&)",
            "CSWGuiObject::SetExtent(int, int, int, int)",
            "CResWave::OnResourceFreed()",
            "vtable for CSWSCreature",
        ]
    )
    assert idx["CSWGuiObject::SetExtent"] == [
        "(CSWGuiExtent const&)",
        "(int, int, int, int)",
    ]
    assert idx["CResWave::OnResourceFreed"] == ["()"]
    assert "vtable for CSWSCreature" not in idx


# --------------------------------------------------------------------------
# call-graph agreement
# --------------------------------------------------------------------------


def test_callgraph_agreement_scores_only_mapped_callees() -> None:
    pairing = {0x10: 0xA0, 0x20: 0xB0, 0x30: 0xC0}
    score, checked = callgraph_agreement([0x10, 0x20, 0x99], [0xA0, 0xB0], pairing)
    assert checked == 2, "0x99 has no counterpart, so it cannot vote"
    assert score == 1.0


def test_callgraph_agreement_is_silent_without_mapped_callees() -> None:
    score, checked = callgraph_agreement([0x99], [0xA0], {0x10: 0xA0})
    assert score is None
    assert checked == 0


def test_callgraph_agreement_detects_contradiction() -> None:
    pairing = {0x10: 0xA0, 0x20: 0xB0}
    score, checked = callgraph_agreement([0x10, 0x20], [0xF0], pairing)
    assert (score, checked) == (0.0, 2)


# --------------------------------------------------------------------------
# confidence tiering
# --------------------------------------------------------------------------


def test_no_donor_counterpart_is_low_confidence() -> None:
    tier, conf = score_confidence(Evidence(name_identity_pair=False, donor_status="absent"))
    assert tier == "low"
    assert conf < 0.6


def test_ambiguous_donor_outranks_absent_donor() -> None:
    """The donor knowing the name but not which function beats never hearing of it."""
    absent = score_confidence(Evidence(name_identity_pair=False, donor_status="absent"))
    ambiguous = score_confidence(Evidence(name_identity_pair=False, donor_status="ambiguous"))
    assert absent[0] == ambiguous[0] == "low"
    assert ambiguous[1] > absent[1]


def test_donor_status_vocabulary_is_declared() -> None:
    assert set(DONOR_STATUSES) == {"paired", "ambiguous", "absent", "unknown"}


def test_donor_agreement_alone_is_medium() -> None:
    tier, _ = score_confidence(Evidence(name_identity_pair=True, donor_ea=0x1000))
    assert tier == "medium"


def test_one_independent_channel_lifts_to_high() -> None:
    tier, conf = score_confidence(
        Evidence(
            name_identity_pair=True,
            callgraph_agreement=1.0,
            callgraph_callees_checked=5,
        )
    )
    assert tier == "high"
    assert conf >= 0.95


def test_two_independent_channels_score_higher_than_one() -> None:
    one = score_confidence(
        Evidence(name_identity_pair=True, callgraph_agreement=1.0, callgraph_callees_checked=5)
    )
    two = score_confidence(
        Evidence(
            name_identity_pair=True,
            callgraph_agreement=1.0,
            callgraph_callees_checked=5,
            strings_comparable=True,
            shared_strings=3,
        )
    )
    assert two[1] > one[1]


def test_contradicting_callgraph_demotes_even_with_a_donor_match() -> None:
    tier, _ = score_confidence(
        Evidence(
            name_identity_pair=True,
            callgraph_agreement=0.0,
            callgraph_callees_checked=6,
        )
    )
    assert tier == "low"


def test_disjoint_strings_demote() -> None:
    tier, _ = score_confidence(
        Evidence(name_identity_pair=True, strings_comparable=True, shared_strings=0)
    )
    assert tier == "low"


def test_low_significance_bsim_match_does_not_corroborate() -> None:
    """Below the measured operating point BSim precision is 36%, so it must not vote."""
    weak = score_confidence(
        Evidence(
            name_identity_pair=True,
            bsim_mutual_best=True,
            bsim_significance=12.0,
            bsim_agrees=True,
        )
    )
    strong = score_confidence(
        Evidence(
            name_identity_pair=True,
            bsim_mutual_best=True,
            bsim_significance=120.0,
            bsim_agrees=True,
        )
    )
    assert weak[0] == "medium"
    assert strong[0] == "high"


def test_bsim_only_votes_when_it_is_the_mutual_best() -> None:
    one_way = score_confidence(
        Evidence(
            name_identity_pair=True,
            bsim_mutual_best=False,
            bsim_significance=200.0,
            bsim_agrees=True,
        )
    )
    assert one_way[0] == "medium"


# --------------------------------------------------------------------------
# serialisation
# --------------------------------------------------------------------------


def _record(**kw) -> SymbolRecord:
    base = dict(
        ea=0x004013C0,
        name="CreateServer",
        cls="CAppManager",
        qualified="CAppManager::CreateServer",
        params="(CExoString const&, int)",
        signature="CAppManager::CreateServer(CExoString const&, int)",
        identity="engine",
        name_source="donor-annotation",
        symbol_source="USER_DEFINED",
        size=260,
        tier="high",
        confidence=0.99,
        evidence=Evidence(donor_ea=0x1C1E38, name_identity_pair=True),
    )
    base.update(kw)
    return SymbolRecord(**base)


def test_jsonl_round_trip_keeps_address_in_both_forms(tmp_path: Path) -> None:
    out = tmp_path / "map.jsonl"
    assert write_jsonl([_record()], out) == 1
    row = json.loads(out.read_text().strip())
    assert row["ea"] == "0x004013c0"
    assert row["ea_int"] == 0x004013C0
    assert row["evidence"]["donor_ea"] == 0x1C1E38
    assert "callgraph_agreement" not in row["evidence"], "unknown evidence is dropped"


def test_contradictions_survive_serialisation(tmp_path: Path) -> None:
    """A zero score is the finding, not an absent value: it must not be stripped."""
    out = tmp_path / "map.jsonl"
    write_jsonl(
        [
            _record(
                evidence=Evidence(
                    donor_ea=0x1000,
                    donor_status="paired",
                    name_identity_pair=True,
                    callgraph_agreement=0.0,
                    callgraph_callees_checked=6,
                    strings_comparable=True,
                    shared_strings=0,
                    bsim_agrees=False,
                )
            )
        ],
        out,
    )
    ev = json.loads(out.read_text().strip())["evidence"]
    assert ev["callgraph_agreement"] == 0.0
    assert ev["shared_strings"] == 0
    assert ev["bsim_agrees"] is False


def test_csv_row_matches_declared_columns() -> None:
    row = record_to_csv_row(_record())
    assert len(row) == 12
    assert row[0] == "0x004013c0"
    assert row[1] == "CAppManager::CreateServer"
    assert row[9] == "0x001c1e38"


def test_summarise_counts_what_it_says_it_counts() -> None:
    records = [
        _record(),
        _record(ea=0x402000, identity="eh-funclet", qualified=None, signature=None, tier="none"),
        _record(ea=0x403000, identity="other-class", signature=None, tier="medium"),
    ]
    got = summarise(records)
    assert got["functions"] == 3
    assert got["named"] == 2
    assert got["engine_class_named"] == 1
    assert got["with_parameter_signature"] == 1
    assert got["by_identity"]["eh-funclet"] == 1


# --------------------------------------------------------------------------
# borrowed-signature arity check
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ("()", 0),
        ("(void)", 0),
        ("(int)", 4),
        ("(CSWSObject*, int, int)", 12),
        ("(CExoString const&)", 4),
        ("(double)", 8),
        ("(unsigned long, CExoString const&, CExoString const&)", 12),
        ("() const", 0),
    ],
)
def test_msvc_stack_arg_bytes(params: str, expected: int) -> None:
    assert msvc_stack_arg_bytes(params) == expected


@pytest.mark.parametrize(
    "params",
    [
        "(CPazaakCard)",  # class by value: size not visible from the name
        "(int, ...)",  # varargs
        "(SomeEnum)",  # enum: not in the known-width table
        "not a parameter list",
    ],
)
def test_msvc_stack_arg_bytes_refuses_to_guess(params: str) -> None:
    assert msvc_stack_arg_bytes(params) is None


def test_arity_check_confirms_a_matching_thiscall() -> None:
    assert (
        check_signature_arity("(CSWSObject*, int, int)", "ResolveRangedAnimations", 12, "__thiscall")
        == ARITY_MATCH
    )


def test_arity_check_knows_the_msvc_deleting_destructor_flag() -> None:
    """MSVC gives ~X a hidden int flag, so `ret 4` on a nullary dtor is correct."""
    assert check_signature_arity("()", "~CExoResFile", 4, "__thiscall") == ARITY_MATCH_DTOR
    # The same purge on a non-destructor is a real disagreement.
    assert check_signature_arity("()", "GetCount", 4, "__thiscall") == ARITY_CONTRADICTED


def test_arity_check_flags_a_real_disagreement() -> None:
    assert (
        check_signature_arity("(CResRef const&, int, int, int)", "StartLoadFromLayout", 4, "__thiscall")
        == ARITY_CONTRADICTED
    )


def test_cdecl_and_unknown_purge_carry_no_arity_information() -> None:
    assert check_signature_arity("(int)", "f", 0, "__cdecl") == ARITY_UNDECIDABLE
    assert check_signature_arity("(int)", "f", UNKNOWN_PURGE, "__stdcall") == ARITY_UNDECIDABLE
