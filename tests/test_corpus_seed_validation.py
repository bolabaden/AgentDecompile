from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.seed_validation import (
    COMPILE_RESULTS,
    RESULTS,
    Seed,
    can_reuse_compile_result,
    candidate_reuse_key,
    group_candidates,
    logical_ids_for_links,
    mask_relocations,
    normalize_address,
    objdiff_only_coff_symbol_decoration,
    parse_seed,
    reuse_key,
    select_object_symbol,
    source_context,
    source_has_verified_coverage,
)

pytestmark = pytest.mark.unit


def test_static_audit_cannot_overwrite_destination_compile_ledger() -> None:
    assert RESULTS != COMPILE_RESULTS


def test_retry_keeps_prior_byte_exact_result_only_for_same_inputs() -> None:
    prior = {
        "seed": "seed.c", "source_path": "/source.c",
        "destination_bytes": "c3", "compile_status": "byte_exact",
    }
    assert can_reuse_compile_result(dict(prior), prior)
    changed = dict(prior, destination_bytes="90c3")
    assert not can_reuse_compile_result(changed, prior)


def test_candidate_rows_are_grouped_by_destination_not_copy_attempt() -> None:
    rows = [
        {"dst_slug": "a__bin", "dst_addr": "00401000", "src_name": "A"},
        {"dst_slug": "a__bin", "dst_addr": "401000", "src_name": "B"},
        {"dst_slug": "a__bin", "dst_addr": "00402000", "src_name": "C"},
    ]
    grouped = group_candidates(rows)
    assert len(grouped) == 2
    assert len(grouped[("a__bin", "401000")]) == 2


def test_parse_seed_keeps_source_and_destination_evidence_separate() -> None:
    text = """/* corpus seed: identical-bytes reuse
 * src=/work/recovered-source/prog/FUN_401000.c
 * dst=/arbitrary/game.bin @ 0x00402000
 * dst_name=RealName size=3
 * Not applied to an external recovery tree; local output only.
 */
/* original machine code: 33c0c3
 * VERIFIED BYTE-EXACT: recompiled and compared against the original binary
 */
int FUN_401000(void) { return 0; }
"""
    seed = parse_seed(text)
    assert seed.source_path == "/work/recovered-source/prog/FUN_401000.c"
    assert seed.destination_repo == "/arbitrary/game.bin"
    assert seed.destination_address == "402000"
    assert seed.destination_name == "RealName"
    assert seed.source_original_bytes == bytes.fromhex("33c0c3")
    assert seed.defined_name == "FUN_401000"
    assert seed.source_evidence is None


def test_reuse_key_normalizes_address_but_not_identity_evidence() -> None:
    key = reuse_key("/work/F.c", "/arbitrary/game.bin", "0000000000402000")
    assert key == ("/work/F.c", "/arbitrary/game.bin", "402000")
    assert normalize_address("0000") == "0"


def test_candidate_reuse_key_points_at_recovered_source_corpus() -> None:
    row = {
        "src_program": "k1",
        "src_name": "FunctionName",
        "dst_repo": "/arbitrary/game.bin",
        "dst_addr": "00402000",
    }
    key = candidate_reuse_key(row)
    assert key[0].rsplit("/", 1)[-1] == "FunctionName.c"
    assert key[0].endswith("/recovered-source/k1/FunctionName.c")
    assert key[1:] == ("/arbitrary/game.bin", "402000")


def test_select_object_symbol_handles_coff_decoration() -> None:
    symbols = {
        "_FUN_401000@4": b"\x90\xc3",
        "_unrelated": b"\xc3",
    }
    name, data = select_object_symbol(symbols, "FUN_401000")
    assert name == "_FUN_401000@4"
    assert data == b"\x90\xc3"


def test_source_verification_comes_from_coverage_ledger_not_header_text() -> None:
    verified = {("k1", "Covered")}
    assert source_has_verified_coverage(verified, "/work/recovered-source/k1/Covered.c")
    assert not source_has_verified_coverage(
        verified, "/work/recovered-source/k1/HeaderClaimOnly.c"
    )


def test_identity_link_requires_one_logical_identity() -> None:
    assert logical_ids_for_links([{"logical_id": 7}, {"logical_id": 7}]) == [7]
    assert logical_ids_for_links([{"logical_id": 9}, {"logical_id": 7}]) == [7, 9]


def test_source_context_follows_the_recovery_evidence_path(tmp_path: Path) -> None:
    shard = tmp_path / "projects" / "prog" / "b001" / "shard0"
    shard.mkdir(parents=True)
    (shard / "ctx.h").write_text("extern int source_global;\n")
    seed = Seed(
        source_path="/source/F.c", destination_repo="/arbitrary/game",
        destination_address="1000", destination_name="F", size=1,
        source_original_bytes=b"\xc3", defined_name="F", payload="void F(void) {}",
        source_evidence="projects/prog/b001/shard0/run-results.json",
    )
    context = source_context(seed, tmp_path)
    assert context == "extern int source_global;\n"


def test_relocation_mask_blanks_only_linker_owned_bytes() -> None:
    original = bytes.fromhex("b8c0d57300c3")
    masked = mask_relocations(original, [{"immOffset": 1, "immSize": 4}])
    assert masked == bytes.fromhex("b800000000c3")


def test_objdiff_accepts_only_the_expected_coff_global_underscore() -> None:
    output = (
        '  row 0: base="mov eax, [_maxTexID]" [arg-mismatch]  '
        'target="mov eax, [maxTexID]" [arg-mismatch]\n'
    )
    assert objdiff_only_coff_symbol_decoration(output)
    assert not objdiff_only_coff_symbol_decoration(
        '  row 0: base="mov eax, [wrong]" [arg-mismatch]  '
        'target="mov eax, [maxTexID]" [arg-mismatch]\n'
    )
