"""Unit tests for match cache, verify pool, and source dump helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.match_cache import MatchCache, cache_key, is_proven_zero, source_sha256
from agentdecompile_recovery.source_dump import (
    authority_label,
    dump_source_tree,
    looks_like_byte_emitter,
    module_for_entry,
    normalize_entry_hex,
)
from agentdecompile_recovery.source_export import (
    resolve_match_source_text,
    vacuum_row_from_verify,
)
from agentdecompile_recovery.source_parity_synthesize import record_with_source_text
from agentdecompile_recovery.verify_pool import map_parallel, resolve_workers

pytestmark = pytest.mark.unit


def test_match_cache_roundtrip(tmp_path: Path) -> None:
    cache = MatchCache()
    row = {
        "name": "FUN_00401000",
        "entry": "00401000",
        "status": "matched",
        "differences": 0,
        "sourceSha256": source_sha256("int fun(void) { return 0; }\n"),
        "targetSha256": "a" * 64,
        "compilerProfileName": "O2_GS-_Oy",
        "source": str(tmp_path / "c.c"),
    }
    (tmp_path / "c.c").write_text("int fun(void) { return 0; }\n", encoding="utf-8")
    assert cache.ingest(row)
    hit = cache.lookup(
        entry="00401000",
        source_sha=row["sourceSha256"],
        target_sha=row["targetSha256"],
        compiler_profile="O2_GS-_Oy",
    )
    assert hit is not None
    assert hit["name"] == "FUN_00401000"
    path = tmp_path / "match-cache.json"
    cache.write(path)
    other = MatchCache()
    assert other.load_cache_file(path) == 1
    assert other.has_entry("00401000")


def test_cache_key_stable() -> None:
    assert cache_key(entry="a", source_sha="b", target_sha="d", compiler_profile="e") == "d|a|b|e|c"
    assert (
        cache_key(entry="a", source_sha="b", target_sha="d", compiler_profile="e", compiler_lane="cxx")
        == "d|a|b|e|cxx"
    )


def test_resolve_match_source_text_prefers_embedded_and_checks_hash(tmp_path: Path) -> None:
    embedded = "int Embedded(void) { return 7; }\n"
    missing_path = tmp_path / "does-not-exist.c"
    row = {
        "name": "Embedded",
        "source": str(missing_path),
        "sourceText": embedded,
        "sourceSha256": source_sha256(embedded),
    }

    assert resolve_match_source_text(row) == embedded


def test_resolve_match_source_text_falls_back_to_path(tmp_path: Path) -> None:
    source = "int Legacy(void) { return 3; }\n"
    source_path = tmp_path / "legacy.c"
    source_path.write_text(source, encoding="utf-8")

    assert resolve_match_source_text(
        {
            "name": "Legacy",
            "source": str(source_path),
            "sourceSha256": source_sha256(source),
        }
    ) == source


def test_resolve_match_source_text_rejects_hash_mismatch() -> None:
    with pytest.raises(ValueError, match="source hash mismatch"):
        resolve_match_source_text(
            {
                "name": "Changed",
                "sourceText": "int Changed(void) { return 1; }\n",
                "sourceSha256": source_sha256("int Changed(void) { return 2; }\n"),
            }
        )


def test_resolve_match_source_text_requires_source() -> None:
    with pytest.raises(FileNotFoundError, match="candidate source missing"):
        resolve_match_source_text({"name": "Missing"})


def test_match_receipt_writers_embed_exact_source(tmp_path: Path) -> None:
    source = "int Proven(void) { return 9; }\n"
    source_path = tmp_path / "candidate.c"
    source_path.write_text(source, encoding="utf-8")

    synthesized = record_with_source_text(
        {
            "name": "Proven",
            "source": str(source_path),
            "sourceSha256": source_sha256(source),
        }
    )
    vacuum = vacuum_row_from_verify(
        "prompt_Proven",
        {"function_name": "Proven", "candidate_source": str(source_path)},
    )

    assert synthesized["sourceText"] == source
    assert vacuum is not None
    assert vacuum["sourceText"] == source
    assert vacuum["sourceSha256"] == source_sha256(source)


def test_match_cache_miss_on_source_change() -> None:
    """A changed candidate source at the same entry must NOT be treated as proven."""

    cache = MatchCache()
    sha_a = source_sha256("int fun(void) { return 0; }\n")
    sha_b = source_sha256("int fun(void) { return 1; }\n")
    row = {
        "name": "FUN_00401000",
        "entry": "00401000",
        "status": "matched",
        "differences": 0,
        "sourceSha256": sha_a,
        "targetSha256": "a" * 64,
        "compilerProfileName": "O2_GS-_Oy",
    }
    assert cache.ingest(row)
    # Same entry, different source bytes -> must miss (no false proven skip).
    assert cache.lookup(
        entry="00401000",
        source_sha=sha_b,
        target_sha="a" * 64,
        compiler_profile="O2_GS-_Oy",
    ) is None
    # A different compiler profile is not evidence for the requested profile.
    assert cache.lookup(
        entry="00401000",
        source_sha=sha_a,
        target_sha="a" * 64,
        compiler_profile="different",
    ) is None
    # A different target at the same entry/source must always be re-verified.
    assert cache.lookup(
        entry="00401000",
        source_sha=sha_a,
        target_sha="b" * 64,
        compiler_profile="O2_GS-_Oy",
    ) is None


def test_match_cache_rejects_unproven_rows() -> None:
    cache = MatchCache()
    # differences != 0 must not enter the cache as a skip authority.
    assert not cache.ingest(
        {"name": "f", "entry": "00401000", "status": "matched", "differences": 3, "sourceSha256": "x" * 64}
    )
    # Missing source sha cannot form a safe key.
    assert not cache.ingest({"name": "f", "entry": "00401000", "status": "matched", "differences": 0})
    # Missing target identity cannot safely authorize reuse across analysis images.
    assert not cache.ingest(
        {
            "name": "f",
            "entry": "00401000",
            "status": "matched",
            "differences": 0,
            "sourceSha256": "x" * 64,
        }
    )


def test_fallback_match_is_not_proven_zero() -> None:
    assert not is_proven_zero(
        {
            "status": "matched",
            "differences": 0,
            "fallback": "objdump-disassembly-byte-compare",
        }
    )


def test_map_parallel_preserves_order() -> None:
    assert resolve_workers(0) >= 2
    out = map_parallel([1, 2, 3, 4], lambda x: x * 10, workers=2)
    assert out == [10, 20, 30, 40]


def test_map_parallel_propagates_worker_exception() -> None:
    def boom(x: int) -> int:
        if x == 3:
            raise ValueError("kaboom")
        return x

    with pytest.raises(ValueError, match="kaboom"):
        map_parallel([1, 2, 3, 4], boom, workers=2)


def test_map_parallel_on_error_isolates_failures() -> None:
    def boom(x: int) -> dict:
        if x == 3:
            raise ValueError("kaboom")
        return {"ok": x}

    out = map_parallel([1, 2, 3, 4], boom, workers=2, on_error=lambda item, exc: {"error": str(exc), "item": item})
    oks = [r for r in out if "ok" in r]
    errs = [r for r in out if "error" in r]
    assert len(oks) == 3 and len(errs) == 1
    assert errs[0]["item"] == 3


def test_byte_emitter_rejected() -> None:
    emitter = "void fun(void) {\n" + "\n".join(f"    __asm _emit 0x{i:02x}" for i in range(200)) + "\n}\n"
    assert looks_like_byte_emitter(emitter, {"sourceQuality": "byte-emission-asm"})
    assert not looks_like_byte_emitter("int fun(void) { return 1; }\n", {"sourceQuality": "high-level-c"})
    # inline-asm-c reproduces bytes, not real C -> hard reject.
    assert looks_like_byte_emitter("void f(void){ __asm _emit 0x90 }\n", {"sourceQuality": "inline-asm-c"})
    assert looks_like_byte_emitter("void f(void){ _asm { mov eax, 1 } }\n")
    assert looks_like_byte_emitter("payload db 90h, 90h\n")
    assert looks_like_byte_emitter(
        "static const unsigned char payload[] = {0x90, 0x90};\n"
        "void f(void *p) { memcpy(p, payload, sizeof(payload)); }\n"
    )


def test_normalize_entry_hex() -> None:
    assert normalize_entry_hex("0x401000") == "401000"
    assert normalize_entry_hex("00401000") == "00401000"
    assert normalize_entry_hex(0x401000) == "00401000"
    assert normalize_entry_hex(None) == ""


def test_authority_label_requires_proven_zero() -> None:
    # source-shape row without a proven zero must be advisory, never verified.
    assert authority_label({"status": "source-shape-code-slice-matched"}) == "ghidra-advisory"
    assert authority_label({"status": "matched", "differences": 5}) == "ghidra-advisory"
    assert authority_label({"status": "matched", "differences": 0}) == "objdiff-matched"


def test_dump_excludes_byte_emitter_from_verified(tmp_path: Path) -> None:
    """End-to-end honesty gate: a byte-emitter matched row must not reach verified/."""

    import json

    summary = tmp_path / "summary.jsonl"
    clean_path = tmp_path / "clean.c"
    emitter_path = tmp_path / "emit.c"
    clean_path.write_text("int CleanFn(void) {\n    return 42;\n}\n", encoding="utf-8")
    emitter_path.write_text("void EmitFn(void) {\n    __asm _emit 0x90\n}\n", encoding="utf-8")
    rows = [
        {
            "name": "CleanFn",
            "entry": "00401000",
            "status": "matched",
            "differences": 0,
            "source": str(clean_path),
            "sourceQuality": "high-level-c",
        },
        {
            "name": "EmitFn",
            "entry": "00402000",
            "status": "matched",
            "differences": 0,
            "source": str(emitter_path),
            "sourceQuality": "inline-asm-c",
        },
    ]
    summary.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(out_dir=out_dir, summaries=[summary], reference_root=tmp_path)

    verified = out_dir / "verified"
    verified_files = list(verified.glob("**/*.c")) if verified.exists() else []
    joined = "\n".join(p.read_text(encoding="utf-8") for p in verified_files)
    assert "_emit" not in joined, "byte-emitter body leaked into verified/"
    assert manifest["rejectedByteEmitters"] >= 1
    # The clean function should still be verified.
    assert any("CleanFn" in p.name for p in verified_files)


def test_module_banding() -> None:
    # No va_bands supplied and no assert-string/RTTI/call-graph evidence: falls
    # back to the unmapped module rather than any hardcoded product banding --
    # module_resolver.ModuleResolver is deliberately never hardcoded to a
    # particular product (see its docstring).
    assert module_for_entry("00410000", None) == "recovered/unmapped"
    assert module_for_entry("00490000", "thunk") == "recovered/unmapped"

    # Operator-supplied va_bands (legacy PE banding) still resolve correctly.
    va_bands = [(0x420000, "game/swmain"), (0x4a0000, "libsource/recovered")]
    assert module_for_entry("00410000", None, va_bands=va_bands) == "game/swmain"
    assert module_for_entry("00490000", "thunk", va_bands=va_bands) == "libsource/recovered"


def test_dump_source_tree_layers_and_format_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Assemble-then-flush dump: verified + advisory + Port layout; format once per C/H file."""

    import json

    format_calls: list[str] = []

    def _counting_format(source: str, suffix: str):
        format_calls.append(suffix.lower())
        return source if source.endswith("\n") else source + "\n", {
            "schema": "agentdecompile.source-formatting.v1",
            "status": "formatted",
            "tool": "test-stub",
        }

    monkeypatch.setattr(
        "agentdecompile_recovery.source_dump.format_source_text",
        _counting_format,
    )

    summary = tmp_path / "summary.jsonl"
    clean_path = tmp_path / "clean.c"
    clean_path.write_text("int CleanFn(void) {\n    return 42;\n}\n", encoding="utf-8")
    summary.write_text(
        json.dumps(
            {
                "name": "CleanFn",
                "entry": "00401000",
                "status": "matched",
                "differences": 0,
                "source": str(clean_path),
                "sourceQuality": "high-level-c",
                "kind": "return-constant-cdecl",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    # A "FUN_"-prefixed name with no module-resolution evidence would fail the
    # readability gate (see passes_readability_gate) and be excluded from
    # Port/CODE and the manifest's function listing, even though its raw
    # advisory .c file is still written -- give this row a named function and
    # module-resolution evidence so it exercises the counted (non-excluded)
    # path, matching the test's intent of checking manifest counts.
    facts = tmp_path / "facts.jsonl"
    facts.write_text(
        json.dumps(
            {
                "name": "RecoveredHelper",
                "entry": "00500000",
                "entryOffset": "00500000",
                "decompiled": "void RecoveredHelper(void) {\n    return;\n}\n",
                "decompilationStatus": "complete",
                "entityKind": "function",
                "bodyBytes": 1,
                "prototype": "void RecoveredHelper(void)",
                "tool": "ghidra",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=[summary],
        ghidra_facts=facts,
        reference_root=tmp_path,
        module_hints={"00500000": {"module": "game/somemodule", "moduleProvenance": "assert-string"}},
    )

    verified = list((out_dir / "verified").glob("**/*.c"))
    advisory = list((out_dir / "advisory" / "ghidra").glob("**/*.c"))
    port_cpp = list((out_dir / "Port" / "CODE").rglob("*.cpp"))
    port_h = list((out_dir / "Port" / "CODE").rglob("*.h"))

    assert any("CleanFn" in p.name for p in verified)
    assert any("RecoveredHelper" in p.name for p in advisory)
    assert port_cpp, "expected Port/CODE module .cpp files"
    assert port_h, "expected Port/CODE module .h files"
    assert (out_dir / "MANIFEST.json").is_file()
    assert manifest["matchedCount"] == 1
    assert manifest["ghidraCount"] == 1

    c_like_on_disk = (
        list((out_dir / "verified").rglob("*.c"))
        + list((out_dir / "advisory").rglob("*.c"))
        + list((out_dir / "Port" / "CODE").rglob("*.cpp"))
        + list((out_dir / "Port" / "CODE").rglob("*.h"))
    )
    assert len(format_calls) == len(c_like_on_disk)
    # Must not format once per function body then again per module (would be > on-disk count).
    assert len(format_calls) < 10


def test_dump_uses_embedded_source_when_candidate_path_is_missing(tmp_path: Path) -> None:
    import json

    source = "int EmbeddedOnly(void) {\n    return 11;\n}\n"
    summary = tmp_path / "summary.jsonl"
    summary.write_text(
        json.dumps(
            {
                "name": "EmbeddedOnly",
                "entry": "00403000",
                "status": "matched",
                "differences": 0,
                "source": str(tmp_path / "deleted-candidate.c"),
                "sourceText": source,
                "sourceSha256": source_sha256(source),
                "sourceQuality": "high-level-c",
                "kind": "return-constant-cdecl",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "dump"
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=[summary],
        reference_root=tmp_path,
    )

    verified = list((out_dir / "verified").glob("*EmbeddedOnly.c"))
    assert len(verified) == 1
    assert "return 11" in verified[0].read_text(encoding="utf-8")
    assert manifest["matchedCount"] == 1
