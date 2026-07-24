"""Unit tests for match cache, verify pool, and source dump helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.match_cache import MatchCache, cache_key, source_sha256
from agentdecompile_recovery.source_dump import (
    authority_label,
    dump_source_tree,
    looks_like_byte_emitter,
    module_for_entry,
    normalize_entry_hex,
)
from agentdecompile_recovery.verify_pool import map_parallel, resolve_workers


def test_match_cache_roundtrip(tmp_path: Path) -> None:
    cache = MatchCache()
    row = {
        "name": "FUN_00401000",
        "entry": "00401000",
        "status": "matched",
        "differences": 0,
        "sourceSha256": source_sha256("int fun(void) { return 0; }\n"),
        "compilerProfileName": "O2_GS-_Oy",
        "source": str(tmp_path / "c.c"),
    }
    (tmp_path / "c.c").write_text("int fun(void) { return 0; }\n", encoding="utf-8")
    assert cache.ingest(row)
    hit = cache.lookup(
        entry="00401000",
        source_sha=row["sourceSha256"],
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
    assert cache_key(entry="a", source_sha="b", compiler_profile="c") == "a|b|c"


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
        "compilerProfileName": "O2_GS-_Oy",
    }
    assert cache.ingest(row)
    # Same entry, different source bytes -> must miss (no false proven skip).
    assert cache.lookup(entry="00401000", source_sha=sha_b, compiler_profile="O2_GS-_Oy") is None
    # Profile-agnostic hit is still safe when the source bytes are identical.
    assert cache.lookup(entry="00401000", source_sha=sha_a, compiler_profile="different") is not None


def test_match_cache_rejects_unproven_rows() -> None:
    cache = MatchCache()
    # differences != 0 must not enter the cache as a skip authority.
    assert not cache.ingest(
        {"name": "f", "entry": "00401000", "status": "matched", "differences": 3, "sourceSha256": "x" * 64}
    )
    # Missing source sha cannot form a safe key.
    assert not cache.ingest({"name": "f", "entry": "00401000", "status": "matched", "differences": 0})


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
    manifest = dump_source_tree(out_dir=out_dir, summaries=[summary], borealis_reference=tmp_path)

    verified = out_dir / "verified"
    verified_files = list(verified.glob("**/*.c")) if verified.exists() else []
    joined = "\n".join(p.read_text(encoding="utf-8") for p in verified_files)
    assert "_emit" not in joined, "byte-emitter body leaked into verified/"
    assert manifest["rejectedByteEmitters"] >= 1
    # The clean function should still be verified.
    assert any("CleanFn" in p.name for p in verified_files)


def test_module_banding() -> None:
    assert module_for_entry("00410000", None) == "game/swmain"
    assert module_for_entry("00490000", "thunk") == "libsource/recovered"
