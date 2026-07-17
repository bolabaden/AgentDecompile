"""Unit tests for acquisition / context fusion (Phase 1) + review-fix honesty."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agentdecompile_recovery.acquire import acquire_context
from agentdecompile_recovery.acquisition_bundle import (
    build_bundle,
    load_bundle,
    query_entities,
    source_record,
    validate_bundle_target,
)
from agentdecompile_recovery.acquisition_mcp import query_bundle
from agentdecompile_recovery.acquisition_registry import (
    REGISTRY_ENV,
    REGISTRY_SCHEMA,
    load_index,
    register_bundle,
    resolve_bundle,
)
from agentdecompile_recovery.claim_report import build_claim_report, write_claim_report
from agentdecompile_recovery.discovery import sniff_path
from agentdecompile_recovery.frontdoor import build_parser as build_frontdoor_parser
from agentdecompile_recovery.tools import STEAMLESS_API_NAME, ToolchainError, ensure_steamless_layout


pytestmark = pytest.mark.unit


def test_bundle_conflicts_and_claim_boundary(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    target = {"stableId": "fixture", "sha256": "a" * 64, "architectureHint": "x86", "imageBase": 0x400000}
    facts = [
        {"name": "alpha", "entryOffset": 0x401000, "sourceId": "one", "decompiled": "int alpha(void) { return 0; }"},
        {"name": "beta_alias", "entryOffset": 0x401000, "sourceId": "two", "decompiled": "int beta(void) { return 1; }"},
        {"name": "alpha", "entryOffset": 0x402000, "sourceId": "three", "decompiled": "int alpha2(void) { return 2; }"},
    ]
    manifest = build_bundle(
        out_dir=out,
        target=target,
        sources=[source_record(path="one.c", source_id="one", kind="source", content_hash="a", extractor="test")],
        facts=facts,
    )
    loaded, entities, conflicts = load_bundle(out)
    assert loaded["targetFingerprint"] == manifest["targetFingerprint"]
    assert len(conflicts) == 1 and conflicts[0]["address"] == 0x401000
    assert len(query_entities(entities, kind="function", query="alpha")) == 2
    assert len((out / "function-facts.jsonl").read_text(encoding="utf-8").splitlines()) == 3
    assert "objdiff" in entities[0]["claimBoundary"]
    assert validate_bundle_target(loaded, target)["targetMatched"] is True
    with pytest.raises(ValueError):
        validate_bundle_target(loaded, {"stableId": "wrong"})


def test_acquire_registers_and_resolves_from_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "registry"))
    binary = tmp_path / "app.elf"
    binary.write_bytes(b"\x7fELF\x02\x01\x01" + os.urandom(64))
    notes = tmp_path / "notes.md"
    notes.write_text("# Notes\nFUN_00148020 returns a default object pointer when a global is unset.\n", encoding="utf-8")
    facts = tmp_path / "facts.jsonl"
    facts.write_text(
        json.dumps(
            {
                "kind": "function",
                "name": "FUN_00148020",
                "address": "0x148020",
                "summary": "returns default object pointer when global unset",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    receipt = acquire_context(
        target_input=binary,
        context_paths=[notes, facts],
        out_dir=tmp_path / "acq",
        repo_root=tmp_path,
        register=True,
    )
    assert receipt["schema"] == "agentdecompile.acquire.v1"
    # Target binary is routed to Ghidra; without analyzeHeadless this may be partial.
    assert receipt["status"] in {"complete", "partial"}
    assert receipt["registered"] is True
    banned = ("recon" + "kit", "mizu" + "chi")
    blob = json.dumps(receipt).lower()
    assert all(token not in blob for token in banned)

    bundle_dir = Path(str(receipt["bundleDir"]))
    assert (bundle_dir / "manifest.json").exists()
    index = load_index(tmp_path)
    assert index["schema"] == REGISTRY_SCHEMA
    assert len(index["bundles"]) == 1

    target = receipt["target"]
    resolved = resolve_bundle(target=target, repo_root=tmp_path)
    assert resolved is not None
    assert Path(resolved).resolve() == bundle_dir.resolve()

    queried = query_bundle(bundle_dir, action="get-function", query="FUN_00148020")
    assert queried["schema"] == "agentdecompile.acquisition-query.v1"
    assert queried["status"] == "complete"
    assert queried["resultCount"] == 1
    assert "advisory" in queried["claimBoundary"]


def test_sniff_notes_and_source(tmp_path: Path) -> None:
    notes = tmp_path / "notes.md"
    notes.write_text("hello\n", encoding="utf-8")
    src = tmp_path / "fn.c"
    src.write_text("int foo(void) { return 0; }\n", encoding="utf-8")
    assert sniff_path(notes).adapter == "context-pack"
    assert sniff_path(src).adapter == "context-pack"


def test_mid_run_acquire_merges_same_fingerprint_and_preserves_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "registry"))
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"MZfake" + os.urandom(64))
    run = tmp_path / "run"
    acq = run / "acquisition"
    verified = run / "verified"
    verified.mkdir(parents=True)
    keep = verified / "keep_00401000.c"
    keep.write_text("int keep(void){return 0;}\n", encoding="utf-8")
    (verified / "keep_00401000.objdiff-verified.json").write_text(
        json.dumps({"proofTier": "target-object-objdiff-match", "status": "matched", "differences": 0, "count": 1}),
        encoding="utf-8",
    )

    notes_a = tmp_path / "notes_a.md"
    notes_a.write_text(
        "# A\nFUN_00401000 at 0x401000 returns zero.\n",
        encoding="utf-8",
    )
    facts_a = tmp_path / "facts_a.jsonl"
    facts_a.write_text(
        json.dumps(
            {
                "kind": "function",
                "name": "FUN_00401000",
                "address": "0x401000",
                "summary": "returns zero",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    first = acquire_context(
        target_input=binary,
        context_paths=[notes_a, facts_a],
        out_dir=acq,
        repo_root=tmp_path,
        register=True,
    )
    assert first["registered"] is True
    first_bundle = Path(str(first["bundleDir"]))
    first_fp = first["targetFingerprint"]
    assert first.get("snapshotDir")
    assert first_bundle.exists()

    notes_b = tmp_path / "notes_b.md"
    notes_b.write_text(
        "# B\nFUN_00402000 at 0x402000 allocates a buffer.\n",
        encoding="utf-8",
    )
    facts_b = tmp_path / "facts_b.jsonl"
    facts_b.write_text(
        json.dumps(
            {
                "kind": "function",
                "name": "FUN_00402000",
                "address": "0x402000",
                "summary": "allocates buffer",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Mid-run: only new context paths — prior evidence must still be present.
    second = acquire_context(
        target_input=binary,
        context_paths=[notes_b, facts_b],
        out_dir=acq,
        repo_root=tmp_path,
        register=True,
    )
    assert second["registered"] is True
    assert second["targetFingerprint"] == first_fp
    assert second.get("priorBundleDir")
    assert int(second.get("mergedPriorSourceCount") or 0) >= 1
    second_bundle = Path(str(second["bundleDir"]))
    assert second_bundle.resolve() != first_bundle.resolve()
    assert first_bundle.exists()  # immutable prior snapshot

    queried_old = query_bundle(second_bundle, action="get-function", query="FUN_00401000")
    queried_new = query_bundle(second_bundle, action="get-function", query="FUN_00402000")
    assert queried_old["resultCount"] >= 1
    assert queried_new["resultCount"] >= 1
    assert keep.exists()
    assert keep.read_text(encoding="utf-8").startswith("int keep")


def test_mid_run_acquire_records_conflicts_across_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "registry"))
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"MZfake" + os.urandom(32))
    facts_a = tmp_path / "a.jsonl"
    facts_a.write_text(
        json.dumps({"kind": "function", "name": "alpha", "address": "0x401000", "summary": "a"}) + "\n",
        encoding="utf-8",
    )
    first = acquire_context(
        target_input=binary,
        context_paths=[facts_a],
        out_dir=tmp_path / "acq",
        repo_root=tmp_path,
        register=True,
    )
    facts_b = tmp_path / "b.jsonl"
    facts_b.write_text(
        json.dumps({"kind": "function", "name": "beta", "address": "0x401000", "summary": "b"}) + "\n",
        encoding="utf-8",
    )
    second = acquire_context(
        target_input=binary,
        context_paths=[facts_b],
        out_dir=tmp_path / "acq",
        repo_root=tmp_path,
        register=True,
    )
    _, entities, conflicts = load_bundle(Path(str(second["bundleDir"])))
    assert first["targetFingerprint"] == second["targetFingerprint"]
    assert any(c.get("address") == 0x401000 and c.get("resolution") == "unresolved" for c in conflicts)
    names = {str(e.get("name")) for e in entities if e.get("address") == 0x401000}
    assert "alpha" in names and "beta" in names


def test_frontdoor_exposes_context_flags() -> None:
    parser = build_frontdoor_parser()
    dests = {action.dest for action in parser._actions}
    assert "context" in dests
    assert "context_positional" in dests
    assert "context_pack" in dests
    assert "acquisition_bundle" in dests
    assert "autonomous" in dests
    args = parser.parse_args(["/tmp/x.exe", "--context", "/tmp/n.md", "--stop-after", "discover"])
    assert args.context == [Path("/tmp/n.md")]
    args2 = parser.parse_args(["/tmp/x.exe", "/tmp/a.c", "/tmp/notes.md", "--context", "/tmp/b.jsonl"])
    assert args2.context_positional == [Path("/tmp/a.c"), Path("/tmp/notes.md")]
    assert args2.context == [Path("/tmp/b.jsonl")]


def test_merge_context_paths_dedupes() -> None:
    from agentdecompile_recovery.frontdoor import merge_context_paths

    a = Path("/tmp/a.c")
    b = Path("/tmp/b.md")
    merged = merge_context_paths([a, b], [a, Path("/tmp/c.json")])
    assert merged[0] == a
    assert b in merged
    assert len(merged) == 3


def test_source_dump_seeds_and_placement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_recovery.context_pack import materialize_context_seeds, write_placement_summary
    from agentdecompile_recovery.recovery_status import build_recovery_status

    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "registry"))
    binary = tmp_path / "app.elf"
    binary.write_bytes(b"\x7fELF\x02\x01\x01" + os.urandom(64))
    dump = tmp_path / "ugly.c"
    dump.write_text(
        "// VA: 0x401000\nint FUN_00401000(void) {\n  return 0;\n}\n",
        encoding="utf-8",
    )
    note = tmp_path / "loose.md"
    note.write_text("Remember the audio mixer is weird.\n", encoding="utf-8")

    work = tmp_path / "work"
    receipt = acquire_context(
        target_input=binary,
        context_paths=[dump, note],
        out_dir=work / "acquisition",
        repo_root=tmp_path,
        register=True,
    )
    placement = write_placement_summary(
        work / "acquisition",
        pack_manifest=receipt.get("contextPack") or {},
        bundle_dir=Path(str(receipt.get("bundleDir"))),
        routing=receipt.get("routing") or {},
    )
    seeds = materialize_context_seeds(
        pack_manifest=receipt.get("contextPack") or {},
        seed_dir=work / "advisory" / "context-seeds",
        facts_path=Path(str(receipt.get("snapshotDir"))) / "context-pack" / "function-facts.jsonl",
    )
    assert placement["counts"]["factsImported"] >= 1
    assert placement["counts"]["unplaced"] >= 1  # loose note
    assert seeds["counts"]["seeded"] >= 1
    assert any((work / "advisory" / "context-seeds").glob("*.c"))

    status = build_recovery_status(work)
    assert status["contextFusion"] is not None
    assert status["contextFusion"]["seeds"] >= 1
    assert status["paths"]["placement"]


def test_claim_report_requires_objdiff_proof_for_semantic(tmp_path: Path) -> None:
    work = tmp_path / "run"
    verified = work / "verified"
    advisory = work / "advisory"
    verified.mkdir(parents=True)
    advisory.mkdir(parents=True)
    (verified / "alpha.c").write_text("int alpha(void){return 0;}\n", encoding="utf-8")
    (advisory / "beta.c").write_text("int beta(void){return 1;}\n", encoding="utf-8")
    synth = work / "source-synthesis"
    synth.mkdir()
    (synth / "summary.json").write_text(json.dumps({"acceptedCandidates": 1}), encoding="utf-8")
    report = build_claim_report(work_dir=work, terminal_status="partial")
    assert report["schema"] == "agentdecompile.claim-report.v1"
    assert report["counts"]["verified"] == 1
    assert report["counts"]["acceptedCandidates"] == 1
    assert report["counts"]["objdiffVerified"] == 0
    # Bare verified/ + acceptedCandidates alone must not claim semantic objdiff proof.
    assert not any(c["class"] == "objdiff-verified-semantic" for c in report["claims"])
    assert any(c["class"] == "advisory-decompiler" for c in report["claims"])
    assert any("bare verified" in str(x).lower() for x in report["nonClaims"])

    (verified / "alpha.json").write_text(
        json.dumps(
            {
                "name": "alpha",
                "status": "source-parity-accepted",
                "proofTier": "target-object-objdiff-match",
                "differences": 0,
            }
        ),
        encoding="utf-8",
    )
    proven = build_claim_report(work_dir=work, terminal_status="matched")
    assert proven["counts"]["objdiffVerified"] == 1
    assert any(c["class"] == "objdiff-verified-semantic" for c in proven["claims"])


def test_claim_report_byte_and_context_hint(tmp_path: Path) -> None:
    work = tmp_path / "run"
    (work / "byte-authority").mkdir(parents=True)
    (work / "byte-authority" / "slice.bin").write_bytes(b"\x90")
    acq = work / "acquisition"
    acq.mkdir(parents=True)
    (acq / "acquire.json").write_text("{}", encoding="utf-8")
    report = build_claim_report(work_dir=work)
    classes = {c["class"] for c in report["claims"]}
    assert "byte-authoritative" in classes
    assert "context-hint" in classes
    path = write_claim_report(work, terminal_status="partial")
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == "agentdecompile.claim-report.v1"


def test_ensure_steamless_layout_copies_api_and_fails_closed(tmp_path: Path) -> None:
    cli = tmp_path / "Steamless.CLI.exe"
    cli.write_bytes(b"MZ")
    plugins = tmp_path / "Plugins"
    plugins.mkdir()
    (plugins / STEAMLESS_API_NAME).write_bytes(b"api")
    resolved = ensure_steamless_layout(cli)
    assert resolved == cli.resolve()
    assert (tmp_path / STEAMLESS_API_NAME).exists()
    ensure_steamless_layout(cli)

    bare = tmp_path / "bare"
    bare.mkdir()
    bare_cli = bare / "Steamless.CLI.exe"
    bare_cli.write_bytes(b"MZ")
    with pytest.raises(ToolchainError) as exc:
        ensure_steamless_layout(bare_cli)
    assert "steamless-api-missing" in str(exc.value)
    assert str(exc.value).startswith("blocked:toolchain:")


def test_register_bundle_refuses_empty_fingerprint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "registry"))
    with pytest.raises(ValueError, match="refusing to register"):
        register_bundle(
            bundle_dir=tmp_path / "bundle",
            manifest={"targetFingerprint": "", "target": {}},
            repo_root=tmp_path,
        )
    with pytest.raises(ValueError, match="refusing to register"):
        register_bundle(
            bundle_dir=tmp_path / "bundle",
            manifest={"targetFingerprint": "abc", "target": {}},
            repo_root=tmp_path,
        )
