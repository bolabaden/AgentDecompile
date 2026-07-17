"""Unit tests for windowed recovery helpers ported from the donor PE lane."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.state import atomic_write_json
from agentdecompile_recovery.tools import (
    STEAMLESS_API_NAME,
    ToolchainError,
    ensure_steamless_layout,
    resolve_steamless_cli,
)
from agentdecompile_recovery.windows import (
    OBJDIFF_PROOF_TIER,
    build_recovered_source_package,
    render_gas_byte_source,
    safe_asm_symbol,
    source_suffix_for_task,
    synthesize_catalog_task_source,
    target_byte_span_for_task,
)


def test_gas_bootstrap_is_byte_authoritative_not_semantic() -> None:
    text = render_gas_byte_source("alpha", b"\x90\x90\xc3")
    assert ".globl alpha" in text
    assert "0x90" in text
    assert "not semantic" in text.lower()


def test_safe_asm_symbol_sanitizes() -> None:
    assert safe_asm_symbol("foo-bar") == "foo_bar"
    assert safe_asm_symbol("9abc").startswith("sub_")


def test_target_byte_span_and_suffix(tmp_path: Path) -> None:
    task = {
        "name": "FUN_401000",
        "sourceLanguage": "gas",
        "sourceQuality": "byte-emission-asm",
        "automaticGenerator": {"targetByteSpan": {"offset": 16, "length": 4}},
        "targetSlice": {"status": "complete", "bytesPath": str(tmp_path / "slice.bin")},
    }
    assert target_byte_span_for_task(task) == (16, 4)
    assert source_suffix_for_task(Path("x.c"), task) == ".S"

    (tmp_path / "slice.bin").write_bytes(b"\xcc\xcc\xcc\xcc")
    out = synthesize_catalog_task_source(task, tmp_path / "functions")
    assert out is not None
    assert out.suffix == ".S"
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    symbol = safe_asm_symbol("FUN_401000")
    assert f".globl {symbol}" in text
    assert "0xcc" in text


def test_ensure_steamless_layout_copies_api_and_fails_closed(tmp_path: Path) -> None:
    cli_dir = tmp_path / "steamless"
    plugins = cli_dir / "Plugins"
    plugins.mkdir(parents=True)
    cli = cli_dir / "Steamless.CLI.exe"
    cli.write_bytes(b"MZ")
    plugin_api = plugins / STEAMLESS_API_NAME
    plugin_api.write_bytes(b"api")
    resolved = ensure_steamless_layout(cli)
    assert resolved == cli.resolve()
    api = cli_dir / STEAMLESS_API_NAME
    assert api.exists()
    assert api.read_bytes() == b"api"
    # Idempotent when already beside the exe.
    ensure_steamless_layout(cli)
    assert api.read_bytes() == b"api"

    bare = tmp_path / "bare"
    bare.mkdir()
    bare_cli = bare / "Steamless.CLI.exe"
    bare_cli.write_bytes(b"MZ")
    with pytest.raises(ToolchainError):
        ensure_steamless_layout(bare_cli)


def test_resolve_steamless_prefers_repo_root_over_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    for root in (repo, cwd):
        extracted = root / "target" / "steamless-release" / "extracted"
        extracted.mkdir(parents=True)
        cli = extracted / "Steamless.CLI.exe"
        cli.write_bytes(b"MZ")
        (extracted / STEAMLESS_API_NAME).write_bytes(b"api")
    monkeypatch.chdir(cwd)
    resolved = resolve_steamless_cli(repo)
    assert resolved is not None
    assert resolved.resolve() == (repo / "target/steamless-release/extracted/Steamless.CLI.exe").resolve()


def test_build_recovered_source_package_preserves_promoted_accepts_on_rebuild(tmp_path: Path) -> None:
    base = tmp_path / "run"
    package = base / "recovered-source"
    functions = package / "functions"
    functions.mkdir(parents=True)
    source = functions / "alpha.c"
    meta = functions / "alpha.json"
    source.write_text("int alpha(void){return 0;}\n", encoding="utf-8")
    atomic_write_json(
        meta,
        {
            "name": "alpha",
            "address": "0x401000",
            "status": "source-parity-accepted",
            "proofTier": OBJDIFF_PROOF_TIER,
            "source": str(source),
        },
    )
    atomic_write_json(
        package / "manifest.json",
        {
            "schema": "agentdecompile.recovered-source-package.v1",
            "functions": [
                {
                    "name": "alpha",
                    "address": "0x401000",
                    "status": "source-parity-accepted",
                    "proofTier": OBJDIFF_PROOF_TIER,
                    "source": str(source),
                    "metadata": str(meta),
                }
            ],
            "functionCount": 1,
            "sourceParityAcceptedFunctionCount": 1,
        },
    )
    # Unverified candidate that should not block restore of the accept.
    (package / "README.md").write_text("old\n", encoding="utf-8")

    rebuilt = build_recovered_source_package(base, windows=[])
    assert rebuilt["restoredPromotedAccepts"] == 1
    assert rebuilt["sourceParityAcceptedFunctionCount"] == 1
    assert (package / "functions" / "alpha.c").exists()
    assert (package / "functions" / "alpha.c").read_text(encoding="utf-8").startswith("int alpha")
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["sourceParityAcceptedFunctionCount"] == 1
    assert any(fn.get("proofTier") == OBJDIFF_PROOF_TIER for fn in manifest["functions"])
    assert not (base / ".recovered-source-accepted-cache").exists()
