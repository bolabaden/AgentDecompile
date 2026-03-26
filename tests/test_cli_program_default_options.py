"""CLI default programPath / binaryName via global flags, tool options, and env."""

from __future__ import annotations

import click
import pytest

# Defer `agentdecompile_cli.cli` import until tests run so `python this_file.py` does not
# load anyio before pytest-asyncio's assert rewrite (avoids PytestAssertRewriteWarning).


@pytest.mark.unit
def test_prepare_injects_program_path_from_ctx_obj() -> None:
    from agentdecompile_cli.cli import _prepare_tool_payload_with_program_fallback, main

    ctx = click.Context(main)
    ctx.obj = {"cli_default_program_path": "/K1/k1_win_gog_swkotor.exe"}
    payload, inferred = _prepare_tool_payload_with_program_fallback(ctx, "get-call-graph", {})
    assert payload.get("programPath") == "/K1/k1_win_gog_swkotor.exe"
    assert inferred == "/K1/k1_win_gog_swkotor.exe"


@pytest.mark.unit
def test_prepare_explicit_program_beats_cli_default() -> None:
    from agentdecompile_cli.cli import _prepare_tool_payload_with_program_fallback, main

    ctx = click.Context(main)
    ctx.obj = {"cli_default_program_path": "/other.exe"}
    payload, inferred = _prepare_tool_payload_with_program_fallback(
        ctx,
        "get-call-graph",
        {"programPath": "/chosen.exe"},
    )
    assert payload.get("programPath") == "/chosen.exe"
    assert inferred is None


@pytest.mark.unit
def test_prepare_binary_name_param_uses_binary_option(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.cli import _prepare_tool_payload_with_program_fallback, main

    ctx = click.Context(main)
    ctx.obj = {"cli_default_binary_name": "mybin.exe"}
    monkeypatch.delenv("AGENTDECOMPILE_PROGRAM_PATH", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_PROGRAM_PATH", raising=False)
    # Use a tool that only advertises binaryName if any — search-everything has programPath first
    payload, _ = _prepare_tool_payload_with_program_fallback(ctx, "search-everything", {"query": "x"})
    assert payload.get("programPath") == "mybin.exe"


@pytest.mark.unit
def test_prepare_env_program_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.cli import _prepare_tool_payload_with_program_fallback, main

    ctx = click.Context(main)
    ctx.obj = {}
    monkeypatch.setenv("AGENTDECOMPILE_PROGRAM_PATH", "/from/env.exe")
    payload, _ = _prepare_tool_payload_with_program_fallback(ctx, "get-call-graph", {})
    assert payload.get("programPath") == "/from/env.exe"


@pytest.mark.unit
def test_prepare_allows_missing_program_for_session_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting programPath is valid; backend uses MCP session active program."""
    from agentdecompile_cli.cli import _prepare_tool_payload_with_program_fallback, main

    ctx = click.Context(main)
    ctx.obj = {}
    for key in (
        "AGENTDECOMPILE_PROGRAM_PATH",
        "AGENT_DECOMPILE_PROGRAM_PATH",
        "AGENTDECOMPILE_PROGRAM",
        "AGENT_DECOMPILE_PROGRAM",
        "AGENTDECOMPILE_BINARY_NAME",
        "AGENT_DECOMPILE_BINARY_NAME",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(
        "agentdecompile_cli.cli._load_cli_state",
        lambda: {},
    )
    payload, inferred = _prepare_tool_payload_with_program_fallback(ctx, "checkout-status", {})
    assert "programPath" not in payload
    assert inferred is None


if __name__ == "__main__":
    # Restrict to this file; bare pytest.main() would use testpaths and run all of tests/.
    pytest.main([__file__, "-v"])