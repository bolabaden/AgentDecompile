from __future__ import annotations

import builtins
import sys

from agentdecompile_cli.stdio_bridge import AgentDecompileStdioBridge, _normalize_backend_url


def test_normalize_backend_url_from_host_port():
    assert _normalize_backend_url("localhost:8080") == "http://localhost:8080/mcp/message"


def test_normalize_backend_url_preserves_explicit_endpoint():
    assert (
        _normalize_backend_url("https://example.com/mcp/message")
        == "https://example.com/mcp/message"
    )


def test_normalize_backend_url_appends_endpoint_to_custom_path():
    assert (
        _normalize_backend_url("https://example.com/base")
        == "https://example.com/base/mcp/message"
    )


def test_stdio_bridge_accepts_int_port_back_compat():
    bridge = AgentDecompileStdioBridge(8080)
    assert bridge.port == 8080
    assert bridge.url == "http://localhost:8080/mcp/message"


def test_stdio_bridge_accepts_url_and_api_key():
    bridge = AgentDecompileStdioBridge("example.com:9000", api_key="abc123")
    assert bridge.port is None
    assert bridge.url == "http://example.com:9000/mcp/message"
    assert bridge._streamable_http_headers == {"X-API-Key": "abc123"}


def test_connect_mode_main_does_not_import_pyghidra(monkeypatch):
    # Import module lazily so monkeypatches apply to the module's main() call.
    import agentdecompile_cli.__main__ as cli_main

    async def fake_run(self):  # noqa: ANN001
        return None

    monkeypatch.setattr(cli_main.AgentDecompileCLI, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["mcp-agentdecompile", "--mcp-server-url", "http://localhost:8080"],
    )

    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):  # noqa: ANN001
        if name == "pyghidra":
            raise AssertionError("pyghidra should not be imported in connect mode")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    cli_main.main()


def test_connect_mode_selected_from_env(monkeypatch):
    import agentdecompile_cli.__main__ as cli_main

    async def fake_run(self):  # noqa: ANN001
        return None

    monkeypatch.setattr(cli_main.AgentDecompileCLI, "run", fake_run)
    monkeypatch.setenv("AGENT_DECOMPILE_MCP_SERVER_URL", "localhost:8080")
    monkeypatch.setattr(sys, "argv", ["mcp-agentdecompile"])
    cli_main.main()
