from __future__ import annotations

import builtins
import sys

from agentdecompile_cli.bridge import AgentDecompileStdioBridge
from agentdecompile_cli.executor import normalize_backend_url
from tests.helpers import assert_bool_invariants, assert_string_invariants, assert_url_shape


def test_normalize_backend_url_from_host_port():
    url = normalize_backend_url("localhost:8080")
    assert_url_shape(url, scheme="http", host="localhost:8080", path="/mcp/message")
    assert url == "http://localhost:8080/mcp/message"
    assert url.count(":") >= 2
    assert "localhost" in url


def test_normalize_backend_url_preserves_explicit_endpoint():
    url = normalize_backend_url("https://example.com/mcp/message")
    assert_url_shape(url, scheme="https", host="example.com", path="/mcp/message")
    assert url == "https://example.com/mcp/message"
    assert url.startswith("https://")
    assert url.endswith("/mcp/message")


def test_normalize_backend_url_appends_endpoint_to_custom_path():
    url = normalize_backend_url("https://example.com/base")
    assert_url_shape(url, scheme="https", host="example.com", path="/base/mcp/message")
    assert url == "https://example.com/base/mcp/message"
    assert "/base/" in url
    assert url.count("/mcp/message") == 1


def test_stdio_bridge_accepts_int_port_back_compat():
    bridge = AgentDecompileStdioBridge(8080)
    assert bridge.port == 8080
    assert_url_shape(bridge.url, scheme="http", host="localhost:8080", path="/mcp/message")
    assert bridge.url == "http://localhost:8080/mcp/message"
    assert bridge.url.startswith("http://localhost")
    assert bridge.url.endswith("/mcp/message")
    assert_bool_invariants(isinstance(bridge.port, int))


def test_stdio_bridge_accepts_url():
    bridge = AgentDecompileStdioBridge("example.com:9000")
    assert bridge.port is None
    assert_url_shape(bridge.url, scheme="http", host="example.com:9000", path="/mcp/message")
    assert bridge.url == "http://example.com:9000/mcp/message"
    assert bridge._streamable_http_headers is None
    assert bridge.url.startswith("http://example.com")
    assert_bool_invariants(bridge.port is None)


def test_stdio_bridge_initialization_options_include_logging_capability():
    bridge = AgentDecompileStdioBridge(8080)
    options = bridge._create_initialization_options()

    assert options.capabilities is not None
    assert options.capabilities.logging is not None


def test_connect_mode_main_does_not_import_pyghidra(monkeypatch):
    # Import module lazily so monkeypatches apply to the module's main() call.
    import agentdecompile_cli.__main__ as cli_main

    async def fake_run(self):  # noqa: ANN001
        return None

    monkeypatch.setattr(cli_main.AgentDecompileCLI, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["mcp-agentdecompile", "--server-url", "http://localhost:8080"],
    )
    assert_string_invariants(sys.argv[0], expected="mcp-agentdecompile")
    assert_string_invariants(sys.argv[1], expected="--server-url")
    assert_string_invariants(sys.argv[2], expected="http://localhost:8080")

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
    assert_string_invariants(sys.argv[0], expected="mcp-agentdecompile")
    cli_main.main()
