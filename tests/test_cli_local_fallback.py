from __future__ import annotations

import types

from unittest.mock import AsyncMock, patch

import click
import pytest

try:
    from agentdecompile_cli.bridge import ServerNotRunningError
    from agentdecompile_cli.cli import _resolve_backend_target, main
    from click.testing import CliRunner

    _CLICK_AVAILABLE = True
except ImportError:
    _CLICK_AVAILABLE = False


pytestmark = pytest.mark.skipif(not _CLICK_AVAILABLE, reason="click CLI not available")


class _FailingClient:
    async def __aenter__(self):
        raise ServerNotRunningError("Cannot connect to backend")

    async def __aexit__(
        self,
        exc_type: type | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ):
        return None


def _runner() -> CliRunner:
    return CliRunner()


def _success_result(text: str = "ok") -> dict[str, object]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


class TestCliLocalFallbackPolicy:
    @patch("agentdecompile_cli.cli._attempt_local_backend_recovery", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client", return_value=_FailingClient())
    def test_explicit_server_url_does_not_fallback(self, _mocked_client: AsyncMock, mocked_recovery: AsyncMock):
        result = _runner().invoke(
            main,
            [
                "--server-url",
                "http://127.0.0.1:65500",
                "tool",
                "execute-script",
                '{"code":"__result__ = 7","responseFormat":"json"}',
            ],
        )

        assert result.exit_code != 0
        mocked_recovery.assert_not_awaited()
        assert "Cannot connect to backend" in result.output

    @patch("agentdecompile_cli.cli._attempt_local_backend_recovery", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client", return_value=_FailingClient())
    def test_invalid_env_server_url_triggers_local_recovery(self, _mocked_client: AsyncMock, mocked_recovery: AsyncMock):
        mocked_recovery.return_value = _success_result("env recovered")

        result = _runner().invoke(
            main,
            [
                "tool",
                "execute-script",
                '{"code":"__result__ = 7","responseFormat":"json"}',
            ],
            env={"AGENT_DECOMPILE_MCP_SERVER_URL": "http://127.0.0.1:65500"},
        )

        assert result.exit_code == 0, result.output
        mocked_recovery.assert_awaited_once()
        assert "env recovered" in result.output

    @patch("agentdecompile_cli.cli._attempt_local_backend_recovery", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client", return_value=_FailingClient())
    def test_default_local_target_triggers_local_recovery(self, _mocked_client: AsyncMock, mocked_recovery: AsyncMock):
        mocked_recovery.return_value = _success_result("default recovered")

        result = _runner().invoke(
            main,
            [
                "tool",
                "execute-script",
                '{"code":"__result__ = 7","responseFormat":"json"}',
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_recovery.assert_awaited_once()
        assert "default recovered" in result.output


class TestBackendTargetResolution:
    def test_cached_local_server_beats_implicit_default(self):
        ctx = click.Context(
            main,
            obj={
                "host": "127.0.0.1",
                "port": 8080,
                "server_url": None,
                "backend_cli_url_explicit": False,
                "backend_host_explicit": False,
                "backend_port_explicit": False,
                "backend_cli_explicit": False,
            },
        )

        with patch(
            "agentdecompile_cli.cli._load_cli_state",
            return_value={"local_server": {"url": "http://127.0.0.1:8099", "port": 8099, "managed_by": "agentdecompile-cli", "pid": None}},
        ):
            resolution = _resolve_backend_target(ctx)

        assert resolution.source == "cached_local_server"
        assert resolution.url.endswith(":8099/mcp/message")
