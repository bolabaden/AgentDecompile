from __future__ import annotations

import types

import sys

from unittest.mock import AsyncMock, Mock, patch

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
    @patch("agentdecompile_cli.cli._call_tool_locally", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client", return_value=_FailingClient())
    def test_default_cli_uses_in_process_local_execution(self, mocked_client: AsyncMock, mocked_local_call: AsyncMock, mocked_recovery: AsyncMock):
        mocked_local_call.return_value = _success_result("default local")

        result = _runner().invoke(
            main,
            [
                "tool",
                "execute-script",
                '{"code":"__result__ = 7","responseFormat":"json"}',
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_client.assert_not_called()
        mocked_recovery.assert_not_awaited()
        mocked_local_call.assert_awaited_once()
        assert "default local" in result.output

    @patch("agentdecompile_cli.cli._ensure_local_server_url", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._call_tool_locally", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client")
    def test_tool_seq_implicit_backend_uses_in_process_local_execution(self, mocked_client_factory: AsyncMock, mocked_local_call: AsyncMock, mocked_ensure_local_server_url: AsyncMock):
        mocked_local_call.side_effect = [_success_result("step one"), _success_result("step two")]

        steps = (
            '[{"name":"execute-script","arguments":{"code":"__result__ = 1","responseFormat":"json"}},'
            '{"name":"execute-script","arguments":{"code":"__result__ = 2","responseFormat":"json"}}]'
        )

        result = _runner().invoke(main, ["tool-seq", steps])

        assert result.exit_code == 0, result.output
        mocked_client_factory.assert_not_called()
        mocked_ensure_local_server_url.assert_not_awaited()
        assert mocked_local_call.await_count == 2
        assert "step one" in result.output
        assert "step two" in result.output

    @patch("agentdecompile_cli.cli._call_tool_locally", new_callable=AsyncMock)
    def test_tool_seq_accepts_args_alias_and_normalizes_payload(self, mocked_local_call: AsyncMock):
        mocked_local_call.return_value = _success_result("script ran")
        steps = '[{"name":"execute-script","args":{"program_path":"/K1/k1_win_gog_swkotor.exe","code":"__result__ = 7"}}]'

        result = _runner().invoke(main, ["tool-seq", steps])

        assert result.exit_code == 0, result.output
        mocked_local_call.assert_awaited_once()
        _ctx, tool_name, payload = mocked_local_call.await_args.args
        assert tool_name == "execute_script"
        assert payload["programPath"] == "/K1/k1_win_gog_swkotor.exe"
        assert payload["code"] == "__result__ = 7"

    @patch("agentdecompile_cli.cli._call_tool_locally", new_callable=AsyncMock)
    def test_tool_seq_rejects_conflicting_argument_aliases(self, mocked_local_call: AsyncMock):
        steps = '[{"name":"execute-script","arguments":{"code":"__result__ = 1"},"args":{"code":"__result__ = 2"}}]'

        result = _runner().invoke(main, ["tool-seq", steps])

        assert result.exit_code != 0
        mocked_local_call.assert_not_awaited()
        assert "conflicting argument aliases" in result.output

    @patch("agentdecompile_cli.cli._ensure_local_server_url", new_callable=AsyncMock)
    @patch("agentdecompile_cli.cli._client", return_value=_FailingClient())
    def test_tool_seq_explicit_server_url_does_not_fallback(self, _mocked_client: AsyncMock, mocked_ensure_local_server_url: AsyncMock):
        steps = '[{"name":"execute-script","arguments":{"code":"__result__ = 1","responseFormat":"json"}}]'

        result = _runner().invoke(
            main,
            [
                "--server-url",
                "http://127.0.0.1:65500",
                "tool-seq",
                steps,
            ],
        )

        assert result.exit_code != 0
        mocked_ensure_local_server_url.assert_not_awaited()
        assert "Cannot connect to backend" in result.output


class TestExplicitBackendDetectionFallback:
    def test_argv_option_detection_accepts_equals_form(self):
        from agentdecompile_cli.cli import _argv_contains_any_option

        with patch.object(sys, "argv", ["agentdecompile-cli", "--server-url=http://127.0.0.1:8080", "tool-seq", "[]"]):
            assert _argv_contains_any_option(("--server-url",)) is True

    def test_argv_option_detection_accepts_split_form(self):
        from agentdecompile_cli.cli import _argv_contains_any_option

        with patch.object(sys, "argv", ["agentdecompile-cli", "--mcp-server-url", "http://127.0.0.1:8080", "tool-seq", "[]"]):
            assert _argv_contains_any_option(("--server-url", "--mcp-server-url")) is True


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


class TestLocalBackendConstruction:
    @patch("agentdecompile_cli.local_backend.LocalToolBackend")
    def test_cli_local_backend_is_non_threaded(self, mocked_local_backend):
        import click
        from agentdecompile_cli.cli import _get_local_backend, main

        ctx = click.Context(
            main,
            obj={
                "local_project_path": "c:/GitHub/agentdecompile/agentdecompile.rep",
                "local_project_name": "agentdecompile",
                "verbose": False,
                "cli_default_program_path": None,
            },
        )

        with patch("agentdecompile_cli.cli._local_backend_instance", None):
            _get_local_backend(ctx)

        mocked_local_backend.assert_called_once()
        assert mocked_local_backend.call_args.kwargs["threaded"] is False


class TestCliEntryPointCleanup:
    @patch("atexit.register")
    @patch("agentdecompile_cli.cli._cleanup_local_backend_instance")
    @patch("agentdecompile_cli.cli.main", side_effect=SystemExit(0))
    def test_cli_entry_point_cleans_up_local_backend_in_finally(self, mocked_main, mocked_cleanup, mocked_atexit_register):
        from agentdecompile_cli.cli import cli_entry_point

        with pytest.raises(SystemExit):
            cli_entry_point()

        mocked_atexit_register.assert_called_once_with(mocked_cleanup)
        mocked_cleanup.assert_called_once()
        mocked_main.assert_called_once()


class TestLocalBackendCleanup:
    def test_cleanup_local_backend_closes_backend(self):
        from agentdecompile_cli.cli import _cleanup_local_backend_instance

        backend = types.SimpleNamespace(close=Mock())

        with patch("agentdecompile_cli.cli._local_backend_instance", backend):
            _cleanup_local_backend_instance()

        backend.close.assert_called_once()


class TestCliEntryPointLocalExit:
    @patch("atexit.register")
    @patch("agentdecompile_cli.cli.os._exit")
    @patch("agentdecompile_cli.cli._cleanup_local_backend_instance")
    @patch("agentdecompile_cli.cli.main", side_effect=SystemExit(0))
    def test_cli_entry_point_forces_exit_after_local_backend_use(self, mocked_main, mocked_cleanup, mocked_os_exit, mocked_atexit_register):
        from agentdecompile_cli.cli import cli_entry_point

        with patch("agentdecompile_cli.cli._local_backend_instance", object()):
            cli_entry_point()

        mocked_atexit_register.assert_called_once_with(mocked_cleanup)
        mocked_cleanup.assert_called_once()
        mocked_os_exit.assert_called_once_with(0)
        mocked_main.assert_called_once()


class TestLocalBackendResponseAdapter:
    def test_text_content_to_response_accepts_plain_text_like_objects(self):
        from agentdecompile_cli.local_backend import _text_content_to_response

        result = _text_content_to_response([types.SimpleNamespace(text='{"success": true, "value": 7}', type="text")])

        assert result["isError"] is False
        assert result["content"] == [{"type": "text", "text": '{"success": true, "value": 7}'}]


class TestSharedRepositoryInference:
    def test_program_path_is_not_repository_name(self):
        from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider

        provider = ProjectToolProvider()

        assert provider._infer_requested_shared_repository_name({"path": "/K1/k1_win_gog_swkotor.exe"}, "/K1/k1_win_gog_swkotor.exe") is None

    def test_explicit_repository_name_wins_over_program_path(self):
        from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider

        provider = ProjectToolProvider()

        assert provider._infer_requested_shared_repository_name({"repositoryname": "Odyssey", "path": "/K1/k1_win_gog_swkotor.exe"}, "/K1/k1_win_gog_swkotor.exe") == "Odyssey"

    def test_single_segment_path_can_still_select_repository(self):
        from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider

        provider = ProjectToolProvider()

        assert provider._infer_requested_shared_repository_name({"path": "Odyssey"}, "Odyssey") == "Odyssey"
