"""Interactive CLI client for AgentDecompile MCP server.

Matches TOOLS_LIST.md tool specifications. Supports all AgentDecompile tool names/parameters.

Usage:
  # Start server (in another terminal)
  mcp-agentdecompile-server -t streamable-http --project-path ./projects /path/to/binary
  # Or docker:
    docker run --rm -it -v /path/to/binary:/binary -v ./projects:/projects agentdecompile:latest \

  # Use CLI
  agentdecompile-cli list binaries
  agentdecompile-cli decompile --binary /myapp main
    agentdecompile-cli search symbols --binary /myapp malloc
    agentdecompile-cli search strings --binary /myapp regex "error|warning"
  agentdecompile-cli xref --binary /myapp 0x401000
  agentdecompile-cli read --binary /myapp 0x1000 -s 64
  agentdecompile-cli memory read --binary /myapp 0x1000 --length 32
  agentdecompile-cli callgraph --binary /myapp main --mode graph
  agentdecompile-cli import /path/to/binary
  agentdecompile-cli list project-files
  agentdecompile-cli analyze --binary /myapp
  agentdecompile-cli checkin --binary /myapp -m "Update labels"
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import multiprocessing
import os
import sys

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import click

from agentdecompile_cli import __version__
from agentdecompile_cli.executor import (
    format_output,
    get_client,
    handle_command_error,
    normalize_backend_url,
    resolve_backend_url,
    run_async,
)
from ghidrecomp.decompile import decompile
from agentdecompile_cli.registry import (
    ADVERTISED_TOOLS,
    NON_ADVERTISED_TOOL_ALIASES,
    RESOURCE_URI_DEBUG_INFO,
    RESOURCE_URI_PROGRAMS,
    RESOURCE_URI_STATIC_ANALYSIS,
    TOOLS,
    Tool,
    get_tool_params,
    to_snake_case,
    tool_registry,
)

if TYPE_CHECKING:
    from collections.abc import Coroutine
    from types import FunctionType

logger = logging.getLogger(__name__)

THREAD_COUNT = multiprocessing.cpu_count()
_dynamic_commands_registered = False
_format_options_registered = False
_CLI_STATE_DIR = ".agentdecompile"
_CLI_STATE_FILE = "cli_state.json"
_DEFAULT_OUTPUT_FORMAT = "text"


def _configure_runtime_logging(verbose: bool) -> None:
    """Set log level and HTTP log verbosity from --verbose; stderr only, no file logging."""
    logger.debug("diag.enter %s", "cli.py:_configure_runtime_logging")
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            stream=sys.stderr,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
    else:
        root_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)

    if verbose:
        logging.getLogger("httpx").setLevel(logging.INFO)
        logging.getLogger("httpcore").setLevel(logging.INFO)
    else:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


# Tools that have dedicated Click subcommands (e.g. decompile, callgraph, xref).
# They are still registered as dynamic tools for tool-seq, but we hide them from
# top-level "agentdecompile-cli --help" to avoid duplicate/alias noise; their
# behavior is exposed via the curated commands instead.
_TOOLS_WITH_CURATED_COMMANDS: frozenset[Tool] = frozenset(
    {
        Tool.ANALYZE_DATA_FLOW,
        Tool.ANALYZE_PROGRAM,
        Tool.ANALYZE_VTABLES,
        Tool.CHANGE_PROCESSOR,
        Tool.CHECKIN_PROGRAM,
        Tool.GET_CALL_GRAPH,
        Tool.GET_CURRENT_ADDRESS,
        Tool.GET_CURRENT_FUNCTION,
        Tool.GET_DATA,
        Tool.GET_FUNCTIONS,
        Tool.GET_REFERENCES,
        Tool.INSPECT_MEMORY,
        Tool.LIST_FUNCTIONS,
        Tool.LIST_PROJECT_FILES,
        Tool.MATCH_FUNCTION,
        Tool.SEARCH_CONSTANTS,
        Tool.SVR_ADMIN,
        Tool.SYNC_PROJECT,
    },
)


def _get_opts(ctx: click.Context) -> dict[str, Any]:
    """Global options from context (set by main group)."""
    logger.debug("diag.enter %s", "cli.py:_get_opts")
    if ctx.obj and isinstance(ctx.obj, dict):
        return ctx.obj
    # Subcommands get their own context; use root so main's opts are available
    root = getattr(ctx, "find_root", None)
    if root is not None:
        try:
            root_ctx = root()
            if root_ctx.obj and isinstance(root_ctx.obj, dict):
                return root_ctx.obj
        except Exception:
            pass
    current = ctx.parent
    while current is not None:
        if current.obj and isinstance(current.obj, dict):
            return current.obj
        current = current.parent
    return {}


def _client(ctx: click.Context) -> Any:
    """Create an MCP HTTP client connected to the backend.

    Reads server host/port/url from CLI context options and creates
    an AgentDecompileMcpClient connected to the specified backend.

    Prefers explicit --server-url over --host/--port.

    Returns:
        AgentDecompileMcpClient: Configured MCP client ready to call tools.
    """
    logger.debug("diag.enter %s", "cli.py:_client")
    opts = _get_opts(ctx)
    url = resolve_backend_url(
        opts.get("server_url"),
        opts.get("host"),
        opts.get("port"),
    )
    extra_headers = dict(_shared_request_headers(ctx) or {})
    # Send persisted session id so second invocation reuses same server session (two-command persistence)
    state = _load_cli_state()
    scope = _cache_scope_key(ctx)
    backends = state.get("backends") if isinstance(state, dict) else None
    if isinstance(backends, dict):
        entry = backends.get(scope)
        if isinstance(entry, dict):
            sid = entry.get("session_id")
            if isinstance(sid, str) and sid.strip():
                extra_headers["Mcp-Session-Id"] = sid.strip()
    cookie_file = _cookie_file_path(ctx)
    if url:
        return get_client(url=url, extra_headers=extra_headers, cookie_file=cookie_file)
    return get_client(
        host=opts.get("host", "127.0.0.1"),
        port=opts.get("port", 8080),
        extra_headers=extra_headers,
        cookie_file=cookie_file,
    )


def _fmt(ctx: click.Context) -> str:
    """Get the output format setting from CLI context options.

    Returns configured format (json, text, yaml, etc.) or default.
    """
    logger.debug("diag.enter %s", "cli.py:_fmt")
    return _get_opts(ctx).get("format", _DEFAULT_OUTPUT_FORMAT)


def _cookie_file_path(ctx: click.Context) -> Path | None:
    """Get the path to the cookie file from CLI context options."""
    logger.debug("diag.enter %s", "cli.py:_cookie_file_path")
    opts = _get_opts(ctx)
    return opts.get("cookie_file")


def _extract_text(result: Any) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_extract_text")
    contents: list[Any] = getattr(result, "contents", None) or []
    for c in contents:
        text = getattr(c, "text", None)
        if text:
            return text
    return None


def _safe_json_loads(value: Any) -> Any:
    """Best-effort JSON decode for string payloads."""
    logger.debug("diag.enter %s", "cli.py:_safe_json_loads")
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


def _iter_tool_result_dicts(data: Any):
    """Yield root and nested tool-result dictionaries from MCP response payloads."""
    logger.debug("diag.enter %s", "cli.py:_iter_tool_result_dicts")
    if not isinstance(data, dict):
        return

    yield data

    content = data.get("content")
    if not isinstance(content, list):
        return

    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        nested = _safe_json_loads(text)
        if isinstance(nested, dict):
            yield nested


def _parse_json(result: Any) -> dict | list | None:
    logger.debug("diag.enter %s", "cli.py:_parse_json")
    text = _extract_text(result)
    if not text:
        return None
    parsed = _safe_json_loads(text)
    if parsed is None and not isinstance(text, str):
        return text
    return parsed


def _ensure_count_in_project_file_results(data: Any) -> Any:
    """Backfill `count` for list-project-files style payloads when backend omits it."""
    logger.debug("diag.enter %s", "cli.py:_ensure_count_in_project_file_results")
    if not isinstance(data, dict):
        return data

    files = data.get("files")
    if "count" not in data and isinstance(files, list):
        data["count"] = len(files)

    content = data.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            nested = _safe_json_loads(item.get("text"))
            if isinstance(nested, dict):
                nested_files = nested.get("files")
                if "count" not in nested and isinstance(nested_files, list):
                    nested["count"] = len(nested_files)
                    item["text"] = json.dumps(nested)

    return data


def _get_error_result_message(data: Any) -> str | None:
    """If data is a tool error result (success: false, error present), return the error message; else None."""
    logger.debug("diag.enter %s", "cli.py:_get_error_result_message")
    for payload in _iter_tool_result_dicts(data):
        if payload.get("success") is False and "error" in payload:
            return str(payload.get("error", "Tool returned an error"))
    return None


def _markdown_mcp_content_indicates_error(data: dict[str, Any]) -> bool:
    """True when formatted markdown in MCP text content is an error (isError often stays false)."""
    logger.debug("diag.enter %s", "cli.py:_markdown_mcp_content_indicates_error")
    content = data.get("content")
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        if "## Modification conflict" in text:
            return True
        if "## Error" not in text:
            continue
        # response_formatter: ## Error then blockquote line "> **...**"
        if "\n> **" in text or "\n\n> **" in text:
            return True
        stripped = text.lstrip()
        if stripped.startswith("## Error\n") or stripped.startswith("## Error\r\n"):
            return True
    return False


def _tool_seq_step_succeeded(data: Any) -> bool:
    """Whether an MCP tool response should count as success for ``tool-seq`` (matches ``tool`` command heuristics)."""
    logger.debug("diag.enter %s", "cli.py:_tool_seq_step_succeeded")
    if data is None:
        return False
    if not isinstance(data, dict):
        return True
    if data.get("isError") is True:
        return False
    if _get_error_result_message(data) is not None:
        return False
    if _markdown_mcp_content_indicates_error(data):
        return False
    return True


def _is_no_program_loaded_error(data: Any) -> bool:
    logger.debug("diag.enter %s", "cli.py:_is_no_program_loaded_error")
    err = _get_error_result_message(data)
    if err:
        err_l = err.strip().lower()
        if "no program loaded" in err_l or "no active program" in err_l:
            return True

    if isinstance(data, dict):
        content = data.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                text = str(item.get("text", "")).strip().lower()
                if "no program loaded" in text or "no active program" in text or "state:** `no-active-program`" in text:
                    return True

    for payload in _iter_tool_result_dicts(data):
        note = str(payload.get("note", "")).strip().lower()
        if note in {"no program currently loaded", "no project loaded"}:
            return True
        if payload.get("loaded") is False and "no program" in note:
            return True

    return False


def _build_svr_admin_payload(
    args: tuple[str, ...],
    passthrough_args: list[str],
    command: str | None,
    timeout_seconds: int | None,
) -> dict[str, Any]:
    """Build MCP payload for svr-admin while preserving raw argument ordering."""
    logger.debug("diag.enter %s", "cli.py:_build_svr_admin_payload")
    payload: dict[str, Any] = {}
    argv = [*args, *passthrough_args]
    if argv:
        payload["args"] = argv
    if command:
        payload["command"] = command
    if timeout_seconds is not None:
        payload["timeoutSeconds"] = timeout_seconds
    return payload


def _backend_host_for_recovery(ctx: click.Context) -> str:
    logger.debug("diag.enter %s", "cli.py:_backend_host_for_recovery")
    opts: dict[str, Any] = _get_opts(ctx)
    backend_url: str | None = resolve_backend_url(opts.get("server_url"), opts.get("host"), opts.get("port"))
    if backend_url:
        try:
            parsed = urlparse(backend_url)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    return str(opts.get("host", "127.0.0.1"))


def _shared_server_defaults(ctx: click.Context) -> dict[str, Any]:
    logger.debug("diag.enter %s", "cli.py:_shared_server_defaults")
    opts = _get_opts(ctx)

    host = (
        str(opts.get("ghidra_server_host") or opts.get("server_host") or "").strip()
        or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_HOST", "").strip()
        or os.environ.get("AGENT_DECOMPILE_SERVER_HOST", "").strip()
        or os.environ.get("AGENTDECOMPILE_SERVER_HOST", "").strip()
    )
    port_raw = (
        str(opts.get("ghidra_server_port") or opts.get("server_port") or "").strip()
        or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_PORT", "").strip()
        or os.environ.get("AGENT_DECOMPILE_SERVER_PORT", "13100").strip()
        or os.environ.get("AGENTDECOMPILE_SERVER_PORT", "13100").strip()
        or "13100"
    )
    try:
        port = int(port_raw)
    except ValueError:
        port = 13100

    username = (
        str(opts.get("ghidra_server_username") or opts.get("server_username") or "").strip()
        or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_USERNAME", "").strip()
        or os.environ.get("AGENT_DECOMPILE_SERVER_USERNAME", "").strip()
        or os.environ.get("AGENTDECOMPILE_SERVER_USERNAME", "").strip()
    )
    password = (
        str(opts.get("ghidra_server_password") or opts.get("server_password") or "").strip()
        or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_PASSWORD", "").strip()
        or os.environ.get("AGENT_DECOMPILE_SERVER_PASSWORD", "").strip()
        or os.environ.get("AGENTDECOMPILE_SERVER_PASSWORD", "").strip()
    )
    repository = (
        str(opts.get("ghidra_server_repository") or opts.get("server_repository") or "").strip()
        or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
        or os.environ.get("AGENTDECOMPILE_GHIDRA_REPOSITORY", "").strip()
        or os.environ.get("AGENT_DECOMPILE_REPOSITORY", "").strip()
        or os.environ.get("AGENTDECOMPILE_REPOSITORY", "").strip()
    )

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "repository": repository,
    }


def _shared_request_headers(ctx: click.Context) -> dict[str, str]:
    logger.debug("diag.enter %s", "cli.py:_shared_request_headers")
    shared_defaults = _shared_server_defaults(ctx)
    host = str(shared_defaults["host"] or "").strip()
    if not host:
        return {}

    headers: dict[str, str] = {
        "X-Ghidra-Server-Host": host,
        "X-Ghidra-Server-Port": str(shared_defaults["port"]),
    }
    repository = str(shared_defaults["repository"] or "").strip()
    if repository:
        headers["X-Ghidra-Repository"] = repository
        headers["X-Agent-Server-Repository"] = repository
    username = str(shared_defaults["username"] or "").strip()
    password = str(shared_defaults["password"] or "")
    if username:
        headers["X-Agent-Server-Username"] = username
        headers["X-Agent-Server-Password"] = password
    return headers


async def _recover_and_retry_with_program(
    ctx: click.Context,
    client: Any,
    tool_name: str,
    payload: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Auto-recover from 'no program loaded' errors by attempting to open the requested program.

    When a tool call fails with "no program loaded", this function attempts to:
    1. Extract the requested program path from the original payload
    2. Try opening the program via shared Ghidra server (if configured)
    3. Try opening the program directly
    4. Retry the original tool call

    This provides a seamless user experience where users don't need to manually
    open programs before using tools that require them.

    Args:
        ctx: Click context with CLI options
        client: MCP client for tool calls
        tool_name: Name of the tool that failed
        payload: Original tool arguments
        result: Failed tool result (containing "no program loaded" error)

    Returns:
        Either the original failed result, or the successful retried result
    """
    logger.debug("diag.enter %s", "cli.py:_recover_and_retry_with_program")
    if not _is_no_program_loaded_error(result):
        return result

    requested_program = _extract_program_argument(payload)
    if not requested_program:
        return result

    open_attempts = _build_open_attempts(ctx, requested_program)
    last_open_error: Any | None = None

    for open_payload in open_attempts:
        clean_open_payload = {k: v for k, v in open_payload.items() if v is not None}
        opened, open_result = await _try_open_program(ctx, client, clean_open_payload)
        if not opened:
            if open_result is not None:
                last_open_error = open_result
            continue
        if opened:
            retried = await _try_retry_tool_call(client, tool_name, payload)
            if retried and not _is_no_program_loaded_error(retried):
                return retried
            result = retried or result

    if last_open_error is not None:
        return last_open_error

    return result


def _build_open_attempts(ctx: click.Context, requested_program: str) -> list[dict[str, Any]]:
    """Build a list of open attempts for the requested program."""
    logger.debug("diag.enter %s", "cli.py:_build_open_attempts")
    shared_defaults = _shared_server_defaults(ctx)
    shared_host = str(shared_defaults["host"])
    shared_port = int(shared_defaults["port"])
    shared_user = str(shared_defaults["username"])
    shared_pass = str(shared_defaults["password"])
    shared_repo = str(shared_defaults["repository"])

    open_attempts: list[dict[str, Any]] = []
    if shared_host:
        open_attempts.append(
            {
                "serverHost": shared_host,
                "serverPort": shared_port,
                "serverUsername": shared_user or None,
                "serverPassword": shared_pass or None,
                "path": requested_program,
            },
        )
    if shared_repo:
        open_attempts.append(
            {
                "serverHost": shared_host,
                "serverPort": shared_port,
                "serverUsername": shared_user or None,
                "serverPassword": shared_pass or None,
                "path": shared_repo,
            },
        )
    open_attempts.append({"path": requested_program})

    return open_attempts


def _build_shared_open_payload(ctx: click.Context) -> dict[str, Any] | None:
    """Build open (shared) payload from global opts; None if no host."""
    logger.debug("diag.enter %s", "cli.py:_build_shared_open_payload")
    shared_defaults = _shared_server_defaults(ctx)
    shared_host = str(shared_defaults["host"] or "").strip()
    if not shared_host:
        return None
    open_payload: dict[str, Any] = {
        "shared": True,
        "serverHost": shared_host,
        "serverPort": int(shared_defaults["port"]),
        "format": "json",
    }
    if str(shared_defaults["username"] or "").strip():
        open_payload["serverUsername"] = str(shared_defaults["username"])
    if str(shared_defaults["password"] or "").strip():
        open_payload["serverPassword"] = str(shared_defaults["password"])
    if str(shared_defaults["repository"] or "").strip():
        open_payload["path"] = str(shared_defaults["repository"])
        open_payload["repositoryName"] = str(shared_defaults["repository"])
    return open_payload


async def _maybe_bootstrap_shared_listing(ctx: click.Context, client: Any, tool_name: str, payload: dict[str, Any]) -> Any | None:
    logger.debug("diag.enter %s", "cli.py:_maybe_bootstrap_shared_listing")
    if tool_name == "list_project_files":
        if any(key in payload for key in ("path", "folder", "programPath", "program_path", "binary", "binaryName", "binary_name")):
            return None
        open_payload = _build_shared_open_payload(ctx)
        if not open_payload:
            return None
        logger.info(
            "cli_implicit_open_for_tool bootstrap_branch=list_project_files shared_host_configured=True tool=%s",
            tool_name,
        )
        open_result = await client.call_tool(Tool.OPEN.value, open_payload)
        if _get_error_result_message(open_result) or _is_no_program_loaded_error(open_result):
            return open_result
        return None
    if tool_name == "match_function":
        # So standalone migrate-metadata works: open shared project first when credentials present.
        # Skip when talking to a local server so migrate-metadata completes without opening remote.
        opts = _get_opts(ctx)
        server_url = (opts.get("server_url") or opts.get("mcp_server_url") or opts.get("backend_url") or "").strip().lower()
        if server_url and ("127.0.0.1" in server_url or "localhost" in server_url):
            logger.info(
                "cli_implicit_open_for_tool bootstrap_branch=match_function skipped_local_backend_for_match=True shared_host_configured=%s tool=%s",
                _build_shared_open_payload(ctx) is not None,
                tool_name,
            )
            return None
        open_payload = _build_shared_open_payload(ctx)
        if not open_payload:
            return None
        logger.info(
            "cli_implicit_open_for_tool bootstrap_branch=match_function skipped_local_backend_for_match=False shared_host_configured=True tool=%s",
            tool_name,
        )
        open_result = await client.call_tool(Tool.OPEN.value, open_payload)
        if _get_error_result_message(open_result):
            return open_result
        return None  # proceed with match-function call
    # Bootstrap shared project for checkout/checkin/checkout-status when path looks like shared repo path
    if tool_name in ("checkout_program", "checkin_program", "checkout_status"):
        program_path = payload.get("program_path") or payload.get("programPath") or payload.get("path") or ""
        if isinstance(program_path, str) and program_path.strip() and (program_path.startswith("/") or "/" in program_path):
            open_payload = _build_shared_open_payload(ctx)
            if not open_payload:
                return None
            logger.info(
                "cli_implicit_open_for_tool bootstrap_branch=checkout_family shared_host_configured=True tool=%s",
                tool_name,
            )
            open_result = await client.call_tool(Tool.OPEN.value, open_payload)
            if _get_error_result_message(open_result):
                return open_result
        return None
    return None


async def _maybe_preopen_requested_program(
    ctx: click.Context,
    client: Any,
    tool_name: str,
    payload: dict[str, Any],
) -> Any | None:
    logger.debug("diag.enter %s", "cli.py:_maybe_preopen_requested_program")
    if tool_name != "get_current_program":
        return None

    requested_program = _extract_program_argument(payload)
    if not requested_program:
        return None

    last_open_error: Any | None = None
    for open_payload in _build_open_attempts(ctx, requested_program):
        clean_open_payload = {k: v for k, v in open_payload.items() if v is not None}
        opened, open_result = await _try_open_program(ctx, client, clean_open_payload)
        if opened:
            return None
        if open_result is not None:
            last_open_error = open_result

    return last_open_error


async def _try_open_program(ctx: click.Context, client: Any, open_payload: dict[str, Any]) -> tuple[bool, Any | None]:
    """Try to open a program with the given payload."""
    logger.debug("diag.enter %s", "cli.py:_try_open_program")
    try:
        open_result = await client.call_tool(Tool.OPEN.value, {**open_payload, "format": "json"})
        if _get_error_result_message(open_result):
            return False, open_result
    except Exception:
        return False, None

    # Best-effort explicit checkout when shared open connected at repo scope.
    try:
        await client.call_tool("manage_files", {"mode": "checkout", "programPath": open_payload.get("path")})
    except Exception:
        pass

    return True, open_result


async def _try_retry_tool_call(client: Any, tool_name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Try to retry the tool call after opening the program."""
    logger.debug("diag.enter %s", "cli.py:_try_retry_tool_call")
    try:
        return await client.call_tool(tool_name, payload)
    except Exception:
        return None


def _resolve_tool_call_target(tool: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Resolve CLI-invoked tool name to a server-advertised canonical call target.

    Handles tool name normalization and alias forwarding.

    This ensures CLI commands map correctly to the server's advertised tool API,
    even when using legacy or aliased command names.

    Args:
        tool: Original tool name from CLI
        payload: Tool arguments dictionary

    Returns:
        Tuple of (canonical_tool_name, updated_payload) ready for server call
    """
    logger.debug("diag.enter %s", "cli.py:_resolve_tool_call_target")
    call_tool_name = tool
    resolved_tool = tool_registry.resolve_tool_name(tool) if tool_registry.is_valid_tool(tool) else None
    if resolved_tool is not None:
        call_tool_name = resolved_tool

    resolved_payload = dict(payload)

    if call_tool_name in NON_ADVERTISED_TOOL_ALIASES:
        forwarded_tool = NON_ADVERTISED_TOOL_ALIASES[call_tool_name]
        call_tool_name = forwarded_tool

    return call_tool_name, resolved_payload


async def _call(ctx: click.Context, tool: str | Tool, **kwargs: Any) -> None:
    """Call tool on the remote MCP server via HTTP client.

    The CLI is a pure HTTP client — it NEVER executes tools locally.  All tool
    calls are forwarded to the MCP server (which runs with PyGhidra and has
    access to Ghidra APIs).

    Workflow:
    1. Clean payload (remove None values)
    2. Resolve tool name and arguments through registry
    3. Cache explicit program paths for future commands
    4. Make HTTP call to MCP server
    5. Auto-recover from "no program loaded" errors
    6. Format and display results

    Args:
        ctx: Click context with CLI options
        tool: Tool name to call
        **kwargs: Tool arguments (None values are filtered out)
    """
    # Drop None values
    logger.debug("diag.enter %s", "cli.py:_call")
    payload: dict[str, Any] = {k: v for k, v in kwargs.items() if v is not None}

    result: Any = await _call_raw(ctx, tool, payload)

    # data is already a dict from AgentDecompileMcpClient._extract_result()
    err_msg: str | None = _get_error_result_message(result)
    if err_msg is not None:
        click.echo(err_msg, err=True)
        sys.exit(1)

    if tool == "list_project_files":
        result = _ensure_count_in_project_file_results(result)

    click.echo(format_output(result, _fmt(ctx)))


async def _call_raw(
    ctx: click.Context,
    tool: str,
    payload: dict[str, Any],
    client_override: Any | None = None,
) -> Any:
    """Call tool and return raw result for programmatic CLI workflows.

    Similar to _call() but returns the raw result dictionary instead of
    formatting/displaying it. Used by internal CLI workflows that need
    to process results programmatically.

    Args:
        ctx: Click context with CLI options
        tool: Tool name to call
        payload: Tool arguments dictionary
        client_override: Optional pre-configured client (avoids creating new one)

    Returns:
        Raw tool result dictionary from MCP server
    """
    # Default to markdown for human-readable output. Use -f json when you need
    # machine-readable output (shell/json/xml/table modes parse structured data).
    logger.debug("diag.enter %s", "cli.py:_call_raw")
    payload.setdefault("format", "markdown")

    call_tool_name, safe_payload = _resolve_tool_call_target(tool, payload)
    prepared_payload, _ = _prepare_tool_payload_with_program_fallback(ctx, call_tool_name, dict(safe_payload))

    if tool_registry.is_valid_tool(call_tool_name):
        dispatch_display = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(call_tool_name))
    else:
        dispatch_display = call_tool_name
    call_tool_snake = to_snake_case(dispatch_display)

    return await _execute_tool_call(ctx, call_tool_snake, prepared_payload, client_override)


async def _execute_tool_call(
    ctx: click.Context,
    call_tool_name: str,
    payload: dict[str, Any],
    client_override: Any | None = None,
) -> Any:
    """Execute the actual tool call with error handling and recovery."""
    logger.debug("diag.enter %s", "cli.py:_execute_tool_call")
    from agentdecompile_cli.bridge import ClientError, ServerNotRunningError  # noqa: PLC0415

    try:
        if client_override is not None:
            bootstrap = await _maybe_bootstrap_shared_listing(ctx, client_override, call_tool_name, payload)
            if bootstrap is not None:
                return bootstrap
            preopen_error = await _maybe_preopen_requested_program(ctx, client_override, call_tool_name, payload)
            if preopen_error is not None:
                return preopen_error
            first = await client_override.call_tool(call_tool_name, payload)
            result = await _recover_and_retry_with_program(ctx, client_override, call_tool_name, payload, first)
            _persist_session_id(ctx, client_override)
            return result

        client = _client(ctx)
        async with client:
            bootstrap = await _maybe_bootstrap_shared_listing(ctx, client, call_tool_name, payload)
            if bootstrap is not None:
                return bootstrap
            preopen_error = await _maybe_preopen_requested_program(ctx, client, call_tool_name, payload)
            if preopen_error is not None:
                return preopen_error
            first = await client.call_tool(call_tool_name, payload)
            result = await _recover_and_retry_with_program(ctx, client, call_tool_name, payload, first)
            _persist_session_id(ctx, client)
            return result
    except ServerNotRunningError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        if isinstance(exc, ClientError) and "400" in str(exc):
            _clear_persisted_session_id(ctx)
        click.echo(f"Error calling tool '{call_tool_name}': {exc}", err=True)
        sys.exit(1)


async def _migrate_metadata_then_checkin(ctx: click.Context, match_payload: dict[str, Any]) -> None:
    """Run match-function (migrate-metadata) then checkin-program in the same session."""
    logger.debug("diag.enter %s", "cli.py:_migrate_metadata_then_checkin")
    from agentdecompile_cli.bridge import ServerNotRunningError  # noqa: PLC0415

    match_payload = dict(match_payload)
    match_payload.setdefault("format", "markdown")
    call_name, safe_match = _resolve_tool_call_target(Tool.MATCH_FUNCTION.value, match_payload)
    if tool_registry.is_valid_tool(call_name):
        call_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(call_name))
        safe_match = tool_registry.parse_arguments(safe_match, call_name)
    call_name = to_snake_case(call_name)
    checkin_payload: dict[str, Any] = {"comment": "migrate-metadata checkin", "format": "markdown"}
    call_name2, safe_checkin = _resolve_tool_call_target(Tool.CHECKIN_PROGRAM.value, checkin_payload)
    if tool_registry.is_valid_tool(call_name2):
        call_name2 = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(call_name2))
        safe_checkin = tool_registry.parse_arguments(safe_checkin, call_name2)
    call_name2 = to_snake_case(call_name2)
    client = _client(ctx)
    try:
        async with client:
            result1 = await _execute_tool_call(ctx, call_name, safe_match, client_override=client)
            err1 = _get_error_result_message(result1)
            if err1 is not None:
                click.echo(err1, err=True)
                sys.exit(1)
            click.echo(format_output(result1, _fmt(ctx)))
            result2 = await _execute_tool_call(ctx, call_name2, safe_checkin, client_override=client)
            err2 = _get_error_result_message(result2)
            if err2 is not None:
                click.echo(err2, err=True)
                sys.exit(1)
            click.echo(format_output(result2, _fmt(ctx)))
            # Verify: call checkout-status for each target so user sees state
            target_paths = safe_match.get("targetProgramPaths") or safe_match.get("target_program_paths")
            if isinstance(target_paths, str):
                target_paths = [target_paths]
            if isinstance(target_paths, list) and target_paths:
                status_name, status_payload_base = _resolve_tool_call_target(Tool.CHECKOUT_STATUS.value, {"format": "markdown"})
                if tool_registry.is_valid_tool(status_name):
                    status_name = to_snake_case(tool_registry.get_display_name(tool_registry.canonicalize_tool_name(status_name)))
                for tpath in target_paths:
                    if not isinstance(tpath, str) or not tpath.strip():
                        continue
                    status_payload = {**status_payload_base, "programPath": tpath.strip()}
                    status_payload = tool_registry.parse_arguments(status_payload, Tool.CHECKOUT_STATUS.value)
                    try:
                        status_result = await _execute_tool_call(ctx, status_name, status_payload, client_override=client)
                        click.echo(format_output(status_result, _fmt(ctx)))
                    except Exception:
                        pass
    except ServerNotRunningError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _parse_tool_payload(arguments: str) -> dict[str, Any]:
    """Parse CLI JSON argument payload for generic tool commands.

    Handles JSON parsing with error handling and shell quoting cleanup.
    PowerShell may wrap JSON arguments in quotes, so this function strips
    matching outer quotes before parsing.

    Args:
        arguments: JSON string from CLI arguments

    Returns:
        Parsed JSON object as dictionary

    Raises:
        SystemExit: If JSON is invalid or not an object
    """
    # Strip whitespace and leading/trailing quotes (PowerShell may pass them)
    logger.debug("diag.enter %s", "cli.py:_parse_tool_payload")
    arguments = arguments.strip()
    if arguments and arguments[0] in ('"', "'") and arguments[-1] == arguments[0]:
        arguments = arguments[1:-1]

    try:
        payload = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON arguments: {e}", err=True)
        sys.exit(1)

    if not isinstance(payload, dict):
        click.echo("Arguments must be a JSON object.", err=True)
        sys.exit(1)
    return payload


def _cli_state_path() -> Path:
    logger.debug("diag.enter %s", "cli.py:_cli_state_path")
    return Path.cwd() / _CLI_STATE_DIR / _CLI_STATE_FILE


def _cookie_file_path(ctx: click.Context) -> Path:
    """Path to persistent cookie file for MCP session (per backend scope)."""
    logger.debug("diag.enter %s", "cli.py:_cookie_file_path")
    scope = _cache_scope_key(ctx)
    safe = hashlib.md5(scope.encode()).hexdigest()[:24]
    return Path.cwd() / _CLI_STATE_DIR / f"cookies_{safe}.json"


def _load_cli_state() -> dict[str, Any]:
    logger.debug("diag.enter %s", "cli.py:_load_cli_state")
    state_path = _cli_state_path()
    if not state_path.exists():
        return {}
    try:
        with state_path.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cli_state(data: dict[str, Any]) -> None:
    logger.debug("diag.enter %s", "cli.py:_save_cli_state")
    try:
        state_path = _cli_state_path()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with state_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        return


def _cache_scope_key(ctx: click.Context) -> str:
    logger.debug("diag.enter %s", "cli.py:_cache_scope_key")
    opts = _get_opts(ctx)
    url = resolve_backend_url(
        opts.get("server_url"),
        opts.get("host"),
        opts.get("port"),
    )
    if url:
        try:
            return normalize_backend_url(url)
        except Exception:
            return url.rstrip("/")
    return f"http://{opts.get('host', '127.0.0.1')}:{opts.get('port', 8080)}"


def _extract_program_argument(payload: dict[str, Any]) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_extract_program_argument")
    for key in ("programPath", "binaryName", "program_path", "binary_name", "program", "binary"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _store_cli_default_program_path(ctx: click.Context, value: str | None) -> None:
    """Persist default program path on root ctx.obj for tool / tool-seq / dynamic dispatch."""
    logger.debug("diag.enter %s", "cli.py:_store_cli_default_program_path")
    if not value or not str(value).strip():
        return
    root = ctx.find_root()
    if root.obj is None:
        root.obj = {}
    root.obj["cli_default_program_path"] = str(value).strip()


def _store_cli_default_binary_name(ctx: click.Context, value: str | None) -> None:
    if not value or not str(value).strip():
        return
    root = ctx.find_root()
    if root.obj is None:
        root.obj = {}
    root.obj["cli_default_binary_name"] = str(value).strip()


def _cli_program_path_option_callback(
    ctx: click.Context,
    _param: click.Parameter,
    value: str | None,
) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_cli_program_path_option_callback")
    _store_cli_default_program_path(ctx, value)
    return value


def _cli_binary_name_option_callback(
    ctx: click.Context,
    _param: click.Parameter,
    value: str | None,
) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_cli_binary_name_option_callback")
    _store_cli_default_binary_name(ctx, value)
    return value


def _resolve_cli_default_program_for_param(ctx: click.Context, program_key: str) -> str | None:
    """CLI flags/env default for programPath or binaryName before cached-session fallback."""
    logger.debug("diag.enter %s", "cli.py:_resolve_cli_default_program_for_param")
    opts = _get_opts(ctx)
    path = opts.get("cli_default_program_path")
    binary = opts.get("cli_default_binary_name")
    if isinstance(path, str) and path.strip():
        path = path.strip()
    else:
        path = None
    if isinstance(binary, str) and binary.strip():
        binary = binary.strip()
    else:
        binary = None

    if not path:
        for env_key in (
            "AGENTDECOMPILE_PROGRAM_PATH",
            "AGENT_DECOMPILE_PROGRAM_PATH",
            "AGENTDECOMPILE_PROGRAM",
            "AGENT_DECOMPILE_PROGRAM",
        ):
            raw = os.environ.get(env_key)
            if isinstance(raw, str) and raw.strip():
                path = raw.strip()
                break

    if not binary:
        for env_key in ("AGENTDECOMPILE_BINARY_NAME", "AGENT_DECOMPILE_BINARY_NAME"):
            raw = os.environ.get(env_key)
            if isinstance(raw, str) and raw.strip():
                binary = raw.strip()
                break

    if program_key == "programPath":
        return path or binary
    if program_key == "binaryName":
        return binary or path
    return None


def _set_cached_program(ctx: click.Context, program: str) -> None:
    logger.debug("diag.enter %s", "cli.py:_set_cached_program")
    if not program.strip():
        return
    state = _load_cli_state()
    backends = state.get("backends")
    if not isinstance(backends, dict):
        backends = {}
    scope = _cache_scope_key(ctx)
    entry = backends.get(scope)
    if not isinstance(entry, dict):
        entry = {}
    entry["last_program"] = program.strip()
    backends[scope] = entry
    state["backends"] = backends
    _save_cli_state(state)


def _persist_session_id(ctx: click.Context, client: Any) -> None:
    """Persist MCP session id from client so next CLI invocation reuses the same server session."""
    logger.debug("diag.enter %s", "cli.py:_persist_session_id")
    get_sid = getattr(client, "get_session_id", None)
    if not callable(get_sid):
        return
    sid = get_sid()
    if not isinstance(sid, str) or not sid.strip():
        return
    state = _load_cli_state()
    backends = state.get("backends")
    if not isinstance(backends, dict):
        backends = {}
    scope = _cache_scope_key(ctx)
    entry = backends.get(scope)
    if not isinstance(entry, dict):
        entry = {}
    entry["session_id"] = sid.strip()
    backends[scope] = entry
    state["backends"] = backends
    _save_cli_state(state)


def _clear_persisted_session_id(ctx: click.Context) -> None:
    """Clear persisted MCP session id for this backend scope (e.g. after 400 so next run does not send stale id)."""
    logger.debug("diag.enter %s", "cli.py:_clear_persisted_session_id")
    state = _load_cli_state()
    backends = state.get("backends")
    if not isinstance(backends, dict):
        return
    scope = _cache_scope_key(ctx)
    entry = backends.get(scope)
    if not isinstance(entry, dict) or "session_id" not in entry:
        return
    entry = dict(entry)
    entry.pop("session_id", None)
    backends[scope] = entry
    state["backends"] = backends
    _save_cli_state(state)


def _get_cached_program(ctx: click.Context) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_get_cached_program")
    state = _load_cli_state()
    backends = state.get("backends")
    if not isinstance(backends, dict):
        return None
    scope = _cache_scope_key(ctx)
    entry = backends.get(scope)
    if not isinstance(entry, dict):
        return None
    value = entry.get("last_program")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _tool_program_param(tool_name: str) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_tool_program_param")
    if not tool_registry.is_valid_tool(tool_name):
        return None
    resolved_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(tool_name))
    params = tool_registry.get_tool_params(resolved_name)
    if "programPath" in params:
        return "programPath"
    if "binaryName" in params:
        return "binaryName"
    return None


def _prepare_tool_payload_with_program_fallback(
    ctx: click.Context,
    tool_name: str,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    logger.debug("diag.enter %s", "cli.py:_prepare_tool_payload_with_program_fallback")
    normalized_payload: dict[str, Any] = {k: v for k, v in payload.items() if v is not None}
    resolved_name = tool_name
    if tool_registry.is_valid_tool(tool_name):
        resolved_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(tool_name))
        normalized_payload = tool_registry.parse_arguments(normalized_payload, resolved_name)

    explicit_program = _extract_program_argument(normalized_payload)
    if explicit_program is not None:
        _set_cached_program(ctx, explicit_program)
        return normalized_payload, None

    program_key = _tool_program_param(resolved_name)
    if program_key is None:
        return normalized_payload, None

    cli_default = _resolve_cli_default_program_for_param(ctx, program_key)
    if cli_default:
        normalized_payload[program_key] = cli_default
        _set_cached_program(ctx, cli_default)
        return normalized_payload, cli_default

    cached_program = _get_cached_program(ctx)
    if cached_program is not None:
        normalized_payload[program_key] = cached_program
    return normalized_payload, cached_program


def _inject_inferred_program(data: Any, inferred_program: str | None) -> Any:
    logger.debug("diag.enter %s", "cli.py:_inject_inferred_program")
    if inferred_program is None:
        return data
    if isinstance(data, dict):
        if any(k in data for k in ("program", "programPath", "binaryName")):
            return data
        return {"program": inferred_program, **data}
    return {"program": inferred_program, "result": data}


def _validate_known_tool(name: str) -> None:
    logger.debug("diag.enter %s", "cli.py:_validate_known_tool")
    if tool_registry.is_valid_tool(name):
        return
    click.echo(
        f"Note: '{name}' is not in the known tool list (agentdecompile-cli tool --list-tools). Proceeding anyway.",
        err=True,
    )


def _run_async(coro: Coroutine[Any, Any, None]) -> None:
    """Run an async coroutine in a new event loop and handle errors.

    Wrapper that:
    1. Runs the coroutine via asyncio.run()
    2. Catches cancellation and general exceptions
    3. Formats errors for CLI output
    4. Exits with code 1 on error

    Used by most CLI commands that need to call async MCP tools.
    """
    logger.debug("diag.enter %s", "cli.py:_run_async")
    try:
        run_async(coro)
    except (asyncio.CancelledError, Exception) as e:
        handle_command_error(e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Global options and main group
# ---------------------------------------------------------------------------


def _add_global_options(cmd: click.Command | FunctionType) -> click.Command | FunctionType:
    logger.debug("diag.enter %s", "cli.py:_add_global_options")
    cmd = click.option("--host", default="127.0.0.1", help="Server host")(cmd)
    cmd = click.option("--port", type=int, default=8080, help="Server port")(cmd)
    cmd = click.option(
        "--server-url",
        "--mcp-server-url",
        help="Full server URL (overrides --host/--port)",
    )(cmd)
    cmd = click.option(
        "-f",
        "--format",
        type=str,
        default=_DEFAULT_OUTPUT_FORMAT,
        help=("Output format (default: text). Use -f/--format json only when you strictly need machine-readable output; text/markdown is recommended."),
    )(cmd)
    return cmd


def _set_output_format_option(
    ctx: click.Context,
    _param: click.Parameter,
    value: str | None,
) -> str | None:
    logger.debug("diag.enter %s", "cli.py:_set_output_format_option")
    if value is None:
        return value
    root_ctx = ctx.find_root()
    if root_ctx.obj is None:
        root_ctx.obj = {}
    root_ctx.obj["format"] = value
    return value


def _command_has_output_format_option(command: click.Command) -> bool:
    logger.debug("diag.enter %s", "cli.py:_command_has_output_format_option")
    for param in command.params:
        if isinstance(param, click.Option):
            opts = set(param.opts + param.secondary_opts)
            if "--format" in opts or "-f" in opts:
                return True
    return False


def _register_output_format_option_on_all_commands(root: click.Command) -> None:
    logger.debug("diag.enter %s", "cli.py:_register_output_format_option_on_all_commands")
    global _format_options_registered
    if _format_options_registered:
        return

    visited: set[int] = set()

    def _walk(command: click.Command) -> None:
        command_id = id(command)
        if command_id in visited:
            return
        visited.add(command_id)

        if not _command_has_output_format_option(command):
            command.params.append(
                click.Option(
                    ["-f", "--format"],
                    type=str,
                    default=None,
                    expose_value=False,
                    callback=_set_output_format_option,
                    help=("Output format (default: text). Use -f/--format json only when you strictly need machine-readable output; text/markdown is recommended."),
                ),
            )

        if isinstance(command, click.Group):
            for subcommand in command.commands.values():
                _walk(subcommand)

    _walk(root)
    _format_options_registered = True


def _create_dynamic_commands(cli_group: click.Group) -> None:
    """Dynamically create CLI commands from the tool registry."""
    logger.debug("diag.enter %s", "cli.py:_create_dynamic_commands")
    advertised_set = set(ADVERTISED_TOOLS)
    for tool_name in TOOLS:
        tool_params = _supported_cli_tool_params(tool_name)
        snake_params = [to_snake_case(param) for param in tool_params]
        params_help = ", ".join(f"--{param}" for param in snake_params) if snake_params else "(none)"
        command_help = f"Call `{tool_name}`. Parameters: {params_help}"

        # Create parameter options for this tool
        def tool_command(_tool_name: str = tool_name, **kwargs: Any) -> None:
            """Auto-generated MCP tool command."""
            ctx = click.get_current_context()
            # Remove None values and format arguments
            args = {k: v for k, v in kwargs.items() if v is not None}
            # For open, merge global Ghidra server options so --ghidra-server-username etc. are sent
            if _tool_name == Tool.OPEN.value:
                opts = _get_opts(ctx)
                if not args.get("serverUsername") and not args.get("server_username"):
                    v = opts.get("ghidra_server_username") or opts.get("server_username")
                    if v:
                        args["serverUsername"] = str(v).strip()
                if not args.get("serverPassword") and not args.get("server_password"):
                    v = opts.get("ghidra_server_password") or opts.get("server_password")
                    if v:
                        args["serverPassword"] = str(v).strip()
                if not args.get("serverHost") and not args.get("server_host"):
                    v = opts.get("ghidra_server_host") or opts.get("server_host")
                    if v:
                        args["serverHost"] = str(v).strip()
                if args.get("serverPort") is None and args.get("server_port") is None:
                    v = opts.get("ghidra_server_port") or opts.get("server_port")
                    if v is not None:
                        args["serverPort"] = int(v)
                if not args.get("repositoryName") and not args.get("repository_name"):
                    v = opts.get("ghidra_server_repository") or opts.get("server_repository")
                    if v:
                        args["repositoryName"] = str(v).strip()
                    if v and not args.get("path"):
                        args["path"] = str(v).strip()

            # Call the tool using the unified registry
            async def _run():
                try:
                    result = await _call(ctx, _tool_name, **args)
                    if result:
                        click.echo(result)
                except Exception as e:
                    handle_command_error(e)

            _run_async(_run())

        # Add options to the command function
        for param in tool_params:
            snake_param = to_snake_case(param)
            option_name = f"--{snake_param}"

            # Determine option type based on parameter name
            if "path" in param.lower() or "file" in param.lower():
                option_type = click.Path(exists=False)
            elif "limit" in param.lower() or "max" in param.lower() or param in ["timeout", "maxRunTime"]:
                option_type = int
            elif param in ["includeSignature", "includeRefs", "caseSensitive", "setAsPrimary"]:
                option_type = bool
            else:
                option_type = str

            # Check if parameter is required (programPath resolves from session / env when omitted)
            required = param in ["addressOrSymbol", "action", "mode"]

            # Add the option decorator
            tool_command = click.option(
                option_name,
                snake_param,
                type=option_type,
                required=required,
                help=f"{snake_param} parameter",
            )(tool_command)

        command_name = tool_name
        hidden_from_help = tool_name in {t.value for t in _TOOLS_WITH_CURATED_COMMANDS} or tool_name not in advertised_set

        # Add global options and register the command
        tool_command = _add_global_options(tool_command)

        # Register canonical kebab-case command unless an explicit command already exists.
        if command_name not in cli_group.commands:
            cli_group.command(command_name, help=command_help, hidden=hidden_from_help)(tool_command)


def _tool_aliases_for(canonical_tool: str) -> list[str]:
    logger.debug("diag.enter %s", "cli.py:_tool_aliases_for")
    aliases: list[str] = [alias for alias, target in NON_ADVERTISED_TOOL_ALIASES.items() if target == canonical_tool]
    snake_alias = to_snake_case(canonical_tool)
    if snake_alias != canonical_tool:
        aliases.append(snake_alias)
    return sorted(set(aliases))


_CLI_UNSUPPORTED_RESULT_LIMIT_PARAMS: frozenset[str] = frozenset({"limit", "maxresults", "maxcount", "topn"})


def _is_cli_result_limit_param(param: str) -> bool:
    logger.debug("diag.enter %s", "cli.py:_is_cli_result_limit_param")
    normalized = param.replace("_", "").replace("-", "").lower()
    return normalized in _CLI_UNSUPPORTED_RESULT_LIMIT_PARAMS


def _supported_cli_tool_params(tool_name: str) -> list[str]:
    logger.debug("diag.enter %s", "cli.py:_supported_cli_tool_params")
    params = get_tool_params(tool_name)
    return [param for param in params if not _is_cli_result_limit_param(param)]


def _tool_signature(tool_name: str) -> str:
    logger.debug("diag.enter %s", "cli.py:_tool_signature")
    params = _supported_cli_tool_params(tool_name)
    params = [to_snake_case(param) for param in params]
    return " ".join(f"--{param}" for param in params) if params else "(none)"


def _ensure_dynamic_commands_registered() -> None:
    logger.debug("diag.enter %s", "cli.py:_ensure_dynamic_commands_registered")
    global _dynamic_commands_registered
    if _dynamic_commands_registered:
        return
    _create_dynamic_commands(main)
    _dynamic_commands_registered = True


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", type=int, default=8080, help="Server port")
@click.option("--server-url", help="Full server URL (overrides --host/--port) (equivalent to AGENT_DECOMPILE_MCP_SERVER_URL)")
@click.option("--mcp-server-url", help="Alias of --server-url for proxy/backend style configuration")
@click.option("--backend-url", help="Alias of --server-url for proxy/backend style configuration")
@click.option("--mcp-backend-url", help="Alias of --server-url for proxy/backend style configuration")
@click.option(
    "--ghidra-server-host",
    "--server-host",
    "ghidra_server_host",
    help="Default shared Ghidra server host (prefer AGENT_DECOMPILE_GHIDRA_SERVER_HOST in environment)",
)
@click.option(
    "--ghidra-server-port",
    "--server-port",
    "ghidra_server_port",
    type=int,
    help="Default shared Ghidra server port (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PORT in environment)",
)
@click.option(
    "--ghidra-server-username",
    "--server-username",
    "ghidra_server_username",
    help="Default shared Ghidra server username (prefer AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME in environment)",
)
@click.option(
    "--ghidra-server-password",
    "--server-password",
    "ghidra_server_password",
    help="Default shared Ghidra server password (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD in environment)",
)
@click.option(
    "--ghidra-server-repository",
    "--server-repository",
    "ghidra_server_repository",
    help="Default shared Ghidra repository (prefer AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY in environment)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logs (including HTTP request diagnostics)")
@click.option(
    "--program-path",
    "--programpath",
    "--programPath",
    "--program",
    "-b",
    "--binary",
    "cli_default_program_path",
    default=None,
    help=("Default programPath for tools when JSON or flags omit it (before `tool` / `tool-seq` or any subcommand). Environment: AGENTDECOMPILE_PROGRAM_PATH, AGENT_DECOMPILE_PROGRAM_PATH, AGENTDECOMPILE_PROGRAM."),
)
@click.option(
    "--binary-name",
    "--binaryname",
    "--binaryName",
    "cli_default_binary_name",
    default=None,
    help="Default binaryName when the tool expects it and arguments omit it. Environment: AGENTDECOMPILE_BINARY_NAME.",
)
@click.option(
    "-f",
    "--format",
    type=str,
    default=_DEFAULT_OUTPUT_FORMAT,
    help=("Output format (default: text). Use -f/--format json only when you strictly need machine-readable output; text/markdown is recommended."),
)
@click.version_option(None, "--version", "-V", package_name="agentdecompile")
@click.pass_context
def main(
    ctx: click.Context,
    host: str,
    port: int,
    server_url: str | None,
    mcp_server_url: str | None,
    backend_url: str | None,
    mcp_backend_url: str | None,
    ghidra_server_host: str | None,
    ghidra_server_port: int | None,
    ghidra_server_username: str | None,
    ghidra_server_password: str | None,
    ghidra_server_repository: str | None,
    verbose: bool,
    cli_default_program_path: str | None,
    cli_default_binary_name: str | None,
    format: str,
) -> None:
    """AgentDecompile CLI – all tools from TOOLS_LIST.md (30+ tools)."""
    logger.debug("diag.enter %s", "cli.py:main")
    _configure_runtime_logging(verbose)

    existing_obj = ctx.obj if isinstance(ctx.obj, dict) else {}
    effective_server_url = server_url or mcp_server_url or backend_url or mcp_backend_url
    pp = (cli_default_program_path or "").strip() or None
    bn = (cli_default_binary_name or "").strip() or None
    ctx.obj = {
        "host": host,
        "port": port,
        "server_url": effective_server_url,
        "ghidra_server_host": ghidra_server_host,
        "ghidra_server_port": ghidra_server_port,
        "ghidra_server_username": ghidra_server_username,
        "ghidra_server_password": ghidra_server_password,
        "ghidra_server_repository": ghidra_server_repository,
        "verbose": verbose,
        "cli_default_program_path": pp or existing_obj.get("cli_default_program_path"),
        "cli_default_binary_name": bn or existing_obj.get("cli_default_binary_name"),
        "format": existing_obj.get("format", format),
    }

    # Ensure command surface includes canonical + snake_case tool commands.
    _ensure_dynamic_commands_registered()
    _register_output_format_option_on_all_commands(main)


@click.version_option(__version__, "--version", "-V")
@main.command(
    "ghidrecomp",
    help="ghidrecomp - A Command Line Ghidra Decompiler",
)
@click.argument("bin", type=click.Path())
@click.option("--cppexport", is_flag=True, help="Use Ghidras CppExporter to decompile to single file")
@click.option("--filter", "filters", multiple=True, help="Regex match for function name")
@click.option(
    "--project-path",
    default="ghidra_projects",
    help="Path to base ghidra projects ",
)
@click.option("--gzf", is_flag=True, help="Export gzf of analyzed project")
@click.option("--gzf-path", default="gzfs", help="Path to store gzf of analyzed project")
@click.option(
    "--gdt",
    "gdts",
    multiple=True,
    help="Additional GDT to apply",
)
@click.option(
    "-o",
    "--output-path",
    default="ghidrecomps",
    help="Location for all decompilations",
)
@click.option("--skip-cache", is_flag=True, help="Skip cached and genearate new decomp and callgraphs.")
@click.option("--sym-file-path", help="Specify single pdb symbol file for bin")
@click.option(
    "-s",
    "--symbols-path",
    default="symbols",
    help="Path for local symbols directory",
)
@click.option("--skip-symbols", is_flag=True, help="Do not apply symbols")
@click.option(
    "-t",
    "--thread-count",
    type=int,
    default=THREAD_COUNT,
    help="Threads to use for processing. Defaults to cpu count",
)
@click.option("--va", is_flag=True, help="Enable verbose analysis")
@click.option("--fa", is_flag=True, help="Force new analysis (even if already analyzed)")
@click.option(
    "--max-ram-percent",
    default=50.0,
    type=float,
    help="Set JVM Max Ram %% of host RAM",
)
@click.option("--print-flags", is_flag=True, help="Print JVM flags at start")
@click.option("--callgraphs", is_flag=True, help="Generate callgraph markdown")
@click.option("--callgraph-filter", default=".", help="Only generate callgraphs for functions matching filter")
@click.option(
    "--mdd",
    "--max-display-depth",
    "max_display_depth",
    type=int,
    default=None,
    help="Max Depth for graph generation",
)
@click.option("--max-time-cg-gen", type=int, default=5, help="Max time in seconds to wait for callgraph gen.")
@click.option(
    "--cg-direction",
    type=click.Choice(["calling", "called", "both"]),
    default="calling",
    help="Direction for callgraph.",
)
@click.option(
    "--no-call-refs",
    is_flag=True,
    help="Do not include non-call references in callgraph",
)
@click.option(
    "--condense-threshold",
    type=int,
    default=50,
    help="Number of edges to trigger graph condensation.",
)
@click.option(
    "--top-layers",
    type=int,
    default=None,
    help="Number of top layers to show in condensed graph.",
)
@click.option(
    "--bottom-layers",
    type=int,
    default=None,
    help="Number of bottom layers to show in condensed graph.",
)
@click.option("--bsim", is_flag=True, help="Generate BSim function feature vector signatures")
@click.option("--bsim-sig-path", default="bsim-xmls", help="Path to store BSim xml sigs")
@click.option("--bsim-template", default="medium_nosize", help="BSim database template")
@click.option("--bsim-cat", "bsim_cat", multiple=True, help="BSim category. (type:value)")
@click.option("--sast", is_flag=True, help="Run SAST scanning on decompiled code with semgrep and CodeQL")
@click.option("--semgrep-rules", "semgrep_rules", multiple=True, help="Path to local semgrep rule file or directory")
@click.option("--codeql-rules", default=None, help="Comma-separated paths to local CodeQL query directories")
def ghidrecomp_command(
    bin: str,
    cppexport: bool,
    filters: tuple[str, ...],
    project_path: str,
    gzf: bool,
    gzf_path: str,
    gdts: tuple[str, ...],
    output_path: str,
    skip_cache: bool,
    sym_file_path: str | None,
    symbols_path: str,
    skip_symbols: bool,
    thread_count: int,
    va: bool,
    fa: bool,
    max_ram_percent: float,
    print_flags: bool,
    callgraphs: bool,
    callgraph_filter: str,
    max_display_depth: int | None,
    max_time_cg_gen: int,
    cg_direction: str,
    no_call_refs: bool,
    condense_threshold: int,
    top_layers: int | None,
    bottom_layers: int | None,
    bsim: bool,
    bsim_sig_path: str,
    bsim_template: str,
    bsim_cat: tuple[str, ...],
    sast: bool,
    semgrep_rules: tuple[str, ...],
    codeql_rules: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:ghidrecomp_command")
    args: Any = SimpleNamespace(
        bin=bin,
        cppexport=cppexport,
        filters=list(filters),
        project_path=project_path,
        gzf=gzf,
        gzf_path=gzf_path,
        gdt=list(gdts),
        output_path=output_path,
        skip_cache=skip_cache,
        sym_file_path=sym_file_path,
        symbols_path=symbols_path,
        skip_symbols=skip_symbols,
        thread_count=thread_count,
        va=va,
        fa=fa,
        max_ram_percent=max_ram_percent,
        print_flags=print_flags,
        callgraphs=callgraphs,
        callgraph_filter=callgraph_filter,
        max_display_depth=max_display_depth,
        max_time_cg_gen=max_time_cg_gen,
        cg_direction=cg_direction,
        no_call_refs=no_call_refs,
        condense_threshold=condense_threshold,
        top_layers=top_layers,
        bottom_layers=bottom_layers,
        bsim=bsim,
        bsim_sig_path=bsim_sig_path,
        bsim_template=bsim_template,
        bsim_cat=list(bsim_cat) if bsim_cat else None,
        sast=sast,
        semgrep_rules=list(semgrep_rules) if semgrep_rules else None,
        codeql_rules=codeql_rules,
    )
    decompile(args)


# ---------------------------------------------------------------------------
# List (binaries, imports, exports, project-files, open-programs)
# ---------------------------------------------------------------------------


@main.group(
    "list",
    help="List programs, imports, exports, project files, open programs",
)
def list_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:list_grp")
    pass


@list_grp.command(
    "binaries",
    help="List all programs in the project (legacy alias ghidra://programs)",
)
@click.option(
    "-f",
    "--format",
    "local_format",
    type=str,
    default=None,
    help=("Output format override (default: inherited text output). Use -f/--format json only when you strictly need machine-readable output; text/markdown is recommended."),
)
@click.pass_context
def list_binaries(ctx: click.Context, local_format: str | None) -> None:
    async def _run():
        client = _client(ctx)
        async with client:
            result = await client.read_resource("ghidra://programs")
        contents: list[Any] = getattr(result, "contents", None) or []
        programs: list[dict[str, Any]] = []
        for c in contents:
            text = getattr(c, "text", None)
            if text:
                data = json.loads(text) if isinstance(text, str) else text
                progs = data if isinstance(data, list) else (data.get("programs") if isinstance(data, dict) else [])
                if isinstance(progs, list):
                    programs = progs
                    break
        if programs:
            names = [p.get("programPath", p.get("name", p)) if isinstance(p, dict) else p for p in programs]
            click.echo(format_output(names, local_format or _fmt(ctx)))
        else:
            click.echo("No programs in project.")

    logger.debug("diag.enter %s", "cli.py:list_binaries")
    _run_async(_run())


@list_grp.command("imports", help="List imports (list-imports)")
@click.option(
    "-b",
    "--binary",
    "program_path",
    help="Program path in project",
)
@click.option("--start-index", type=int, default=0)
@click.option("--library-filter", help="Filter by library name")
@click.option("--no-group-by-library", is_flag=True, help="Do not group by library")
@click.pass_context
def list_imports(
    ctx: click.Context,
    program_path: str | None,
    start_index: int,
    library_filter: str | None,
    no_group_by_library: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:list_imports")
    payload: dict[str, Any] = {
        "startIndex": start_index,
    }
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if library_filter is not None:
        payload["libraryFilter"] = library_filter
    if no_group_by_library:
        payload["groupByLibrary"] = False
    _run_async(_call(ctx, Tool.LIST_IMPORTS.value, **payload))


@list_grp.command("exports", help="List exports (list-exports)")
@click.option("-b", "--binary", "program_path")
@click.option("--start-index", type=int, default=0)
@click.pass_context
def list_exports(
    ctx: click.Context,
    program_path: str | None,
    start_index: int,
) -> None:
    logger.debug("diag.enter %s", "cli.py:list_exports")
    kwargs: dict[str, Any] = {"startIndex": start_index}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, "list-exports", **kwargs))


@list_grp.command(
    "project-files",
    help="List project file/folder hierarchy (list-project-files)",
)
@click.option("-b", "--binary", "program_path")
@click.pass_context
def list_project_files(ctx: click.Context, program_path: str | None) -> None:
    logger.debug("diag.enter %s", "cli.py:list_project_files")
    payload: dict[str, Any] = {}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    _run_async(_call(ctx, Tool.LIST_PROJECT_FILES.value, **payload))


# ---------------------------------------------------------------------------
# Data (get-data, apply-data-type, create-label)
# ---------------------------------------------------------------------------


@main.group(
    "data",
    help="Data at address (get-data, apply-data-type, create-label)",
)
def data_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:data_grp")
    pass


@data_grp.command("get", help="Get data/code unit at address (get-data)")
@click.option("-b", "--binary", "program_path")
@click.argument("address_or_symbol")
@click.pass_context
def data_get(ctx: click.Context, program_path: str | None, address_or_symbol: str) -> None:
    logger.debug("diag.enter %s", "cli.py:data_get")
    kwargs: dict[str, Any] = {"addressOrSymbol": address_or_symbol}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, "get-data", **kwargs))


@data_grp.command("apply-type", help="Apply data type at address (apply-data-type)")
@click.option("-b", "--binary", "program_path")
@click.argument("address_or_symbol")
@click.option("--data-type", "data_type_string", required=True)
@click.option("--archive-name", "archive_name")
@click.pass_context
def data_apply_type(
    ctx: click.Context,
    program_path: str | None,
    address_or_symbol: str,
    data_type_string: str,
    archive_name: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:data_apply_type")
    payload: dict[str, Any] = {
        "addressOrSymbol": address_or_symbol,
        "dataTypeString": data_type_string,
    }
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if archive_name is not None:
        payload["archiveName"] = archive_name
    _run_async(_call(ctx, Tool.APPLY_DATA_TYPE.value, **payload))


@data_grp.command("create-label", help="Create label at address (create-label)")
@click.option("-b", "--binary", "program_path")
@click.argument("address_or_symbol")
@click.option("--name", "labelName", required=True)
@click.option("--primary", "setAsPrimary", is_flag=True)
@click.pass_context
def data_create_label(
    ctx: click.Context,
    program_path: str | None,
    address_or_symbol: str,
    label_name: str,
    set_as_primary: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:data_create_label")
    kwargs: dict[str, Any] = {
        "addressOrSymbol": address_or_symbol,
        "labelName": label_name,
        "setAsPrimary": set_as_primary,
    }
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, "create-label", **kwargs))


# ---------------------------------------------------------------------------
# Resources (program list, static analysis, debug info)
# ---------------------------------------------------------------------------


@main.group(
    "resource",
    help="Read MCP resources. Canonical advertised URI: agentdecompile://debug-info. Legacy program/static-analysis aliases remain readable.",
)
def resource_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:resource_grp")
    pass


async def _read_resource(ctx: click.Context, uri: str) -> None:
    """Read a resource with auto-recovery for program loading."""
    logger.debug("diag.enter %s", "cli.py:_read_resource")
    client = _client(ctx)

    try:
        async with client:
            result = await client.read_resource(uri)
    except Exception as e:
        error_msg = str(e).lower()

        # Check if error is program-related
        if "no program loaded" in error_msg or "no active program" in error_msg:
            # Try to recover by opening a program from environment
            try:
                # Try to auto-open from cache or environment
                cached_prog = _get_cached_program(ctx)
                if cached_prog:
                    # Open the cached program
                    await _call_raw(
                        ctx,
                        Tool.OPEN.value,
                        {"path": cached_prog, "local": True},
                    )
                    # Retry resource read
                    async with client:
                        result = await client.read_resource(uri)
                else:
                    # No cached program, raise original error
                    raise e
            except Exception as recovery_error:
                logger.debug("Resource recovery failed: %s", recovery_error)
                raise e
        else:
            # Not a program-loading error, re-raise
            raise

    data = _parse_json(result)
    click.echo(format_output(data or result, _fmt(ctx)))


@resource_grp.command("programs", help="Read legacy alias ghidra://programs (same as list binaries)")
@click.pass_context
def resource_programs(ctx: click.Context) -> None:
    logger.debug("diag.enter %s", "cli.py:resource_programs")
    _run_async(_read_resource(ctx, RESOURCE_URI_PROGRAMS))


@resource_grp.command(
    "static-analysis",
    help="Read legacy alias ghidra://static-analysis-results (SARIF 2.1.0)",
)
@click.pass_context
def resource_static_analysis(ctx: click.Context) -> None:
    logger.debug("diag.enter %s", "cli.py:resource_static_analysis")
    _run_async(_read_resource(ctx, RESOURCE_URI_STATIC_ANALYSIS))


@resource_grp.command(
    "debug-info",
    help="Read agentdecompile://debug-info (legacy ghidra://agentdecompile-debug-info is still accepted)",
)
@click.pass_context
def resource_debug_info(ctx: click.Context) -> None:
    logger.debug("diag.enter %s", "cli.py:resource_debug_info")
    _run_async(_read_resource(ctx, RESOURCE_URI_DEBUG_INFO))


# ---------------------------------------------------------------------------
# get-functions (decompile, disassemble, info, calls)
# ---------------------------------------------------------------------------


@main.group(
    "functions",
    help="Get function details (get-functions): decompile, disassemble, info, calls",
)
def functions_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:functions_grp")
    pass


@functions_grp.command("decompile", help="Decompile a function (view=decompile)")
@click.option("-b", "--binary", "program_path")
@click.argument("identifier")
@click.option("--offset", type=int, default=1, help="Line offset (1-based)")
@click.option("--include-callers", is_flag=True)
@click.option("--include-callees", is_flag=True)
@click.option("--include-comments", is_flag=True)
@click.option(
    "--no-incoming-refs",
    is_flag=True,
    help="Disable includeIncomingReferences",
)
@click.option("--no-ref-context", is_flag=True, help="Disable includeReferenceContext")
@click.pass_context
def functions_decompile(
    ctx: click.Context,
    program_path: str | None,
    identifier: str,
    offset: int,
    include_callers: bool,
    include_callees: bool,
    include_comments: bool,
    no_incoming_refs: bool,
    no_ref_context: bool,
) -> None:
    async def _run():
        client = _client(ctx)
        async with client:
            body: dict[str, Any] = {
                "identifier": identifier,
                "view": "decompile",
                "offset": offset,
                "includeCallers": include_callers,
                "includeCallees": include_callees,
                "includeComments": include_comments,
                "includeIncomingReferences": False if no_incoming_refs else True,
                "includeReferenceContext": False if no_ref_context else True,
            }
            if program_path is not None and program_path.strip():
                body["programPath"] = program_path
            result = await client.call_tool(
                Tool.GET_FUNCTIONS.value,
                body,
            )
        data = _parse_json(result)
        if isinstance(data, dict):
            text = data.get("decompilation") or data.get("code")
            if text is not None and str(text).strip():
                click.echo(text)
            else:
                click.echo(format_output(data or result, _fmt(ctx)))
        else:
            click.echo(format_output(data or result, _fmt(ctx)))

    logger.debug("diag.enter %s", "cli.py:functions_decompile")
    _run_async(_run())


@functions_grp.command(
    "disassemble",
    help="Disassembly for a function (view=disassemble)",
)
@click.option("-b", "--binary", "program_path")
@click.argument("identifier")
@click.pass_context
def functions_disassemble(
    ctx: click.Context,
    program_path: str | None,
    identifier: str,
) -> None:
    logger.debug("diag.enter %s", "cli.py:functions_disassemble")
    kwargs: dict[str, Any] = {"identifier": identifier, "view": "disassemble"}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, Tool.GET_FUNCTIONS.value, **kwargs))


@functions_grp.command("info", help="Function metadata (view=info)")
@click.option("-b", "--binary", "program_path")
@click.argument("identifier")
@click.pass_context
def functions_info(ctx: click.Context, program_path: str | None, identifier: str) -> None:
    logger.debug("diag.enter %s", "cli.py:functions_info")
    kwargs: dict[str, Any] = {"identifier": identifier, "view": "info"}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, Tool.GET_FUNCTIONS.value, **kwargs))


@functions_grp.command("calls", help="Internal calls (view=calls)")
@click.option("-b", "--binary", "program_path")
@click.argument("identifier")
@click.pass_context
def functions_calls(ctx: click.Context, program_path: str | None, identifier: str) -> None:
    logger.debug("diag.enter %s", "cli.py:functions_calls")
    kwargs: dict[str, Any] = {"identifier": identifier, "view": "calls"}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, Tool.GET_FUNCTIONS.value, **kwargs))


# ---------------------------------------------------------------------------
# manage-symbols (all modes)
# ---------------------------------------------------------------------------


@main.group(
    "symbols",
    help="Symbol operations: classes, namespaces, imports, exports, create_label, symbols, count, rename_data, demangle",
)
def symbols_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:symbols_grp")
    pass


@symbols_grp.command("run", help="Run symbol operations with --mode and optional params")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--mode",
    type=click.Choice(
        [
            "classes",
            "namespaces",
            "imports",
            "exports",
            "create_label",
            "symbols",
            "count",
            "rename_data",
            "demangle",
        ],
    ),
    required=True,
)
@click.option("--address", multiple=True)
@click.option("--label-name", "label_name", multiple=True)
@click.option("--new-name", "new_name", multiple=True)
@click.option("--library-filter", "library_filter")
@click.option("--start-index", "start_index", type=int)
@click.option("--offset", type=int)
@click.option(
    "--group-by-library/--no-group-by-library",
    "group_by_library",
    default=True,
)
@click.option("--include-external", "include_external", is_flag=True)
@click.option(
    "--filter-default-names/--no-filter-default-names",
    "filter_default_names",
    default=True,
)
@click.option("--demangle-all", "demangle_all", is_flag=True)
@click.pass_context
def symbols_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    address: tuple[str, ...],
    label_name: tuple[str, ...],
    new_name: tuple[str, ...],
    library_filter: str | None,
    start_index: int | None,
    offset: int | None,
    group_by_library: bool,
    include_external: bool,
    filter_default_names: bool,
    demangle_all: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:symbols_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address:
        payload["address"] = list(address) if len(address) != 1 else address[0]
    if label_name:
        payload["labelName"] = list(label_name) if len(label_name) != 1 else label_name[0]
    if new_name:
        payload["newName"] = list(new_name) if len(new_name) != 1 else new_name[0]
    if library_filter is not None:
        payload["libraryFilter"] = library_filter
    if start_index is not None:
        payload["startIndex"] = start_index
    if offset is not None:
        payload["offset"] = offset
    payload["groupByLibrary"] = group_by_library
    payload["includeExternal"] = include_external
    payload["filterDefaultNames"] = filter_default_names
    if mode == "demangle":
        payload["demangleAll"] = demangle_all
    _run_async(_call(ctx, Tool.MANAGE_SYMBOLS.value, **payload))


# --- Convenience subcommands (``symbols classes``, ``symbols imports``, …) ---


def _symbols_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``symbols <mode>`` shorthand subcommands."""

    @symbols_grp.command(mode_name, help=help_text or f"Run symbols mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--offset", type=int)
    @click.option("--library-filter", "library_filter")
    @click.option("--group-by-library/--no-group-by-library", "group_by_library", default=True)
    @click.option("--include-external", "include_external", is_flag=True)
    @click.option("--filter-default-names/--no-filter-default-names", "filter_default_names", default=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        offset: int | None,
        library_filter: str | None,
        group_by_library: bool,
        include_external: bool,
        filter_default_names: bool,
    ) -> None:
        payload: dict[str, Any] = {"mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if offset is not None:
            payload["offset"] = offset
        if library_filter:
            payload["libraryFilter"] = library_filter
        payload["groupByLibrary"] = group_by_library
        payload["includeExternal"] = include_external
        payload["filterDefaultNames"] = filter_default_names
        _run_async(_call(ctx, Tool.MANAGE_SYMBOLS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_symbols_mode_command")
    return _cmd


for _mode in ("classes", "namespaces", "imports", "exports", "symbols", "count", "demangle"):
    _symbols_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-strings
# ---------------------------------------------------------------------------


@main.group("strings", help="String operations: list, regex, count, similarity")
def strings_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:strings_grp")
    pass


@strings_grp.command("run", help="Run string operations with --mode and optional params")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--mode",
    type=click.Choice(["list", "regex", "count", "similarity"]),
    default="list",
)
@click.option("--pattern")
@click.option("--search-string", "searchString")
@click.option("--filter")
@click.option("--start-index", "startIndex", type=int)
@click.option("--offset", type=int)
@click.option("--include-referencing-functions", "includeReferencingFunctions", is_flag=True)
@click.pass_context
def strings_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    pattern: str | None,
    search_string: str | None,
    filter: str | None,
    start_index: int | None,
    offset: int | None,
    include_referencing_functions: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:strings_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if pattern is not None:
        payload["pattern"] = pattern
    if search_string is not None:
        payload["searchString"] = search_string
    if filter is not None:
        payload["filter"] = filter
    if start_index is not None:
        payload["startIndex"] = start_index
    if offset is not None:
        payload["offset"] = offset
    payload["includeReferencingFunctions"] = include_referencing_functions
    _run_async(_call(ctx, Tool.MANAGE_STRINGS.value, **payload))


# --- Convenience subcommands (``strings list``, ``strings regex``, …) ---


def _strings_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``strings <mode>`` shorthand subcommands."""

    @strings_grp.command(mode_name, help=help_text or f"Run strings mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--pattern")
    @click.option("--search-string", "search_string")
    @click.option("--filter")
    @click.option("--offset", type=int)
    @click.option("--include-referencing-functions", "include_refs", is_flag=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        pattern: str | None,
        search_string: str | None,
        filter: str | None,
        offset: int | None,
        include_refs: bool,
    ) -> None:
        payload: dict[str, Any] = {"mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if pattern:
            payload["pattern"] = pattern
        if search_string:
            payload["searchString"] = search_string
        if filter:
            payload["filter"] = filter
        if offset is not None:
            payload["offset"] = offset
        payload["includeReferencingFunctions"] = include_refs
        _run_async(_call(ctx, Tool.MANAGE_STRINGS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_strings_mode_command")
    return _cmd


for _mode in ("list", "regex", "count", "similarity"):
    _strings_mode_command(_mode)


# ---------------------------------------------------------------------------
# list-functions
# ---------------------------------------------------------------------------


@main.group(
    "list-functions",
    help="List/search functions (list-functions): all, search, similarity, undefined, count, by_identifiers",
)
def list_functions_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:list_functions_grp")
    pass


@list_functions_grp.command("run", help="Run list-functions with --mode and optional params")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--mode",
    type=click.Choice(["all", "search", "similarity", "undefined", "count", "by_identifiers"]),
    default="all",
)
@click.option("--query")
@click.option("--search-string", "searchString")
@click.option("--min-reference-count", "minReferenceCount", type=int)
@click.option("--identifiers", multiple=True)
@click.option("--start-index", "startIndex", type=int)
@click.option("--offset", type=int)
@click.option(
    "--filter-default-names/--no-filter-default-names",
    "filterDefaultNames",
    default=True,
)
@click.option("--filter-by-tag", "filterByTag")
@click.option("--untagged", is_flag=True)
@click.option("--has-tags", "hasTags", is_flag=True)
@click.option("--verbose", is_flag=True)
@click.pass_context
def list_functions_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    query: str | None,
    search_string: str | None,
    min_reference_count: int | None,
    identifiers: tuple[str, ...],
    start_index: int | None,
    offset: int | None,
    filter_default_names: bool,
    filter_by_tag: str | None,
    untagged: bool,
    has_tags: bool,
    verbose: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:list_functions_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if query is not None and query.strip():
        payload["query"] = query
    if search_string is not None and search_string.strip():
        payload["searchString"] = search_string
    if min_reference_count is not None:
        payload["minReferenceCount"] = min_reference_count
    if identifiers:
        payload["identifiers"] = list(identifiers)
    if start_index is not None:
        payload["startIndex"] = start_index
    if offset is not None:
        payload["offset"] = offset
    payload["filterDefaultNames"] = filter_default_names
    if filter_by_tag is not None and filter_by_tag.strip():
        payload["filterByTag"] = filter_by_tag
    payload["untagged"] = untagged
    payload["hasTags"] = has_tags
    payload["verbose"] = verbose
    _run_async(_call(ctx, Tool.LIST_FUNCTIONS.value, **payload))


# --- Convenience subcommands (``list-functions all``, ``list-functions search``, …) ---


def _list_functions_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``list-functions <mode>`` shorthand subcommands."""

    @list_functions_grp.command(mode_name, help=help_text or f"list-functions mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--query")
    @click.option("--offset", type=int)
    @click.option("--filter-default-names/--no-filter-default-names", "filter_default_names", default=True)
    @click.option("--verbose", is_flag=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        query: str | None,
        offset: int | None,
        filter_default_names: bool,
        verbose: bool,
    ) -> None:
        payload: dict[str, Any] = {"mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if query:
            payload["query"] = query
        if offset is not None:
            payload["offset"] = offset
        payload["filterDefaultNames"] = filter_default_names
        payload["verbose"] = verbose
        _run_async(_call(ctx, Tool.LIST_FUNCTIONS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_list_functions_mode_command")
    return _cmd


for _mode in ("all", "search", "similarity", "undefined", "count", "by_identifiers"):
    _list_functions_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-function
# ---------------------------------------------------------------------------


@main.group("function", help="Manage function (manage-function): create, rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes")
def function_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:function_grp")
    pass


@function_grp.command("run", help="Run manage-function with --action and optional params")
@click.option("-b", "--binary", "program_path")
@click.option("--action", type=click.Choice(["create", "rename_function", "rename_variable", "set_prototype", "set_variable_type", "change_datatypes"]), required=True)
@click.option("--address", multiple=True)
@click.option("--function-identifier", "functionIdentifier", multiple=True)
@click.option("--name")
@click.option("--functions", help="JSON array of function rename objects")
@click.option("--old-name", "oldName")
@click.option("--new-name", "newName")
@click.option("--variable-mappings", "variableMappings", help="oldName1:newName1,oldName2:newName2")
@click.option("--prototype", "prototype", multiple=True)
@click.option("--variable-name", "variableName")
@click.option("--new-type", "newType")
@click.option("--datatype-mappings", "datatypeMappings", help="varName1:type1,varName2:type2")
@click.option("--archive-name", "archiveName")
@click.option("--create-if-not-exists/--no-create-if-not-exists", "createIfNotExists", default=True)
@click.option("--propagate/--no-propagate", default=True)
@click.option("--propagate-program-paths", "propagateProgramPaths", multiple=True)
@click.option("--propagate-max-candidates", "propagateMaxCandidates", type=int)
@click.option("--propagate-max-instructions", "propagateMaxInstructions", type=int)
@click.pass_context
def function_run(
    ctx: click.Context,
    program_path: str | None,
    action: str,
    address: tuple[str, ...],
    function_identifier: tuple[str, ...],
    name: str | None,
    functions: str | None,
    old_name: str | None,
    new_name: str | None,
    variable_mappings: str | None,
    prototype: tuple[str, ...],
    variable_name: str | None,
    new_type: str | None,
    datatype_mappings: str | None,
    archive_name: str | None,
    create_if_not_exists: bool,
    propagate: bool,
    propagate_program_paths: tuple[str, ...],
    propagate_max_candidates: int | None,
    propagate_max_instructions: int | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:function_run")
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address:
        payload["address"] = list(address) if len(address) != 1 else address[0]
    if function_identifier:
        payload["functionIdentifier"] = list(function_identifier) if len(function_identifier) != 1 else function_identifier[0]
    if name is not None and name.strip():
        payload["name"] = name
    if functions is not None and functions.strip():
        try:
            payload["functions"] = json.loads(functions)
        except json.JSONDecodeError:
            raise click.BadParameter("--functions must be valid JSON array")
    if old_name is not None and old_name.strip():
        payload["oldName"] = old_name
    if new_name is not None and new_name.strip():
        payload["newName"] = new_name
    if variable_mappings is not None and variable_mappings.strip():
        payload["variableMappings"] = variable_mappings
    if prototype:
        payload["prototype"] = list(prototype) if len(prototype) != 1 else prototype[0]
    if variable_name is not None and variable_name.strip():
        payload["variableName"] = variable_name
    if new_type is not None and new_type.strip():
        payload["newType"] = new_type
    if datatype_mappings is not None and datatype_mappings.strip():
        payload["datatypeMappings"] = datatype_mappings
    if archive_name is not None and archive_name.strip():
        payload["archiveName"] = archive_name
    payload["createIfNotExists"] = create_if_not_exists
    payload["propagate"] = propagate
    if propagate_program_paths:
        payload["propagateProgramPaths"] = list(propagate_program_paths)
    if propagate_max_candidates is not None:
        payload["propagateMaxCandidates"] = propagate_max_candidates
    if propagate_max_instructions is not None:
        payload["propagateMaxInstructions"] = propagate_max_instructions
    _run_async(_call(ctx, Tool.MANAGE_FUNCTION.value, **payload))


# ---------------------------------------------------------------------------
# manage-function-tags
# ---------------------------------------------------------------------------


@main.group("function-tags", help="Manage function tags (manage-function-tags): get, set, add, remove, list")
def function_tags_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:function_tags_grp")
    pass


@function_tags_grp.command("run", help="Run manage-function-tags with --mode")
@click.option("-b", "--binary", "program_path")
@click.option("--mode", type=click.Choice(["get", "set", "add", "remove", "list"]), required=True)
@click.option("--function", "function", multiple=True)
@click.option("--tags", multiple=True)
@click.pass_context
def function_tags_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    function: tuple[str, ...],
    tags: tuple[str, ...],
) -> None:
    logger.debug("diag.enter %s", "cli.py:function_tags_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if function:
        payload["function"] = list(function) if len(function) != 1 else function[0]
    if tags:
        payload["tags"] = list(tags)
    _run_async(_call(ctx, Tool.MANAGE_FUNCTION_TAGS.value, **payload))


# ---------------------------------------------------------------------------
# match-function
# ---------------------------------------------------------------------------


@main.command("match-function", help=f"Match functions across programs ({Tool.MATCH_FUNCTION.value})")
@click.option("-b", "--binary", "program_path")
@click.option("--function-identifier", "functionIdentifier", multiple=True)
@click.option("--target-program-paths", "targetProgramPaths", multiple=True)
@click.option("--max-instructions", "maxInstructions", type=int)
@click.option("--min-similarity", "minSimilarity", type=float)
@click.option("--propagate-names/--no-propagate-names", "propagateNames", default=True)
@click.option("--propagate-tags/--no-propagate-tags", "propagateTags", default=True)
@click.option("--propagate-comments/--no-propagate-comments", "propagateComments", default=False)
@click.option("--filter-default-names/--no-filter-default-names", "filterDefaultNames", default=True)
@click.option("--filter-by-tag", "filterByTag")
@click.option("--max-functions", "maxFunctions", type=int)
@click.option("--batch-size", "batchSize", type=int)
@click.pass_context
def match_function(
    ctx: click.Context,
    program_path: str | None,
    function_identifier: tuple[str, ...],
    target_program_paths: tuple[str, ...],
    max_instructions: int | None,
    min_similarity: float | None,
    propagate_names: bool,
    propagate_tags: bool,
    propagate_comments: bool,
    filter_default_names: bool,
    filter_by_tag: str | None,
    max_functions: int | None,
    batch_size: int | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:match_function")
    payload: dict[str, Any] = {}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if function_identifier:
        payload["functionIdentifier"] = list(function_identifier) if len(function_identifier) != 1 else function_identifier[0]
    if target_program_paths:
        payload["targetProgramPaths"] = list(target_program_paths) if len(target_program_paths) != 1 else target_program_paths[0]
    if max_instructions is not None:
        payload["maxInstructions"] = max_instructions
    if min_similarity is not None:
        payload["minSimilarity"] = min_similarity
    payload["propagateNames"] = propagate_names
    payload["propagateTags"] = propagate_tags
    payload["propagateComments"] = propagate_comments
    payload["filterDefaultNames"] = filter_default_names
    if filter_by_tag is not None and filter_by_tag.strip():
        payload["filterByTag"] = filter_by_tag
    if max_functions is not None:
        payload["maxFunctions"] = max_functions
    if batch_size is not None:
        payload["batchSize"] = batch_size
    _run_async(_call(ctx, Tool.MATCH_FUNCTION.value, **payload))


# ---------------------------------------------------------------------------
# migrate-metadata (bulk match-function: all functions, optional targets)
# ---------------------------------------------------------------------------


@main.command(
    "migrate-metadata",
    help="Bulk propagate function metadata from a source binary to others (match-function over all functions). "
    "Uses match-function with no function identifier so the tool iterates all functions; discovers targets from the session if not given. "
    "When using a remote server (--server-url), open the project in the same session first (e.g. tool-seq with open then this command).",
)
@click.option("-b", "--binary", "program_path", help="Source program path (programPath).")
@click.option("--source-path", "program_path_alt", help="Alias for --binary.")
@click.option("--target-paths", "target_program_paths", multiple=True, help="Target program paths; if omitted, discovered from session.")
@click.option("--min-similarity", "minSimilarity", type=float, default=0.7, help="minSimilarity for match (default 0.7).")
@click.option("--limit", "limit", type=int, help="Cap number of functions to process. When omitted with no --binary and no --target-paths, defaults to 50 so the command completes in bounded time.")
@click.option("--include-externals/--no-include-externals", "includeExternals", default=True, help="Include external functions (default true).")
@click.option("--propagate-names/--no-propagate-names", "propagateNames", default=True)
@click.option("--propagate-tags/--no-propagate-tags", "propagateTags", default=True)
@click.option("--propagate-comments/--no-propagate-comments", "propagateComments", default=True)
@click.option("--propagate-prototype/--no-propagate-prototype", "propagatePrototype", default=True)
@click.option("--propagate-bookmarks/--no-propagate-bookmarks", "propagateBookmarks", default=True)
@click.option(
    "--checkin",
    "do_checkin",
    is_flag=True,
    help="After propagation, check in all modified target programs (same as checkin-program with no path; uses same session).",
)
@click.pass_context
def migrate_metadata(
    ctx: click.Context,
    program_path: str | None,
    program_path_alt: str | None,
    target_program_paths: tuple[str, ...],
    minSimilarity: float,
    limit: int | None,
    includeExternals: bool,
    propagateNames: bool,
    propagateTags: bool,
    propagateComments: bool,
    propagatePrototype: bool,
    propagateBookmarks: bool,
    do_checkin: bool,
) -> None:
    """Run match-function over all functions in the source (bulk migration). No function identifier = iterate all.

    Sessions are isolated: the server session for this CLI run must already have a project open
    (shared or local). Use tool-seq to run open then migrate-metadata in one connection.
    Use --checkin to check in all open programs after propagation (same session).
    """
    logger.debug("diag.enter %s", "cli.py:migrate_metadata")
    source = (program_path or program_path_alt or "").strip()
    payload: dict[str, Any] = {
        "propagateNames": propagateNames,
        "propagateTags": propagateTags,
        "propagateComments": propagateComments,
        "propagatePrototype": propagatePrototype,
        "propagateBookmarks": propagateBookmarks,
        "minSimilarity": minSimilarity,
        "includeExternals": includeExternals,
    }
    if source:
        payload["programPath"] = source
    if target_program_paths:
        payload["targetProgramPaths"] = list(target_program_paths) if len(target_program_paths) != 1 else target_program_paths[0]
    # When no args at all (no binary, no target-paths), default limit so the command completes in bounded time
    effective_limit = limit
    if effective_limit is None and not source and not target_program_paths:
        effective_limit = 50
    if effective_limit is not None:
        payload["limit"] = effective_limit
    if do_checkin:
        _run_async(_migrate_metadata_then_checkin(ctx, payload))
    else:
        _run_async(_call(ctx, Tool.MATCH_FUNCTION.value, **payload))


# ---------------------------------------------------------------------------
# inspect-memory
# ---------------------------------------------------------------------------


@main.group("memory", help="Inspect memory (inspect-memory): blocks, read, data_at, data_items, segments")
def memory_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:memory_grp")
    pass


@memory_grp.command("run", help="Run inspect-memory with --mode")
@click.option("-b", "--binary", "program_path")
@click.option("--mode", type=click.Choice(["blocks", "read", "data_at", "data_items", "segments"]), required=True)
@click.option("--address")
@click.option("--length", type=int)
@click.option("--offset", type=int)
@click.pass_context
def memory_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    address: str | None,
    length: int | None,
    offset: int | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:memory_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address is not None and address.strip():
        payload["address"] = address
    if length is not None:
        payload["length"] = length
    if offset is not None:
        payload["offset"] = offset
    _run_async(_call(ctx, Tool.INSPECT_MEMORY.value, **payload))


# ---------------------------------------------------------------------------
# open
# ---------------------------------------------------------------------------


@main.command("open", help="Open project/shared session (open); use import/import-binary for local binaries")
@click.argument("path", type=click.Path(exists=False), required=False, default=None)
@click.option("--shared/--no-shared", "shared", default=False, help="Force shared Ghidra repository mode for open")
@click.option("--open-all-programs", "open_all_programs", is_flag=True, default=False, help="Open all programs in the project")
@click.option("--extensions", help="Comma-separated extensions for bulk open (e.g. exe,dll)")
@click.option("--destination_folder", "--destination-folder", "destination_folder", default="/")
@click.option("--analyze_after_import/--no-analyze_after_import", "--analyze-after-import/--no-analyze-after-import", "analyze_after_import", default=True)
@click.option("--enable_version_control/--no-enable_version_control", "--enable-version-control/--no-enable-version-control", "enable_version_control", default=False)
@click.option("--server_username", "--server-username", "--ghidra_server_username", "--ghidra-server-username", "server_username")
@click.option("--server_password", "--server-password", "--ghidra_server_password", "--ghidra-server-password", "server_password")
@click.option("--server_host", "--server-host", "--ghidra_server_host", "--ghidra-server-host", "server_host")
@click.option("--server_port", "--server-port", "--ghidra_server_port", "--ghidra-server-port", "server_port", type=int)
@click.option("--server_repository", "--server-repository", "--ghidra_server_repository", "--ghidra-server-repository", "server_repository")
@click.pass_context
def open_cmd(
    ctx: click.Context,
    path: str | None,
    shared: bool,
    extensions: str | None,
    open_all_programs: bool,
    destination_folder: str,
    analyze_after_import: bool,
    enable_version_control: bool,
    server_username: str | None,
    server_password: str | None,
    server_host: str | None,
    server_port: int | None,
    server_repository: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:open_cmd")
    payload: dict[str, Any] = {}
    opts = _get_opts(ctx)
    # Merge global Ghidra server options when command-level options are not set (e.g. --ghidra-server-username before open)
    if not (server_username and server_username.strip()):
        server_username = opts.get("ghidra_server_username") or opts.get("server_username")
    if not (server_password and server_password.strip()):
        server_password = opts.get("ghidra_server_password") or opts.get("server_password")
    if not (server_host and server_host.strip()):
        server_host = opts.get("ghidra_server_host") or opts.get("server_host")
    if server_port is None:
        server_port = opts.get("ghidra_server_port") or opts.get("server_port")
    if not (server_repository and server_repository.strip()):
        server_repository = opts.get("ghidra_server_repository") or opts.get("server_repository")

    is_shared_server_mode = shared or bool(server_host and str(server_host).strip())

    # When connecting to a remote Ghidra shared-project server, the MCP
    # backend typically runs on the *same* host (Docker exposes the Ghidra
    # server ports and the MCP HTTP port side-by-side).  If the caller
    # provided --server_host but did NOT override the global --host /
    # --server-url (which still points at localhost), automatically route
    # the MCP client connection to the remote host on the default MCP port.
    if is_shared_server_mode and server_host:
        if opts.get("host") == "127.0.0.1" and not opts.get("server_url"):
            opts["host"] = server_host

    if path is not None:
        if is_shared_server_mode:
            payload["path"] = path
        else:
            payload["path"] = str(Path(path).resolve()) if path != "/" else path
    elif is_shared_server_mode and server_repository and str(server_repository).strip():
        payload["path"] = str(server_repository).strip()
    if extensions is not None:
        payload["extensions"] = extensions
    if shared:
        payload["shared"] = True
    payload["openAllPrograms"] = open_all_programs
    payload["destinationFolder"] = destination_folder
    payload["analyzeAfterImport"] = analyze_after_import
    payload["enableVersionControl"] = enable_version_control
    if server_username is not None and str(server_username).strip():
        payload["serverUsername"] = str(server_username).strip()
    if server_password is not None and str(server_password).strip():
        payload["serverPassword"] = str(server_password).strip()
    if server_host is not None and str(server_host).strip():
        payload["serverHost"] = str(server_host).strip()
    if server_port is not None:
        payload["serverPort"] = int(server_port)
    if server_repository is not None and str(server_repository).strip():
        payload["repositoryName"] = str(server_repository).strip()
    _run_async(_call(ctx, Tool.OPEN.value, **payload))


# ---------------------------------------------------------------------------
# get-references
# ---------------------------------------------------------------------------


@main.group("references", help="Cross-references (get-references): to, from, both, function, referencers_decomp, import, thunk")
def references_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:references_grp")
    pass


@references_grp.command("run", help="Run get-references with --target and --mode")
@click.option("-b", "--binary", "program_path")
@click.option("--target", required=True, help="Address, symbol, function, or import name")
@click.option("--mode", type=click.Choice(["to", "from", "both", "function", "referencers_decomp", "import", "thunk"]), default="both")
@click.option("--direction", type=click.Choice(["to", "from", "both"]))
@click.option("--offset", type=int)
@click.option("--library-name", "libraryName")
@click.option("--start-index", "startIndex", type=int)
@click.option("--max-referencers", "maxReferencers", type=int)
@click.option("--include-ref-context/--no-include-ref-context", "includeRefContext", default=True)
@click.option("--include-data-refs/--no-include-data-refs", "includeDataRefs", default=True)
@click.pass_context
def references_run(
    ctx: click.Context,
    program_path: str | None,
    target: str,
    mode: str,
    direction: str | None,
    offset: int | None,
    library_name: str | None,
    start_index: int | None,
    max_referencers: int | None,
    include_ref_context: bool,
    include_data_refs: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:references_run")
    payload: dict[str, Any] = {"target": target, "mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if direction is not None:
        payload["direction"] = direction
    if offset is not None:
        payload["offset"] = offset
    if library_name is not None:
        payload["libraryName"] = library_name
    if start_index is not None:
        payload["startIndex"] = start_index
    if max_referencers is not None:
        payload["maxReferencers"] = max_referencers
    payload["includeRefContext"] = include_ref_context
    payload["includeDataRefs"] = include_data_refs
    _run_async(_call(ctx, Tool.GET_REFERENCES.value, **payload))


# --- Convenience subcommands (``references to``, ``references from``, …) ---


def _references_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``references <mode>`` shorthand subcommands."""

    @references_grp.command(mode_name, help=help_text or f"get-references mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--target", required=True, help="Address, symbol, function, or import name")
    @click.option("--direction", type=click.Choice(["to", "from", "both"]))
    @click.option("--offset", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        target: str,
        direction: str | None,
        offset: int | None,
    ) -> None:
        payload: dict[str, Any] = {"target": target, "mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if direction is not None:
            payload["direction"] = direction
        if offset is not None:
            payload["offset"] = offset
        _run_async(_call(ctx, Tool.GET_REFERENCES.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_references_mode_command")
    return _cmd


for _mode in ("to", "from", "both", "function", "referencers_decomp", "import", "thunk"):
    _references_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-data-types
# ---------------------------------------------------------------------------


@main.group("datatypes", help="Manage data types (manage-data-types): archives, list, by_string, apply")
def datatypes_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:datatypes_grp")
    pass


@datatypes_grp.command("run", help="Run manage-data-types with --action")
@click.option("-b", "--binary", "program_path")
@click.option("--action", type=click.Choice(["archives", "list", "by_string", "apply"]), required=True)
@click.option("--archive-name", "archiveName")
@click.option("--category-path", "categoryPath", default="/")
@click.option("--include-subcategories", "includeSubcategories", is_flag=True)
@click.option("--start-index", "startIndex", type=int)
@click.option("--data-type-string", "dataTypeString")
@click.option("--address-or-symbol", "addressOrSymbol")
@click.pass_context
def datatypes_run(
    ctx: click.Context,
    program_path: str | None,
    action: str,
    archive_name: str | None,
    category_path: str,
    include_subcategories: bool,
    start_index: int | None,
    data_type_string: str | None,
    address_or_symbol: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:datatypes_run")
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if archive_name is not None:
        payload["archiveName"] = archive_name
    payload["categoryPath"] = category_path
    payload["includeSubcategories"] = include_subcategories
    if start_index is not None:
        payload["startIndex"] = start_index
    if data_type_string is not None:
        payload["dataTypeString"] = data_type_string
    if address_or_symbol is not None:
        payload["addressOrSymbol"] = address_or_symbol
    _run_async(_call(ctx, Tool.MANAGE_DATA_TYPES.value, **payload))


# --- Convenience subcommands (``datatypes archives``, ``datatypes list``, …) ---


def _datatypes_action_command(action_name: str, help_text: str | None = None):
    """Factory for ``datatypes <action>`` shorthand subcommands."""

    @datatypes_grp.command(action_name, help=help_text or f"manage-data-types action={action_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--archive-name", "archiveName")
    @click.option("--category-path", "categoryPath", default="/")
    @click.option("--include-subcategories", "includeSubcategories", is_flag=True)
    @click.option("--start-index", "startIndex", type=int)
    @click.option("--data-type-string", "dataTypeString")
    @click.option("--address-or-symbol", "addressOrSymbol")
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        archive_name: str | None,
        category_path: str,
        include_subcategories: bool,
        start_index: int | None,
        data_type_string: str | None,
        address_or_symbol: str | None,
    ) -> None:
        payload: dict[str, Any] = {"action": action_name}
        if program_path:
            payload["programPath"] = program_path
        if archive_name is not None:
            payload["archiveName"] = archive_name
        payload["categoryPath"] = category_path
        payload["includeSubcategories"] = include_subcategories
        if start_index is not None:
            payload["startIndex"] = start_index
        if data_type_string is not None:
            payload["dataTypeString"] = data_type_string
        if address_or_symbol is not None:
            payload["addressOrSymbol"] = address_or_symbol
        _run_async(_call(ctx, Tool.MANAGE_DATA_TYPES.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_datatypes_action_command")
    return _cmd


for _action in ("archives", "list", "by_string", "apply"):
    _datatypes_action_command(_action)


# ---------------------------------------------------------------------------
# manage-structures
# ---------------------------------------------------------------------------


@main.group("structures", help="Manage structures (manage-structures): parse, validate, create, add_field, modify_field, modify_from_c, info, apply, delete, parse_header")
def structures_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:structures_grp")
    pass


@structures_grp.command("run", help="Run manage-structures with --action")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--action",
    type=click.Choice(
        [
            "parse",
            "validate",
            "create",
            "add_field",
            "modify_field",
            "modify_from_c",
            "info",
            "apply",
            "delete",
            "parse_header",
        ],
    ),
    required=True,
)
@click.option("--c-definition", "cDefinition")
@click.option("--header-content", "headerContent")
@click.option("--structure-name", "structureName")
@click.option("--name")
@click.option("--size", type=int)
@click.option("--type", "type_", type=click.Choice(["structure", "union"]))
@click.option("--category", default="/")
@click.option("--packed", is_flag=True)
@click.option("--description")
@click.option("--fields", help="JSON array of field objects")
@click.option("--address-or-symbol", "addressOrSymbol", multiple=True)
@click.option("--clear-existing/--no-clear-existing", "clearExisting", default=True)
@click.option("--force", is_flag=True)
@click.option("--name-filter", "nameFilter")
@click.option("--include-built-in", "includeBuiltIn", is_flag=True)
@click.pass_context
def structures_run(
    ctx: click.Context,
    program_path: str | None,
    action: str,
    c_definition: str | None,
    header_content: str | None,
    structure_name: str | None,
    name: str | None,
    size: int | None,
    type_: str | None,
    category: str,
    packed: bool,
    description: str | None,
    fields: str | None,
    address_or_symbol: tuple[str, ...],
    clear_existing: bool,
    force: bool,
    name_filter: str | None,
    include_built_in: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:structures_run")
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if c_definition is not None:
        payload["cDefinition"] = c_definition
    if header_content is not None:
        payload["headerContent"] = header_content
    if structure_name is not None:
        payload["structureName"] = structure_name
    if name is not None:
        payload["name"] = name
    if size is not None:
        payload["size"] = size
    if type_ is not None:
        payload["type"] = type_
    payload["category"] = category
    payload["packed"] = packed
    if description is not None:
        payload["description"] = description
    if fields is not None:
        try:
            payload["fields"] = json.loads(fields)
        except json.JSONDecodeError:
            raise click.BadParameter("--fields must be valid JSON array")
    if address_or_symbol:
        payload["addressOrSymbol"] = list(address_or_symbol) if len(address_or_symbol) != 1 else address_or_symbol[0]
    payload["clearExisting"] = clear_existing
    payload["force"] = force
    if name_filter is not None:
        payload["nameFilter"] = name_filter
    payload["includeBuiltIn"] = include_built_in
    _run_async(_call(ctx, Tool.MANAGE_STRUCTURES.value, **payload))


# --- Convenience subcommands (``structures parse``, ``structures create``, …) ---


def _structures_action_command(action_name: str, help_text: str | None = None):
    """Factory for ``structures <action>`` shorthand subcommands."""

    @structures_grp.command(action_name, help=help_text or f"manage-structures action={action_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--c-definition", "cDefinition")
    @click.option("--structure-name", "structureName")
    @click.option("--name")
    @click.option("--size", type=int)
    @click.option("--category", default="/")
    @click.option("--description")
    @click.option("--fields", help="JSON array of field objects")
    @click.option("--name-filter", "nameFilter")
    @click.option("--include-built-in", "includeBuiltIn", is_flag=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        c_definition: str | None,
        structure_name: str | None,
        name: str | None,
        size: int | None,
        category: str,
        description: str | None,
        fields: str | None,
        name_filter: str | None,
        include_built_in: bool,
    ) -> None:
        payload: dict[str, Any] = {"action": action_name}
        if program_path:
            payload["programPath"] = program_path
        if c_definition is not None:
            payload["cDefinition"] = c_definition
        if structure_name is not None:
            payload["structureName"] = structure_name
        if name is not None:
            payload["name"] = name
        if size is not None:
            payload["size"] = size
        payload["category"] = category
        if description is not None:
            payload["description"] = description
        if fields is not None:
            try:
                payload["fields"] = json.loads(fields)
            except json.JSONDecodeError:
                raise click.BadParameter("--fields must be valid JSON array")
        if name_filter is not None:
            payload["nameFilter"] = name_filter
        payload["includeBuiltIn"] = include_built_in
        _run_async(_call(ctx, Tool.MANAGE_STRUCTURES.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_structures_action_command")
    return _cmd


for _action in ("parse", "validate", "create", "add_field", "modify_field", "modify_from_c", "info", "apply", "delete", "parse_header"):
    _structures_action_command(_action)


# ---------------------------------------------------------------------------
# manage-comments
# ---------------------------------------------------------------------------


@main.group("comments", help="Manage comments (manage-comments): set, get, remove, search, search_decomp")
def comments_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:comments_grp")
    pass


@comments_grp.command("run", help="Run manage-comments with --action")
@click.option("-b", "--binary", "program_path")
@click.option("--action", type=click.Choice(["set", "get", "remove", "search", "search_decomp"]), required=True)
@click.option("--address-or-symbol", "addressOrSymbol")
@click.option("--function")
@click.option("--line-number", "lineNumber", type=int)
@click.option("--comment")
@click.option("--comment-type", "commentType", type=click.Choice(["pre", "eol", "post", "plate", "repeatable"]))
@click.option("--comments", help="JSON array of comment objects")
@click.option("--start")
@click.option("--end")
@click.option("--comment-types", "commentTypes")
@click.option("--search-text", "searchText")
@click.option("--pattern")
@click.option("--case-sensitive", "caseSensitive", is_flag=True)
@click.option("--override-max-functions-limit", "overrideMaxFunctionsLimit", is_flag=True)
@click.pass_context
def comments_run(
    ctx: click.Context,
    program_path: str | None,
    action: str,
    address_or_symbol: str | None,
    function: str | None,
    line_number: int | None,
    comment: str | None,
    comment_type: str | None,
    comments: str | None,
    start: str | None,
    end: str | None,
    comment_types: str | None,
    search_text: str | None,
    pattern: str | None,
    case_sensitive: bool,
    override_max_functions_limit: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:comments_run")
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address_or_symbol is not None:
        payload["addressOrSymbol"] = address_or_symbol
    if function is not None:
        payload["function"] = function
    if line_number is not None:
        payload["lineNumber"] = line_number
    if comment is not None:
        payload["comment"] = comment
    if comment_type is not None:
        payload["commentType"] = comment_type
    if comments is not None:
        try:
            payload["comments"] = json.loads(comments)
        except json.JSONDecodeError:
            raise click.BadParameter("--comments must be valid JSON array")
    if start is not None:
        payload["start"] = start
    if end is not None:
        payload["end"] = end
    if comment_types is not None:
        payload["commentTypes"] = comment_types
    if search_text is not None:
        payload["searchText"] = search_text
    if pattern is not None:
        payload["pattern"] = pattern
    payload["caseSensitive"] = case_sensitive
    payload["overrideMaxFunctionsLimit"] = override_max_functions_limit
    _run_async(_call(ctx, Tool.MANAGE_COMMENTS.value, **payload))


# --- Convenience subcommands (``comments set``, ``comments get``, …) ---


def _comments_action_command(action_name: str, help_text: str | None = None):
    """Factory for ``comments <action>`` shorthand subcommands."""

    @comments_grp.command(action_name, help=help_text or f"manage-comments action={action_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--address-or-symbol", "addressOrSymbol")
    @click.option("--function")
    @click.option("--comment")
    @click.option("--comment-type", "commentType", type=click.Choice(["pre", "eol", "post", "plate", "repeatable"]))
    @click.option("--search-text", "searchText")
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        address_or_symbol: str | None,
        function: str | None,
        comment: str | None,
        comment_type: str | None,
        search_text: str | None,
    ) -> None:
        payload: dict[str, Any] = {"action": action_name}
        if program_path:
            payload["programPath"] = program_path
        if address_or_symbol is not None:
            payload["addressOrSymbol"] = address_or_symbol
        if function is not None:
            payload["function"] = function
        if comment is not None:
            payload["comment"] = comment
        if comment_type is not None:
            payload["commentType"] = comment_type
        if search_text is not None:
            payload["searchText"] = search_text
        _run_async(_call(ctx, Tool.MANAGE_COMMENTS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_comments_action_command")
    return _cmd


for _action in ("set", "get", "remove", "search", "search_decomp"):
    _comments_action_command(_action)


# ---------------------------------------------------------------------------
# manage-bookmarks
# ---------------------------------------------------------------------------


@main.group("bookmarks", help="Manage bookmarks (manage-bookmarks): set, get, search, remove, removeAll, categories")
def bookmarks_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:bookmarks_grp")
    pass


@bookmarks_grp.command("run", help="Run manage-bookmarks with --action")
@click.option("-b", "--binary", "program_path")
@click.option("--action", type=click.Choice(["set", "get", "search", "remove", "removeAll", "categories"]), required=True)
@click.option("--address-or-symbol", "addressOrSymbol")
@click.option("--type", "type_", type=click.Choice(["Note", "Warning", "TODO", "Bug", "Analysis"]))
@click.option("--category")
@click.option("--comment")
@click.option("--bookmarks", help="JSON array of bookmark objects")
@click.option("--search-text", "searchText")
@click.option("--remove-all", "removeAll", is_flag=True)
@click.pass_context
def bookmarks_run(
    ctx: click.Context,
    program_path: str | None,
    action: str,
    address_or_symbol: str | None,
    type_: str | None,
    category: str | None,
    comment: str | None,
    bookmarks: str | None,
    search_text: str | None,
    remove_all: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:bookmarks_run")
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address_or_symbol is not None:
        payload["addressOrSymbol"] = address_or_symbol
    if type_ is not None:
        payload["type"] = type_
    if category is not None:
        payload["category"] = category
    if comment is not None:
        payload["comment"] = comment
    if bookmarks is not None:
        try:
            payload["bookmarks"] = json.loads(bookmarks)
        except json.JSONDecodeError:
            raise click.BadParameter("--bookmarks must be valid JSON array")
    if search_text is not None:
        payload["searchText"] = search_text
    payload["removeAll"] = remove_all
    _run_async(_call(ctx, Tool.MANAGE_BOOKMARKS.value, **payload))


# --- Convenience subcommands (``bookmarks set``, ``bookmarks get``, …) ---


def _bookmarks_action_command(action_name: str, help_text: str | None = None):
    """Factory for ``bookmarks <action>`` shorthand subcommands."""

    @bookmarks_grp.command(action_name, help=help_text or f"manage-bookmarks action={action_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--address-or-symbol", "addressOrSymbol")
    @click.option("--type", "type_", type=click.Choice(["Note", "Warning", "TODO", "Bug", "Analysis"]))
    @click.option("--category")
    @click.option("--comment")
    @click.option("--search-text", "searchText")
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        address_or_symbol: str | None,
        type_: str | None,
        category: str | None,
        comment: str | None,
        search_text: str | None,
    ) -> None:
        payload: dict[str, Any] = {"action": action_name}
        if program_path:
            payload["programPath"] = program_path
        if address_or_symbol is not None:
            payload["addressOrSymbol"] = address_or_symbol
        if type_ is not None:
            payload["type"] = type_
        if category is not None:
            payload["category"] = category
        if comment is not None:
            payload["comment"] = comment
        if search_text is not None:
            payload["searchText"] = search_text
        _run_async(_call(ctx, Tool.MANAGE_BOOKMARKS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_bookmarks_action_command")
    return _cmd


for _action in ("set", "get", "search", "remove", "categories"):
    _bookmarks_action_command(_action)


# ---------------------------------------------------------------------------
# analyze-data-flow
# ---------------------------------------------------------------------------


@main.command("dataflow", help="Trace data flow (analyze-data-flow): backward, forward, variable_accesses")
@click.option("-b", "--binary", "program_path")
@click.option("--function-address", "functionAddress", required=True)
@click.option("--start-address", "startAddress")
@click.option("--variable-name", "variableName")
@click.option("--direction", type=click.Choice(["backward", "forward", "variable_accesses"]), required=True)
@click.pass_context
def dataflow(
    ctx: click.Context,
    program_path: str | None,
    function_address: str,
    start_address: str | None,
    variable_name: str | None,
    direction: str,
) -> None:
    logger.debug("diag.enter %s", "cli.py:dataflow")
    payload: dict[str, Any] = {
        "functionAddress": function_address,
        "direction": direction,
    }
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if start_address is not None:
        payload["startAddress"] = start_address
    if variable_name is not None:
        payload["variableName"] = variable_name
    _run_async(_call(ctx, Tool.ANALYZE_DATA_FLOW.value, **payload))


# ---------------------------------------------------------------------------
# get-call-graph
# ---------------------------------------------------------------------------


@main.group("callgraph", help="Call graph (get-call-graph): graph, tree, callers, callees, callers_decomp, common_callers")
def callgraph_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:callgraph_grp")
    pass


@callgraph_grp.command("run", help="Run get-call-graph")
@click.option("-b", "--binary", "program_path")
@click.option("--function", "functionIdentifier", required=True)
@click.option("--mode", type=click.Choice(["graph", "tree", "callers", "callees", "callers_decomp", "common_callers"]), default="graph")
@click.option("--depth", type=int)
@click.option("--direction", type=click.Choice(["callers", "callees"]))
@click.option("--max-depth", "maxDepth", type=int)
@click.option("--start-index", "startIndex", type=int)
@click.option("--max-callers", "maxCallers", type=int)
@click.option("--include-call-context/--no-include-call-context", "includeCallContext", default=True)
@click.option("--function-addresses", "functionAddresses", help="Comma-separated for common_callers")
@click.pass_context
def callgraph_run(
    ctx: click.Context,
    program_path: str | None,
    function_identifier: str,
    mode: str,
    depth: int | None,
    direction: str | None,
    max_depth: int | None,
    start_index: int | None,
    max_callers: int | None,
    include_call_context: bool,
    function_addresses: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:callgraph_run")
    payload: dict[str, Any] = {"functionIdentifier": function_identifier, "mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if depth is not None:
        payload["depth"] = depth
    if direction is not None:
        payload["direction"] = direction
    if max_depth is not None:
        payload["maxDepth"] = max_depth
    if start_index is not None:
        payload["startIndex"] = start_index
    if max_callers is not None:
        payload["maxCallers"] = max_callers
    payload["includeCallContext"] = include_call_context
    if function_addresses is not None:
        payload["functionAddresses"] = function_addresses
    _run_async(_call(ctx, Tool.GET_CALL_GRAPH.value, **payload))


# --- Convenience subcommands (``callgraph callers``, ``callgraph callees``, …) ---


def _callgraph_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``callgraph <mode>`` shorthand subcommands."""

    @callgraph_grp.command(mode_name, help=help_text or f"get-call-graph mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--function", "functionIdentifier", required=True)
    @click.option("--depth", type=int)
    @click.option("--max-depth", "maxDepth", type=int)
    @click.option("--max-callers", "maxCallers", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        function_identifier: str,
        depth: int | None,
        max_depth: int | None,
        max_callers: int | None,
    ) -> None:
        payload: dict[str, Any] = {"functionIdentifier": function_identifier, "mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if depth is not None:
            payload["depth"] = depth
        if max_depth is not None:
            payload["maxDepth"] = max_depth
        if max_callers is not None:
            payload["maxCallers"] = max_callers
        _run_async(_call(ctx, Tool.GET_CALL_GRAPH.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_callgraph_mode_command")
    return _cmd


for _mode in ("graph", "tree", "callers", "callees", "callers_decomp", "common_callers"):
    _callgraph_mode_command(_mode)


# ---------------------------------------------------------------------------
# search-constants
# ---------------------------------------------------------------------------


@main.group("constants", help="Search constants (search-constants): specific, range, common")
def constants_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:constants_grp")
    pass


@constants_grp.command("run", help="Run search-constants")
@click.option("-b", "--binary", "program_path")
@click.option("--mode", type=click.Choice(["specific", "range", "common"]), required=True)
@click.option("--value")
@click.option("--min-value", "minValue")
@click.option("--max-value", "maxValue")
@click.option("--include-small-values", "includeSmallValues", is_flag=True)
@click.pass_context
def constants_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    value: str | None,
    min_value: str | None,
    max_value: str | None,
    include_small_values: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:constants_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if value is not None:
        payload["value"] = value
    if min_value is not None:
        payload["minValue"] = min_value
    if max_value is not None:
        payload["maxValue"] = max_value
    payload["includeSmallValues"] = include_small_values
    _run_async(_call(ctx, Tool.SEARCH_CONSTANTS.value, **payload))


# --- Convenience subcommands (``constants specific``, ``constants range``, …) ---


def _constants_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``constants <mode>`` shorthand subcommands."""

    @constants_grp.command(mode_name, help=help_text or f"search-constants mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--value")
    @click.option("--min-value", "minValue")
    @click.option("--max-value", "maxValue")
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        value: str | None,
        min_value: str | None,
        max_value: str | None,
    ) -> None:
        payload: dict[str, Any] = {"mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if value is not None:
            payload["value"] = value
        if min_value is not None:
            payload["minValue"] = min_value
        if max_value is not None:
            payload["maxValue"] = max_value
        _run_async(_call(ctx, Tool.SEARCH_CONSTANTS.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_constants_mode_command")
    return _cmd


for _mode in ("specific", "range", "common"):
    _constants_mode_command(_mode)


# ---------------------------------------------------------------------------
# analyze-vtables
# ---------------------------------------------------------------------------


@main.group("vtables", help="Analyze vtables (analyze-vtables): analyze, callers, containing")
def vtables_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:vtables_grp")
    pass


@vtables_grp.command("run", help="Run analyze-vtables")
@click.option("-b", "--binary", "program_path")
@click.option("--mode", type=click.Choice(["analyze", "callers", "containing"]), required=True)
@click.option("--vtable-address", "vtableAddress")
@click.option("--function-address", "functionAddress")
@click.option("--max-entries", "maxEntries", type=int)
@click.pass_context
def vtables_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    vtable_address: str | None,
    function_address: str | None,
    max_entries: int | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:vtables_run")
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if vtable_address is not None:
        payload["vtableAddress"] = vtable_address
    if function_address is not None:
        payload["functionAddress"] = function_address
    if max_entries is not None:
        payload["maxEntries"] = max_entries
    _run_async(_call(ctx, Tool.ANALYZE_VTABLES.value, **payload))


# --- Convenience subcommands (``vtables analyze``, ``vtables callers``, …) ---


def _vtables_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``vtables <mode>`` shorthand subcommands."""

    @vtables_grp.command(mode_name, help=help_text or f"analyze-vtables mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--vtable-address", "vtableAddress")
    @click.option("--function-address", "functionAddress")
    @click.option("--max-entries", "maxEntries", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        vtable_address: str | None,
        function_address: str | None,
        max_entries: int | None,
    ) -> None:
        payload: dict[str, Any] = {"mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if vtable_address is not None:
            payload["vtableAddress"] = vtable_address
        if function_address is not None:
            payload["functionAddress"] = function_address
        if max_entries is not None:
            payload["maxEntries"] = max_entries
        _run_async(_call(ctx, Tool.ANALYZE_VTABLES.value, **payload))

    logger.debug("diag.enter %s", "cli.py:_vtables_mode_command")
    return _cmd


for _mode in ("analyze", "callers", "containing"):
    _vtables_mode_command(_mode)


# ---------------------------------------------------------------------------
# suggest
# ---------------------------------------------------------------------------


@main.command("suggest", help="Context-aware suggestions (suggest): comments, names, tags, types")
@click.option("-b", "--binary", "program_path")
@click.option("--suggestion-type", "suggestionType", required=True)
@click.option("--address")
@click.option("--function")
@click.option("--data-type", "dataType")
@click.option("--variable-address", "variableAddress")
@click.pass_context
def suggest_cmd(
    ctx: click.Context,
    program_path: str | None,
    suggestion_type: str,
    address: str | None,
    function: str | None,
    data_type: str | None,
    variable_address: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:suggest_cmd")
    payload: dict[str, Any] = {
        "suggestionType": suggestion_type,
    }
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if address is not None:
        payload["address"] = address
    if function is not None:
        payload["function"] = function
    if data_type is not None:
        payload["dataType"] = data_type
    if variable_address is not None:
        payload["variableAddress"] = variable_address
    _run_async(_call(ctx, Tool.SUGGEST.value, **payload))


# ---------------------------------------------------------------------------
# Project: checkin, analyze, change-processor, manage-files, get-current-*, open-in-code-browser
# ---------------------------------------------------------------------------


@main.command(
    "checkin",
    help="Checkin program (checkin-program). Omit --binary to check in every open program that is checked out (checkin all).",
)
@click.option("-b", "--binary", "program_path", default=None, help="Program path to check in. Omit to check in all open programs that can be checked in.")
@click.option("-m", "--message", "comment", default=None, help="Checkin comment (default: 'AgentDecompile checkin').")
@click.option("--keep-checked-out", "keepCheckedOut", is_flag=True)
@click.pass_context
def checkin(
    ctx: click.Context,
    program_path: str | None,
    comment: str | None,
    keep_checked_out: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:checkin")
    payload: dict[str, Any] = {"keepCheckedOut": keep_checked_out}
    if comment is not None:
        payload["comment"] = comment
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path.strip()
    # Omit programPath to check in all open programs (checkin all)
    _run_async(_call(ctx, Tool.CHECKIN_PROGRAM.value, **payload))


@main.command("analyze", help="Run auto-analysis (analyze-program)")
@click.option("-b", "--binary", "program_path")
@click.option("--force", is_flag=True, help="Force re-analysis even if the program is already analyzed")
@click.pass_context
def analyze(ctx: click.Context, program_path: str | None, force: bool) -> None:
    logger.debug("diag.enter %s", "cli.py:analyze")
    payload: dict[str, Any] = {}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if force:
        payload["force"] = True
    _run_async(_call(ctx, Tool.ANALYZE_PROGRAM.value, **payload))


@main.command("change-processor", help="Change processor (change-processor)")
@click.option("-b", "--binary", "program_path")
@click.option("--language-id", "languageId", required=True)
@click.option("--compiler-spec-id", "compilerSpecId")
@click.pass_context
def change_processor(
    ctx: click.Context,
    program_path: str | None,
    language_id: str,
    compiler_spec_id: str | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:change_processor")
    payload: dict[str, Any] = {"languageId": language_id}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if compiler_spec_id is not None:
        payload["compilerSpecId"] = compiler_spec_id
    _run_async(_call(ctx, Tool.CHANGE_PROCESSOR.value, **payload))


@main.group("files", help="Manage files/repositories (manage-files): list, info, create, edit, move, import/export, checkout")
def files_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:files_grp")
    pass


@files_grp.command("run", help="Run manage-files with --operation")
@click.option(
    "--operation",
    type=click.Choice(
        [
            "import",
            "export",
            "download-shared",
            "pull-shared",
            "push-shared",
            "sync-shared",
            "checkout",
            "uncheckout",
            "unhijack",
            "list",
            "info",
            "mkdir",
            "touch",
            "read",
            "write",
            "append",
            "rename",
            "delete",
            "copy",
            "move",
        ],
    ),
    required=True,
)
@click.option("--path")
@click.option("--source-path", "source_path")
@click.option("-b", "--binary", "program_path")
@click.option("--mode", type=click.Choice(["pull", "push", "bidirectional"]))
@click.option("--new-path", "new_path")
@click.option("--new-name", "new_name")
@click.option("--content")
@click.option("--encoding", default="utf-8")
@click.option("--create-parents/--no-create-parents", "create_parents", default=True)
@click.option("--destination-folder", "destination_folder", default="/")
@click.option("--recursive/--no-recursive", default=True)
@click.option("--max-depth", "max_depth", type=int)
@click.option("--analyze-after-import/--no-analyze-after-import", "analyze_after_import", default=True)
@click.option("--strip-leading-path/--no-strip-leading-path", "strip_leading_path", default=True)
@click.option("--strip-all-container-path", "strip_all_container_path", is_flag=True)
@click.option("--mirror-fs", "mirror_fs", is_flag=True)
@click.option("--enable-version-control/--no-enable-version-control", "enable_version_control", default=False)
@click.option("--export-type", "export_type", type=click.Choice(["program", "function_info", "strings"]))
@click.option("--export-format", "export_format", type=click.Choice(["json", "csv"]))
@click.option("--include-parameters", "include_parameters", is_flag=True)
@click.option("--include-variables", "include_variables", is_flag=True)
@click.option("--include-comments", "include_comments", is_flag=True)
@click.option("--keep", is_flag=True)
@click.option("--force", is_flag=True)
@click.option("--exclusive", is_flag=True)
@click.option("--dry-run", "dry_run", is_flag=True)
@click.pass_context
def files_run(
    ctx: click.Context,
    operation: str,
    path: str | None,
    source_path: str | None,
    program_path: str | None,
    mode: str | None,
    new_path: str | None,
    new_name: str | None,
    content: str | None,
    encoding: str,
    create_parents: bool,
    destination_folder: str,
    recursive: bool,
    max_depth: int | None,
    analyze_after_import: bool,
    strip_leading_path: bool,
    strip_all_container_path: bool,
    mirror_fs: bool,
    enable_version_control: bool,
    export_type: str | None,
    export_format: str | None,
    include_parameters: bool,
    include_variables: bool,
    include_comments: bool,
    keep: bool,
    force: bool,
    exclusive: bool,
    dry_run: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:files_run")
    payload: dict[str, Any] = {"operation": operation}
    if path is not None:
        payload["path"] = path
    if source_path is not None:
        payload["sourcePath"] = source_path
    if program_path is not None:
        payload["programPath"] = program_path
    if mode is not None:
        payload["mode"] = mode
    if new_path is not None:
        payload["newPath"] = new_path
    if new_name is not None:
        payload["newName"] = new_name
    if content is not None:
        payload["content"] = content
    payload["encoding"] = encoding
    payload["createParents"] = create_parents
    payload["destinationFolder"] = destination_folder
    payload["recursive"] = recursive
    if max_depth is not None:
        payload["maxDepth"] = max_depth
    payload["analyzeAfterImport"] = analyze_after_import
    payload["stripLeadingPath"] = strip_leading_path
    payload["stripAllContainerPath"] = strip_all_container_path
    payload["mirrorFs"] = mirror_fs
    payload["enableVersionControl"] = enable_version_control
    if export_type is not None:
        payload["exportType"] = export_type
    if export_format is not None:
        payload["format"] = export_format
    payload["includeParameters"] = include_parameters
    payload["includeVariables"] = include_variables
    payload["includeComments"] = include_comments
    payload["keep"] = keep
    payload["force"] = force
    payload["exclusive"] = exclusive
    payload["dryRun"] = dry_run
    _run_async(_call(ctx, Tool.MANAGE_FILES.value, **payload))


@main.group("shared", help="Shared repository workflows")
def shared_grp() -> None:
    logger.debug("diag.enter %s", "cli.py:shared_grp")
    pass


@shared_grp.command("download", help="Pull shared repository files into local project storage")
@click.option("--source", "source_path", default="/", show_default=True, help="Shared repository folder/path to download")
@click.option("--destination", "destination_path", default="/", show_default=True, help="Destination folder in local project")
@click.option("--recursive/--no-recursive", default=True, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite existing local project files")
@click.option("--dry-run", is_flag=True, help="Preview changes without copying")
@click.pass_context
def shared_download(
    ctx: click.Context,
    source_path: str,
    destination_path: str,
    recursive: bool,
    force: bool,
    dry_run: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:shared_download")
    payload: dict[str, Any] = {
        "mode": "pull",
        "path": source_path,
        "newPath": destination_path,
        "recursive": recursive,
        "force": force,
        "dryRun": dry_run,
    }
    _run_async(_call(ctx, Tool.SYNC_PROJECT.value, **payload))


@shared_grp.command("push", help="Push local project files toward shared-backed storage mapping")
@click.option("--source", "source_path", default="/", show_default=True, help="Local project source folder/path")
@click.option("--destination", "destination_path", default="/", show_default=True, help="Destination mapping path")
@click.option("--recursive/--no-recursive", default=True, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite destination items")
@click.option("--dry-run", is_flag=True, help="Preview changes without copying")
@click.pass_context
def shared_push(
    ctx: click.Context,
    source_path: str,
    destination_path: str,
    recursive: bool,
    force: bool,
    dry_run: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:shared_push")
    payload: dict[str, Any] = {
        "mode": "push",
        "path": source_path,
        "newPath": destination_path,
        "recursive": recursive,
        "force": force,
        "dryRun": dry_run,
    }
    _run_async(_call(ctx, Tool.SYNC_PROJECT.value, **payload))


@shared_grp.command("sync", help="Bidirectional shared/local synchronization")
@click.option("--source", "source_path", default="/", show_default=True, help="Scope source folder/path")
@click.option("--destination", "destination_path", default="/", show_default=True, help="Scope destination mapping")
@click.option("--recursive/--no-recursive", default=True, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite destination items")
@click.option("--dry-run", is_flag=True, help="Preview changes without copying")
@click.pass_context
def shared_sync(
    ctx: click.Context,
    source_path: str,
    destination_path: str,
    recursive: bool,
    force: bool,
    dry_run: bool,
) -> None:
    logger.debug("diag.enter %s", "cli.py:shared_sync")
    payload: dict[str, Any] = {
        "mode": "bidirectional",
        "path": source_path,
        "newPath": destination_path,
        "recursive": recursive,
        "force": force,
        "dryRun": dry_run,
    }
    _run_async(_call(ctx, Tool.SYNC_PROJECT.value, **payload))


def _gui_only_command_error(tool_name: str) -> None:
    """Handle GUI-only commands by displaying an error and exiting.

    Consolidates the repeated pattern of GUI-only tool error handling
    to reduce code duplication and improve maintainability.

    Args:
        tool_name: The name of the GUI-only tool that was requested
    """
    logger.debug("diag.enter %s", "cli.py:_gui_only_command_error")
    click.echo(f"Tool '{tool_name}' is disabled (GUI-only).", err=True)
    sys.exit(1)


# TODO: GUI Only tools/commands
@main.command("current-address", help="Get current address (get-current-address, GUI)")
@click.pass_context
def current_address(ctx: click.Context) -> None:
    logger.debug("diag.enter %s", "cli.py:current_address")
    _gui_only_command_error("get-current-address")


# TODO: GUI Only tools/commands
@main.command("current-function", help="Get current function (get-current-function, GUI)")
@click.pass_context
def current_function(ctx: click.Context) -> None:
    logger.debug("diag.enter %s", "cli.py:current_function")
    _gui_only_command_error("get-current-function")


# TODO: GUI Only tools/commands
@main.command("open-in-code-browser", help="Open program in Code Browser (open-program-in-code-browser, GUI)")
@click.option("-b", "--binary", "program_path")
@click.pass_context
def open_in_code_browser(ctx: click.Context, program_path: str | None) -> None:
    logger.debug("diag.enter %s", "cli.py:open_in_code_browser")
    _gui_only_command_error("open-program-in-code-browser")


# TODO: GUI Only tools/commands
@main.command("open-all-in-code-browser", help="Open all programs matching extensions in Code Browser (open-all-programs-in-code-browser, GUI)")
@click.option("--extensions", default="exe,dll", help="Comma-separated file extensions to open (default: exe,dll)")
@click.option("--folder-path", "folderPath", default="/", help="Project folder to search (default: /)")
@click.pass_context
def open_all_in_code_browser(
    ctx: click.Context,
    extensions: str,
    folder_path: str,
) -> None:
    logger.debug("diag.enter %s", "cli.py:open_all_in_code_browser")
    _gui_only_command_error("open-all-programs-in-code-browser")


# ---------------------------------------------------------------------------
# delete (stub)
# ---------------------------------------------------------------------------


@main.command("delete", help="Delete program (not implemented in AgentDecompile)")
@click.option("-b", "--binary", "program_path")
def delete_cmd(program_path: str | None) -> None:
    logger.debug("diag.enter %s", "cli.py:delete_cmd")
    click.echo("Delete program is not implemented in AgentDecompile.", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Convenience aliases
# ---------------------------------------------------------------------------


@main.command("import", help="Import a binary into the project (open with path)")
@click.argument("path", type=click.Path(exists=False))
@click.option("--no-analyze", is_flag=True, help="Skip analysis after import")
@click.pass_context
def import_cmd(ctx: click.Context, path: str, no_analyze: bool) -> None:
    logger.debug("diag.enter %s", "cli.py:import_cmd")
    opts = ctx.ensure_object(dict)
    host = opts.get("host", "127.0.0.1")
    is_remote = host not in ("127.0.0.1", "localhost", "::1")
    # Only resolve path locally when connecting to a local server;
    # for remote servers the path refers to the remote filesystem.
    resolved_path = path if is_remote else str(Path(path).resolve())
    _run_async(
        _call(
            ctx,
            Tool.OPEN.value,
            path=resolved_path,
            analyzeAfterImport=not no_analyze,
        ),
    )


# Alias for import-binary compatibility (Click's command() treats second positional as cls)
main.add_command(main.commands["import"], "import-binary")


@main.command("read", help="Read bytes at address (inspect-memory mode=read)")
@click.option("-b", "--binary", "program_path")
@click.argument("address")
@click.option("-s", "--size", "length", type=int, default=32)
@click.pass_context
def read_cmd(ctx: click.Context, program_path: str | None, address: str, length: int) -> None:
    logger.debug("diag.enter %s", "cli.py:read_cmd")
    kwargs: dict[str, Any] = {"mode": "read", "address": address, "length": length}
    if program_path is not None and program_path.strip():
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, Tool.INSPECT_MEMORY.value, **kwargs))


@main.command(
    "svr-admin",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    help=("Run bundled Ghidra svrAdmin with full passthrough. Use --arg repeatedly or pass raw trailing tokens after '--'."),
)
@click.option("--arg", "args", multiple=True, help="Raw token forwarded to svrAdmin (repeatable).")
@click.option("--command", help="Optional command string tokenized server-side and appended.")
@click.option("--timeout-seconds", type=int, default=None, help="Timeout for svrAdmin execution in seconds.")
@click.pass_context
def svr_admin_cmd(
    ctx: click.Context,
    args: tuple[str, ...],
    command: str | None,
    timeout_seconds: int | None,
) -> None:
    logger.debug("diag.enter %s", "cli.py:svr_admin_cmd")
    payload = _build_svr_admin_payload(args, list(ctx.args), command, timeout_seconds)
    _run_async(_call(ctx, Tool.SVR_ADMIN.value, **payload))


# Compatibility alias for canonical `svr-admin`.
main.add_command(main.commands["svr-admin"], "svrAdmin")


# ---------------------------------------------------------------------------
# eval – execute arbitrary Ghidra/PyGhidra API code (execute-script)
# ---------------------------------------------------------------------------


@main.command(
    "eval",
    help=("Execute Ghidra/PyGhidra API code on the server. The full Ghidra API is available (currentProgram, flatApi, toAddr, …). Example: eval -b /myapp 'currentProgram.getName()'"),
)
@click.argument("code")
@click.option(
    "-b",
    "--binary",
    "program_path",
    help="Program path in the project",
)
@click.option(
    "--timeout",
    type=int,
    default=30,
    show_default=True,
    help="Max execution time in seconds",
)
@click.pass_context
def eval_cmd(ctx: click.Context, code: str, program_path: str | None, timeout: int) -> None:
    """Execute arbitrary Ghidra/PyGhidra Python code on the MCP server.

    The code runs in a namespace with the full Ghidra API pre-imported:
    currentProgram, flatApi, monitor, toAddr(), getFunctionManager(), etc.

    Use __result__ to explicitly set the return value, or simply write an
    expression (it will be eval'd and returned automatically).

    \b
    Examples:
      eval -b /myapp 'currentProgram.getName()'
      eval -b /myapp 'currentProgram.getLanguage().getLanguageID()'
      eval -b /myapp 'len(list(currentProgram.getFunctionManager().getFunctions(True)))'
      eval -b /myapp 'list(currentProgram.getMemory().getBlocks())'
      eval -b /myapp 'fm=getFunctionManager(); __result__=[str(f) for f in fm.getFunctions(True)][:10'
    """
    logger.debug("diag.enter %s", "cli.py:eval_cmd")
    kwargs: dict[str, Any] = {"code": code, "timeout": timeout}
    if program_path:
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, Tool.EXECUTE_SCRIPT.value, **kwargs))


# ---------------------------------------------------------------------------
# Generic tool call (any MCP tool by name + JSON args)
# ---------------------------------------------------------------------------


@main.command("alias", help="Show alias/overload mappings and signatures for a tool name.")
@click.argument("name", required=True)
def alias_cmd(name: str) -> None:
    """Show alias details for a canonical or alias tool name."""
    logger.debug("diag.enter %s", "cli.py:alias_cmd")
    resolved = tool_registry.resolve_tool_name(name)
    if not resolved:
        click.echo(f"Unknown tool or alias: {name}", err=True)
        sys.exit(1)

    canonical = resolved
    canonical_sig = _tool_signature(canonical)
    click.echo(f"Canonical: {canonical}")
    click.echo(f"  Signature: {canonical_sig}")

    aliases = _tool_aliases_for(canonical)
    if not aliases:
        click.echo("Aliases: none")
        return

    different_signatures: list[tuple[str, str]] = []
    same_signature_aliases: list[str] = []
    for alias in aliases:
        alias_sig = _tool_signature(alias)
        if alias_sig != canonical_sig:
            different_signatures.append((alias, alias_sig))
        else:
            same_signature_aliases.append(alias)

    if different_signatures:
        click.echo("Aliases with different signatures:")
        for alias, signature in different_signatures:
            click.echo(f"  - {alias}")
            click.echo(f"      Signature: {signature}")

    if same_signature_aliases:
        click.echo("Aliases with identical signatures (hidden from main help):")
        for alias in same_signature_aliases:
            click.echo(f"  - {alias}")


@main.command("tool", help='Call any MCP tool by name with JSON arguments. Example: tool get-data \'{"programPath":"/a","addressOrSymbol":"0x1000"}\'')
@click.argument("name", required=False, default=None)
@click.argument("arguments", required=False, default="{}")
@click.option("--list-tools", is_flag=True, help="List valid tool names and exit")
@click.option(
    "--program-path",
    "--programpath",
    "--programPath",
    "--program",
    "-b",
    "--binary",
    expose_value=False,
    callback=_cli_program_path_option_callback,
    help="Default programPath when JSON omits it (may appear after `tool`, before NAME).",
)
@click.option(
    "--binary-name",
    "--binaryname",
    "--binaryName",
    expose_value=False,
    callback=_cli_binary_name_option_callback,
    help="Default binaryName when JSON omits it.",
)
@click.pass_context
def tool_cmd(
    ctx: click.Context,
    name: str | None,
    arguments: str,
    list_tools: bool,
) -> None:
    """Invoke any MCP tool by name; arguments as JSON object (camelCase keys)."""
    logger.debug("diag.enter %s", "cli.py:tool_cmd")
    available_tools = tool_registry.get_tools()
    if list_tools:
        click.echo("Valid tool names:")
        for t in sorted(available_tools):
            click.echo(f"  {t}")
        return

    if not name:
        raise click.UsageError("Missing argument 'NAME'. Use --list-tools to see valid tool names.")

    payload = _parse_tool_payload(arguments)
    _validate_known_tool(name)

    async def _run() -> None:
        prepared_payload, inferred_program = _prepare_tool_payload_with_program_fallback(ctx, name, payload)
        data = await _call_raw(ctx, name, prepared_payload)
        err_msg = _get_error_result_message(data)
        if err_msg is not None:
            click.echo(err_msg, err=True)
            sys.exit(1)
        display_data = _inject_inferred_program(data, inferred_program)

        if isinstance(display_data, dict):
            nested_json: Any | None = None
            content = display_data.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        nested = _safe_json_loads(item.get("text"))
                        if isinstance(nested, (dict, list)):
                            nested_json = nested
                            break
            if nested_json is not None:
                click.echo(format_output(nested_json, "json"))
                return

        click.echo(format_output(display_data, _fmt(ctx)))

    _run_async(_run())


def _load_tool_seq_steps_arg(steps: str) -> str:
    """If steps starts with ``@path``, read JSON from that file (shell-friendly on Windows).

    PowerShell/CMD often pass ``@C:\\temp\\steps.json`` literally; ``json.loads`` would fail on ``@``.
    """
    logger.debug("diag.enter %s", "cli.py:_load_tool_seq_steps_arg")
    raw = (steps or "").strip()
    if not raw.startswith("@"):
        return steps
    path_str = raw[1:].strip().strip('"').strip("'")
    if not path_str:
        return steps
    path = Path(path_str).expanduser()
    if not path.is_file():
        click.echo(f"tool-seq: steps file not found: {path}", err=True)
        sys.exit(1)
    return path.read_text(encoding="utf-8")


@main.command(
    "tool-seq",
    help=('Run a sequence of MCP tool calls from JSON. Format: [{"name":"open","arguments":{...}}, ...]. Prefix the argument with @path to load steps from a UTF-8 file (recommended from PowerShell). Steps also fail on markdown ## Error / ## Modification conflict in text content (even if isError is false).'),
)
@click.argument("steps", required=True)
@click.option(
    "--continue-on-error",
    is_flag=True,
    help="Continue remaining steps after a step failure; exit code is still non-zero if any step failed.",
)
@click.option(
    "--program-path",
    "--programpath",
    "--programPath",
    "--program",
    "-b",
    "--binary",
    expose_value=False,
    callback=_cli_program_path_option_callback,
    help="Default programPath for steps that omit it.",
)
@click.option(
    "--binary-name",
    "--binaryname",
    "--binaryName",
    expose_value=False,
    callback=_cli_binary_name_option_callback,
    help="Default binaryName for steps that omit it.",
)
@click.pass_context
def tool_seq_cmd(ctx: click.Context, steps: str, continue_on_error: bool) -> None:
    """Invoke a sequence of tools without using ad-hoc python scripts.

    A step fails if the MCP response has isError, embedded JSON with success:false and error,
    or markdown text with ## Error (blockquote-style) or ## Modification conflict.
    Exits with code 1 when any step fails (unless the process already exited on the first failure).
    """
    logger.debug("diag.enter %s", "cli.py:tool_seq_cmd")
    steps = _load_tool_seq_steps_arg(steps)
    try:
        parsed_steps = json.loads(steps)
    except json.JSONDecodeError as exc:
        click.echo(f"Invalid JSON for steps: {exc}", err=True)
        sys.exit(1)

    if not isinstance(parsed_steps, list) or not all(isinstance(s, dict) for s in parsed_steps):
        click.echo("Steps must be a JSON array of objects.", err=True)
        sys.exit(1)

    async def _run_sequence() -> None:
        results: list[dict[str, Any]] = []
        client = _client(ctx)
        async with client:
            step: dict[str, Any]
            for index, step in enumerate(parsed_steps, start=1):
                name = step.get("name")
                arguments = step.get("arguments", {})

                if not isinstance(name, str) or not name.strip():
                    click.echo(f"Step {index}: missing or invalid 'name'", err=True)
                    sys.exit(1)
                if not isinstance(arguments, dict):
                    click.echo(f"Step {index}: 'arguments' must be a JSON object", err=True)
                    sys.exit(1)

                _validate_known_tool(name)
                prepared_arguments: dict[str, Any] = {k: v for k, v in arguments.items() if v is not None}
                if tool_registry.is_valid_tool(name):
                    resolved_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(name))
                    prepared_arguments = tool_registry.parse_arguments(prepared_arguments, resolved_name)
                # For open, merge global Ghidra server options so tool-seq sends credentials
                if tool_registry.canonicalize_tool_name(name) == tool_registry.canonicalize_tool_name(Tool.OPEN.value):
                    opts = _get_opts(ctx)
                    # Ensure we have root/group opts (tool-seq runs as subcommand; ctx.obj may be unset)
                    if not opts and ctx.parent and isinstance(getattr(ctx.parent, "obj", None), dict):
                        opts = ctx.parent.obj or {}

                    # Fallback to env so credentials are sent even when opts not propagated
                    def _g(k: str, *alt: str) -> Any:
                        for key in (k, *alt):
                            v = (opts or {}).get(key)
                            if v is not None and str(v).strip() != "":
                                return v
                        return None

                    if not prepared_arguments.get("serverUsername"):
                        v = _g("ghidra_server_username", "server_username") or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME")
                        if v:
                            prepared_arguments["serverUsername"] = str(v).strip()
                    if not prepared_arguments.get("serverPassword"):
                        v = _g("ghidra_server_password", "server_password") or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD")
                        if v:
                            prepared_arguments["serverPassword"] = str(v).strip()
                    if not prepared_arguments.get("serverHost"):
                        v = _g("ghidra_server_host", "server_host") or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_HOST")
                        if v:
                            prepared_arguments["serverHost"] = str(v).strip()
                    if prepared_arguments.get("serverPort") is None:
                        v = _g("ghidra_server_port", "server_port")
                        if v is not None:
                            prepared_arguments["serverPort"] = int(v)
                        else:
                            p = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PORT")
                            if p:
                                try:
                                    prepared_arguments["serverPort"] = int(p)
                                except ValueError:
                                    pass
                    if not prepared_arguments.get("repositoryName"):
                        v = _g("ghidra_server_repository", "server_repository") or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY")
                        if v:
                            prepared_arguments["repositoryName"] = str(v).strip()
                            if not prepared_arguments.get("path"):
                                prepared_arguments["path"] = str(v).strip()

                data = await _call_raw(ctx, name, prepared_arguments, client_override=client)
                step_ok = _tool_seq_step_succeeded(data)
                step_result = {
                    "index": index,
                    "name": name,
                    "success": step_ok,
                    "result": data,
                }
                results.append(step_result)

                if not step_ok and not continue_on_error:
                    click.echo(format_output({"success": False, "steps": results}, _fmt(ctx)))
                    sys.exit(1)

        all_ok = all(step["success"] for step in results)
        click.echo(format_output({"success": all_ok, "steps": results}, _fmt(ctx)))
        if not all_ok:
            sys.exit(1)

    _run_async(_run_sequence())


# ---------------------------------------------------------------------------
# Entry (click group is invoked directly)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _ensure_dynamic_commands_registered()
    main()


# Register dynamic commands for normal CLI invocation paths as well
# (important for subcommand resolution before main() callback runs).
_ensure_dynamic_commands_registered()
_register_output_format_option_on_all_commands(main)


def cli_entry_point() -> None:
    """Entry point for the CLI (referenced by pyproject.toml scripts)."""
    logger.debug("diag.enter %s", "cli.py:cli_entry_point")
    _ensure_dynamic_commands_registered()
    main()
