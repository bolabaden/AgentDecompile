"""Server and proxy entry points with project initialization and transport selection.

agentdecompile-server (main()): Local MCP server only. Always starts PyGhidra/JVM and serves
from a local project. Supports project path (.gpr or directory), transport (stdio or
streamable-http/sse/http), list/delete project binaries, and import binaries before serving.
For forwarding to a remote MCP backend without local Ghidra, use agentdecompile-proxy instead.

agentdecompile-proxy (proxy_main()): Forward MCP to a remote backend. No local PyGhidra/JVM.
Requires backend URL via --backend-url, --mcp-server-url, or env AGENT_DECOMPILE_MCP_SERVER_URL
/ AGENTDECOMPILE_MCP_SERVER_URL.

Environment (1:1 with Python AgentDecompileLauncher / ConfigManager) for agentdecompile-server:
- AGENT_DECOMPILE_PROJECT_PATH: Path to a .gpr file or to a project directory location
- AGENT_DECOMPILE_HOST: Server bind host (applied when no config file)
- AGENT_DECOMPILE_PORT: Server port (applied when no config file)
- AGENT_DECOMPILE_SERVER_USERNAME, AGENT_DECOMPILE_SERVER_PASSWORD: Shared project auth
- AGENT_DECOMPILE_SERVER_HOST, AGENT_DECOMPILE_SERVER_PORT: Ghidra server for shared projects
- AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY / AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY, etc.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentdecompile_cli.executor import normalize_backend_url
from agentdecompile_cli.launcher import AgentDecompileLauncher
from agentdecompile_cli.mcp_server.auth import AuthConfig
from agentdecompile_cli.project_manager import ProjectManager
from agentdecompile_cli.registry import Tool
from agentdecompile_cli.utils import get_client, run_async

if TYPE_CHECKING:
    from mcp.client.session import ClientSession

logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

_HTTP_TRANSPORTS: frozenset[str] = frozenset({"streamable-http", "http", "sse"})


def init_agentdecompile_context(
    *,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    project_path_gpr: Path | None,
    force_analysis: bool = False,
    verbose_analysis: bool = False,
    no_symbols: bool = False,
    gdts: list[str] | None = None,
    program_options_path: str | None = None,
    gzfs_path: str | None = None,
    threaded: bool = True,
    max_workers: int = 0,
    wait_for_analysis: bool = False,
    list_project_binaries: bool = False,
    delete_project_binary: str | None = None,
    symbols_path: str | None = None,
    sym_file_path: str | None = None,
    port: int | None = None,
    host: str | None = None,
    config_file: Path | None = None,
    auth_config: AuthConfig | None = None,
    tls_certfile: str | None = None,
    tls_keyfile: str | None = None,
) -> tuple[AgentDecompileLauncher, ProjectManager | None]:
    """Initialize AgentDecompile: project resolution, PyGhidra, launcher, optional list/delete/import.

    When project_path_gpr is set (a .gpr file), sets AGENT_DECOMPILE_PROJECT_PATH so the
    launcher uses that project. Otherwise uses project_directory and project_name for
    an ephemeral or directory-based project.

    If list_project_binaries is True, lists programs via MCP and exits (does not return).
    If delete_project_binary is set, attempts to remove that program and exits (does not return).

    Returns (launcher, project_manager). project_manager is only set when not using a .gpr.
    """
    bin_paths: list[Path] = [Path(p) for p in input_paths]
    logger.info("Project: %s", project_name)
    logger.info("Project location: %s", project_directory)

    if project_path_gpr is not None and project_path_gpr.suffix.lower() == ".gpr":
        os.environ["AGENT_DECOMPILE_PROJECT_PATH"] = str(project_path_gpr.resolve())

    # Launcher is started by the caller after PyGhidra is initialized (see main()).
    # We only compute launcher args here; actual start happens in main() after pyghidra.start().
    use_random_port: bool = port is None
    launcher = AgentDecompileLauncher(config_file=config_file, use_random_port=use_random_port)
    project_manager: ProjectManager | None = None
    if not (os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")):
        project_manager = ProjectManager()

    # Start the server (caller must have called pyghidra.start() before)
    started_port: int = launcher.start(
        port=port,
        host=host,
        project_directory=project_directory if project_path_gpr is None else None,
        project_name=project_name if project_path_gpr is None else None,
        auth_config=auth_config,
        tls_certfile=tls_certfile,
        tls_keyfile=tls_keyfile,
    )

    async def _list_and_exit() -> None:
        client = get_client(host="127.0.0.1", port=started_port)
        async with client:
            try:
                result = await client.read_resource("ghidra://programs")
                contents = getattr(result, "contents", None) or []
                for c in contents:
                    text = getattr(c, "text", None)
                    if text:
                        data = json.loads(text) if isinstance(text, str) else text
                        programs = data if isinstance(data, list) else (data.get("programs") if isinstance(data, dict) else [])
                        if isinstance(programs, list) and programs:
                            sys.stderr.write("Project programs:\n")
                            for p in programs:
                                name = p.get("programPath", p.get("name", p)) if isinstance(p, dict) else p
                                sys.stderr.write(f"  - {name}\n")
                            sys.exit(0)
                sys.stderr.write("No programs in project.\n")
            except Exception as e:
                sys.stderr.write(f"Error listing programs: {e.__class__.__name__}: {e}\n")
            sys.exit(0)

    if list_project_binaries:
        run_async(_list_and_exit())

    if delete_project_binary:

        async def _delete_and_exit() -> None:
            sys.stderr.write(
                "Delete program is not implemented via CLI; use MCP tools or Ghidra UI.\n",
            )
            sys.exit(0)

        run_async(_delete_and_exit())

    if bin_paths:
        logger.info("Importing binaries: %s", ", ".join(str(p) for p in bin_paths))

        async def _import_binaries() -> None:
            client: ClientSession = get_client(host="127.0.0.1", port=started_port)
            async with client:
                for path in bin_paths:
                    try:
                        await client.call_tool(Tool.OPEN_PROJECT.value, {"path": str(path.resolve()), "runAnalysis": True})
                        sys.stderr.write(f"Imported: {path}\n")
                    except Exception as e:
                        sys.stderr.write(f"Import failed for {path}: {e.__class__.__name__}: {e}\n")

        run_async(_import_binaries())

    if wait_for_analysis:
        # Optional: wait a few seconds for analysis to progress (server is already up)
        time.sleep(5)

    return launcher, project_manager


def _env_port() -> int:
    """Default port from AGENT_DECOMPILE_PORT (1:1 Java applyHeadlessServerEnvOverrides)."""
    v = os.environ.get("AGENT_DECOMPILE_PORT")
    if not v:
        return 8080
    try:
        p = int(v)
        return p if p > 0 else 8080
    except ValueError:
        return 8080


def _env_host() -> str:
    """Default host from AGENT_DECOMPILE_HOST (1:1 Java applyHeadlessServerEnvOverrides)."""
    return (os.environ.get("AGENT_DECOMPILE_HOST") or "").strip() or "127.0.0.1"


def _resolve_proxy_backend_url(
    explicit_backend_url: str | None,
    explicit_mcp_server_url: str | None = None,
) -> str | None:
    """Resolve proxy backend URL from CLI/env and normalize to /mcp/message.

    Priority: --backend-url > --mcp-server-url > AGENT_DECOMPILE_* env
              > AGENTDECOMPILE_* env (compact form, e.g. AGENTDECOMPILE_MCP_SERVER_URL).
    """
    raw = explicit_backend_url
    if not raw or not raw.strip():
        raw = explicit_mcp_server_url
    if not raw or not raw.strip():
        raw = os.environ.get("AGENT_DECOMPILE_BACKEND_URL") or os.environ.get("AGENT_DECOMPILE_MCP_SERVER_URL") or os.environ.get("AGENT_DECOMPILE_SERVER_URL")
    if not raw or not raw.strip():
        raw = os.environ.get("AGENTDECOMPILE_BACKEND_URL") or os.environ.get("AGENTDECOMPILE_MCP_SERVER_URL") or os.environ.get("AGENTDECOMPILE_SERVER_URL")
    if not raw or not raw.strip():
        return None
    return normalize_backend_url(raw.strip())


def _resolve_default_project_path(project_path_arg: Path) -> Path:
    """Resolve effective default project path for server mode.

    If caller did not override ``--project-path`` (still using
    ``agentdecompile_projects``) and a mounted ``/projects`` directory exists,
    prefer that persistent location so domain storage survives container restarts.
    """
    raw: str = str(project_path_arg).strip()
    is_builtin_default = raw in {"agentdecompile_projects", "./agentdecompile_projects"}
    if not is_builtin_default:
        return project_path_arg

    explicit_default: str = (os.environ.get("AGENT_DECOMPILE_DEFAULT_PROJECT_DIR") or "").strip()
    if explicit_default:
        return Path(explicit_default)

    persistent_root = Path("/projects")
    if persistent_root.exists() and persistent_root.is_dir():
        return persistent_root / "agentdecompile_projects"

    return project_path_arg


def _configure_http_debug_logging(verbose: bool) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.getLogger("httpx").setLevel(level)
    logging.getLogger("httpcore").setLevel(level)


def _configure_logging(verbose: bool) -> None:
    """Configure root and HTTP client logging levels."""
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.WARNING)
    _configure_http_debug_logging(verbose)


class CredentialSanitizer(logging.Filter):
    """Logging filter that redacts registered sensitive strings from all log records."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()

    def register(self, value: str) -> None:
        if value and value.strip():
            self._secrets.add(value.strip())

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        try:
            msg = record.getMessage()
            for secret in self._secrets:
                if secret in msg:
                    record.msg = record.msg.replace(secret, "***") if isinstance(record.msg, str) else record.msg
                    record.args = _redact_args(record.args, secret)
        except Exception:
            pass
        return True


def _redact_args(args: Any, secret: str) -> Any:
    if args is None:
        return args
    if isinstance(args, str):
        return args.replace(secret, "***")
    if isinstance(args, dict):
        return {k: _redact_args(v, secret) for k, v in args.items()}
    if isinstance(args, (list, tuple)):
        redacted = [_redact_args(a, secret) for a in args]
        return type(args)(redacted)
    return args


# Module-level sanitizer — installed once in _set_env_from_args and reused
_credential_sanitizer = CredentialSanitizer()


def _first_non_empty_env(*keys: str) -> str | None:
    for key in keys:
        value = os.environ.get(key)
        if value is not None and value.strip():
            return value.strip()
    return None


def _set_env_if_missing(target: str, *sources: str) -> None:
    current = os.environ.get(target)
    if current is not None and current.strip():
        logger.debug("env-alias: %s already set (value length=%d), skipping sources %s", target, len(current.strip()), sources)
        return
    resolved = _first_non_empty_env(*sources)
    if resolved is not None:
        matched_source = next((k for k in sources if (os.environ.get(k) or "").strip() == resolved), "?")
        # Redact credential values in log output
        _is_sensitive = any(kw in target.upper() for kw in ("PASSWORD", "SECRET", "TOKEN", "KEY"))
        display_val = "***" if _is_sensitive else repr(resolved)
        logger.debug("env-alias: %s ← %s = %s", target, matched_source, display_val)
        os.environ[target] = resolved
    else:
        logger.debug("env-alias: %s not resolved from %s (none set)", target, sources)


def _normalize_shared_server_env_aliases() -> None:
    """Normalize shared-server environment aliases to canonical names.

    Supports both canonical AGENT_DECOMPILE_* variables and compact
    AGENTDECOMPILE_* variants so external MCP launchers can supply either form.
    """
    # Canonical Ghidra-prefixed env vars used by server/launcher/auth logic.
    # Includes AGENTDECOMPILE_HTTP_GHIDRA_SERVER_* variants used by MCP
    # launcher configs (e.g. VS Code mcp.json).
    _set_env_if_missing(
        "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
        "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST",
        "AGENTDECOMPILE_GHIDRA_SERVER_HOST",
        "AGENTDECOMPILE_GHIDRA_HOST",
        "AGENT_DECOMPILE_SERVER_HOST",
        "AGENTDECOMPILE_SERVER_HOST",
    )
    _set_env_if_missing(
        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
        "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT",
        "AGENTDECOMPILE_GHIDRA_SERVER_PORT",
        "AGENTDECOMPILE_GHIDRA_PORT",
        "AGENT_DECOMPILE_SERVER_PORT",
        "AGENTDECOMPILE_SERVER_PORT",
    )
    _set_env_if_missing(
        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
        "AGENTDECOMPILE_GHIDRA_SERVER_USERNAME",
        "AGENTDECOMPILE_GHIDRA_USERNAME",
        "AGENT_DECOMPILE_SERVER_USERNAME",
        "AGENTDECOMPILE_SERVER_USERNAME",
    )
    _set_env_if_missing(
        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
        "AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD",
        "AGENTDECOMPILE_GHIDRA_PASSWORD",
        "AGENT_DECOMPILE_SERVER_PASSWORD",
        "AGENTDECOMPILE_SERVER_PASSWORD",
    )
    _set_env_if_missing(
        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
        "AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY",
        "AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY",
        "AGENTDECOMPILE_GHIDRA_REPOSITORY",
        "AGENT_DECOMPILE_REPOSITORY",
        "AGENTDECOMPILE_REPOSITORY",
    )

    logger.debug("env-alias: canonical Ghidra-prefixed env vars resolved")

    # Mirror canonical values into legacy/non-ghidra names used by bridge paths.
    _set_env_if_missing("AGENT_DECOMPILE_SERVER_HOST", "AGENT_DECOMPILE_GHIDRA_SERVER_HOST")
    _set_env_if_missing("AGENT_DECOMPILE_SERVER_PORT", "AGENT_DECOMPILE_GHIDRA_SERVER_PORT")
    _set_env_if_missing("AGENT_DECOMPILE_SERVER_USERNAME", "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME")
    _set_env_if_missing("AGENT_DECOMPILE_SERVER_PASSWORD", "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD")
    _set_env_if_missing("AGENTDECOMPILE_SERVER_HOST", "AGENT_DECOMPILE_SERVER_HOST")
    _set_env_if_missing("AGENTDECOMPILE_SERVER_PORT", "AGENT_DECOMPILE_SERVER_PORT")
    _set_env_if_missing("AGENTDECOMPILE_SERVER_USERNAME", "AGENT_DECOMPILE_SERVER_USERNAME")
    _set_env_if_missing("AGENTDECOMPILE_SERVER_PASSWORD", "AGENT_DECOMPILE_SERVER_PASSWORD")
    _set_env_if_missing("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "AGENT_DECOMPILE_GHIDRA_SERVER_HOST")
    _set_env_if_missing("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "AGENT_DECOMPILE_GHIDRA_SERVER_PORT")
    _set_env_if_missing("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME", "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME")
    _set_env_if_missing("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD", "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD")
    _set_env_if_missing("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY")
    _set_env_if_missing("AGENT_DECOMPILE_REPOSITORY", "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY")
    _set_env_if_missing("AGENTDECOMPILE_REPOSITORY", "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY")

    # Log summary of resolved shared-server env vars for diagnostics
    _resolved_host = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "").strip()
    _resolved_port = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "").strip()
    _resolved_repo = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
    _resolved_user = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
    _resolved_pass = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
    if _resolved_host or _resolved_port or _resolved_repo or _resolved_user:
        sys.stderr.write(f"[env-normalize] shared server: host={_resolved_host or '(not set)'}, port={_resolved_port or '(not set)'}, repo={_resolved_repo or '(not set)'}, username={'(set)' if _resolved_user else '(not set)'}, password={'(set)' if _resolved_pass else '(not set)'}\n")
    else:
        sys.stderr.write("[env-normalize] No shared Ghidra server env vars detected.\n")


def _set_env_from_args(args: Any) -> None:
    """Populate AGENT_DECOMPILE_* env vars from CLI args when provided.

    Also scrubs credential values from sys.argv and the args namespace so they
    cannot appear in process listings, debug logs, or exception tracebacks, and
    installs a root logging filter that redacts any residual occurrences.
    """
    _SENSITIVE_ARGS = {"ghidra_server_username", "ghidra_server_password"}
    mappings = {
        "ghidra_server_host": "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
        "ghidra_server_port": "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
        "ghidra_server_username": "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
        "ghidra_server_password": "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
        "ghidra_server_repository": "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
    }
    for arg_name, env_name in mappings.items():
        value = getattr(args, arg_name, None)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        os.environ[env_name] = str(value)
        _is_cred = arg_name in _SENSITIVE_ARGS
        sys.stderr.write(f"[cli-args] {env_name} \u2190 --{arg_name.replace('_', '-')} = {'***' if _is_cred else str(value)}\n")
        # Register with sanitizer before clearing from args
        if _is_cred:
            _credential_sanitizer.register(str(value))
        # Overwrite on the namespace so exception dumps don't expose it
        setattr(args, arg_name, None)

    # Scrub sensitive flags and their values from sys.argv
    _scrub_argv(_SENSITIVE_ARGS)

    # Install sanitizer on the root logger (idempotent)
    root_logger = logging.getLogger()
    if _credential_sanitizer not in root_logger.filters:
        root_logger.addFilter(_credential_sanitizer)


def _scrub_argv(sensitive_arg_names: set[str]) -> None:
    """Remove credential flags and their values from sys.argv in-place."""
    # Build the set of CLI flag strings that carry sensitive values.
    # For each name like "ghidra_server_password", generate:
    #   --ghidra-server-password, --ghidra_server_password (current forms)
    #   --ghidra-server-password, --ghidra-server_password (legacy forms, for safety)
    flag_variants: set[str] = set()
    for name in sensitive_arg_names:
        base = name.replace("_", "-")
        flag_variants.update(
            {
                f"--{base}",
                f"--{name}",
            },
        )
        # Also scrub the legacy --server-* form in case it appears in sys.argv
        short = name.replace("ghidra_server_", "")
        flag_variants.update(
            {
                f"--server-{short}",
                f"--server_{short}",
            },
        )

    scrubbed: list[str] = []
    skip_next = False
    for token in sys.argv:
        if skip_next:
            skip_next = False
            continue
        token_key = token.split("=", 1)[0] if "=" in token else token
        if token_key in flag_variants:
            # --flag value  (two-token form)
            if "=" not in token:
                skip_next = True
            # --flag=value  (single-token form) — just drop it
            continue
        scrubbed.append(token)
    sys.argv[:] = scrubbed


def _setup_project_paths(parser: Any, args: Any) -> tuple[str, str, Path | None]:
    """Resolve and validate project path inputs into directory/name/.gpr tuple."""
    project_path = _resolve_default_project_path(args.project_path).resolve()
    sys.stderr.write(f"[project-paths] raw='{args.project_path}' \u2192 resolved='{project_path}' (suffix='{project_path.suffix}', project_name='{args.project_name}')\n")
    if project_path.suffix.lower() == ".gpr":
        if args.project_name != "my_project":
            parser.error("Cannot use --project-name with a .gpr file")
        sys.stderr.write(f"[project-paths] .gpr mode: dir='{project_path.parent}', name='{project_path.stem}'\n")
        return str(project_path.parent), project_path.stem, project_path
    sys.stderr.write(f"[project-paths] directory mode: dir='{project_path}', name='{args.project_name}'\n")
    return str(project_path), args.project_name, None


def _initialize_pyghidra(verbose_analysis: bool) -> None:
    """Initialize PyGhidra and apply session/output patches."""
    from agentdecompile_cli.mcp_session_patch import _apply_mcp_session_fix

    _apply_mcp_session_fix()

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    try:
        from agentdecompile_cli.__main__ import StderrFilter, StdoutFilter, _redirect_java_outputs
    except ImportError:
        StderrFilter = None
        StdoutFilter = None
        _redirect_java_outputs = None

    if StderrFilter is not None and StdoutFilter is not None:
        sys.stderr = StderrFilter(original_stderr)
        sys.stdout = StdoutFilter(original_stdout)

    try:
        sys.stderr.write("Initializing PyGhidra...\n")
        try:
            import pyghidra
        except ImportError:
            sys.stderr.write(
                "PyGhidra is not installed. Install with: pip install 'agentdecompile[local]'\n",
            )
            sys.exit(1)
        pyghidra.start(verbose=verbose_analysis)
        if _redirect_java_outputs:
            _redirect_java_outputs()
        sys.stderr.write("PyGhidra initialized\n")
    except Exception:
        if sys.stdout != original_stdout:
            sys.stdout = original_stdout
        if sys.stderr != original_stderr:
            sys.stderr = original_stderr
        raise


async def _run_stdio_mode(
    launcher: Any | None,
    project_manager: Any | None,
    backend: str | int,
) -> None:
    """Run stdio MCP bridge mode."""
    from agentdecompile_cli.__main__ import AgentDecompileCLI

    cli = AgentDecompileCLI(
        launcher=launcher,
        project_manager=project_manager,
        backend=backend,
    )
    await cli.run()


async def _run_http_mode(host: str, port: int | None) -> None:
    """Run HTTP mode loop after launcher startup."""
    if port is None:
        raise RuntimeError("Launcher did not provide a server port")
    sys.stderr.write(f"AgentDecompile server running at http://{host}:{port}/mcp/message\n")
    sys.stderr.write("Press Ctrl+C to stop.\n")
    while True:
        await asyncio.sleep(3600)


def _cleanup_resources(
    launcher: AgentDecompileLauncher | None,
    project_manager: ProjectManager | None,
) -> None:
    """Release launcher and project manager resources."""
    if launcher:
        launcher.stop()
    if project_manager and hasattr(project_manager, "cleanup"):
        try:
            project_manager.cleanup()
        except Exception:
            pass


def main() -> None:
    """Parse server options and run init + transport."""
    import argparse

    try:
        from agentdecompile_cli import __version__
    except ImportError:
        __version__ = "0.0.0.dev0"

    parser = argparse.ArgumentParser(
        description="AgentDecompile MCP server with project and transport options",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Server options (defaults from env to match Java headless launcher)
    g_server = parser.add_argument_group("Server options")
    g_server.add_argument(
        "-t",
        "--transport",
        choices=["stdio", "streamable-http", "sse", "http"],
        default="stdio",
        help="Transport: stdio (stdio bridge) or HTTP-based (server only)",
    )
    g_server.add_argument(
        "-p",
        "--port",
        "--mcp-server-port",
        type=int,
        default=None,
        help="Port for the MCP server (default: AGENT_DECOMPILE_PORT or 8080)",
    )
    g_server.add_argument(
        "-o",
        "--host",
        type=str,
        default=None,
        help="Host for HTTP transports (default: AGENT_DECOMPILE_HOST or 127.0.0.1)",
    )
    g_server.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose logs (including HTTP request diagnostics)",
    )
    g_server.add_argument(
        "--ghidra-server-host",
        type=str,
        default=None,
        help="Shared Ghidra server host (prefer AGENT_DECOMPILE_GHIDRA_SERVER_HOST in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-port",
        type=int,
        default=None,
        help="Shared Ghidra server port (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PORT in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-username",
        type=str,
        default=None,
        help="Shared Ghidra server username (prefer AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-password",
        type=str,
        default=None,
        help="Shared Ghidra server password (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-repository",
        type=str,
        default=None,
        help="Shared Ghidra repository (prefer AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY in environment)",
    )
    g_server.add_argument(
        "--require-auth",
        dest="require_auth",
        action="store_true",
        default=None,
        help="Require HTTP Basic auth on every MCP request (auto-enabled when --ghidra-server-username is set)",
    )
    g_server.add_argument(
        "--no-require-auth",
        dest="require_auth",
        action="store_false",
        help="Disable HTTP Basic auth enforcement even when --ghidra-server-username is set",
    )
    g_server.add_argument(
        "--tls-cert",
        dest="tls_certfile",
        type=str,
        default=None,
        help="Path to TLS certificate (PEM) for HTTPS. Requires --tls-key. Env: AGENT_DECOMPILE_TLS_CERT",
    )
    g_server.add_argument(
        "--tls-key",
        dest="tls_keyfile",
        type=str,
        default=None,
        help="Path to TLS private key (PEM) for HTTPS. Requires --tls-cert. Env: AGENT_DECOMPILE_TLS_KEY",
    )
    g_server.add_argument(
        "--project-path",
        type=Path,
        default=Path("agentdecompile_projects"),
        help="Project directory or path to .gpr file",
    )
    g_server.add_argument(
        "--project-name",
        type=str,
        default="my_project",
        help="Project name (ignored when using .gpr)",
    )
    g_server.add_argument("--threaded", dest="threaded", action="store_true", help="Allow threaded analysis")
    g_server.add_argument("--no-threaded", dest="threaded", action="store_false", help="Disable threaded analysis")
    g_server.set_defaults(threaded=True)
    g_server.add_argument("--max-workers", type=int, default=0, help="Workers for analysis (0 = CPU count)")
    g_server.add_argument("--wait-for-analysis", dest="wait_for_analysis", action="store_true", help="Wait for initial analysis before serving")
    g_server.add_argument("--no-wait-for-analysis", dest="wait_for_analysis", action="store_false", help="Do not wait for initial analysis before serving")
    g_server.set_defaults(wait_for_analysis=False)

    # Project management
    g_proj = parser.add_argument_group("Project management")
    g_proj.add_argument("--list-project-binaries", action="store_true", help="List programs and exit")
    g_proj.add_argument("--delete-project-binary", type=str, metavar="NAME", help="Delete a program and exit")

    # Analysis options (passed through for future use; Java backend may use env)
    g_analysis = parser.add_argument_group("Analysis options")
    g_analysis.add_argument("--force-analysis", dest="force_analysis", action="store_true", help="Force re-analysis")
    g_analysis.add_argument("--no-force-analysis", dest="force_analysis", action="store_false", help="Disable forced re-analysis")
    g_analysis.set_defaults(force_analysis=False)
    g_analysis.add_argument("--verbose-analysis", dest="verbose_analysis", action="store_true", help="Verbose analysis log")
    g_analysis.add_argument("--no-verbose-analysis", dest="verbose_analysis", action="store_false", help="Disable verbose analysis log")
    g_analysis.set_defaults(verbose_analysis=False)
    g_analysis.add_argument("--no-symbols", action="store_true", help="Disable symbols for analysis")
    g_analysis.add_argument("--symbols-path", type=Path, default=None, help="Symbols directory")
    g_analysis.add_argument("--sym-file-path", type=Path, default=None, help="Single PDB symbol file")
    g_analysis.add_argument("--gdt", type=Path, action="append", default=[], help="GDT file (repeatable)")
    g_analysis.add_argument("--program-options", type=Path, default=None, help="JSON program options")
    g_analysis.add_argument("--gzfs-path", type=Path, default=None, help="GZF output path")

    parser.add_argument(
        "input_paths",
        nargs="*",
        type=Path,
        help="Binary paths to import before serving",
    )
    parser.add_argument("--config", type=Path, default=None, help="AgentDecompile config file")
    args = parser.parse_args()

    # ---------------------------------------------------------------
    # Local mode only: agentdecompile-server always runs PyGhidra locally.
    # For forwarding to a remote MCP backend, use agentdecompile-proxy instead.
    # ---------------------------------------------------------------
    _configure_logging(args.verbose)

    # Normalize compact and legacy shared-server env aliases before consuming
    # defaults from the process environment.
    sys.stderr.write("[main] Normalizing shared-server env aliases (pass 1 - env vars)...\n")
    _normalize_shared_server_env_aliases()

    # Set environment variables from args
    _set_env_from_args(args)
    # Re-run normalization so CLI-provided values are mirrored to compatibility
    # aliases used by older bridge/bootstrap code paths.
    sys.stderr.write("[main] Normalizing shared-server env aliases (pass 2 - after CLI args)...\n")
    _normalize_shared_server_env_aliases()

    sys.stderr.write(f"[main] transport={args.transport}, verbose={args.verbose}\n")

    # Resolve TLS paths (CLI > env)
    tls_certfile: str | None = args.tls_certfile or os.environ.get("AGENT_DECOMPILE_TLS_CERT") or None
    tls_keyfile: str | None = args.tls_keyfile or os.environ.get("AGENT_DECOMPILE_TLS_KEY") or None
    if bool(tls_certfile) != bool(tls_keyfile):
        parser.error("--tls-cert and --tls-key must be provided together")

    # Build AuthConfig from CLI args / env.
    # EXPERIMENTAL: Auth is disabled by default.  Set the env var
    # AGENT_DECOMPILE_AUTH_ENABLED=true (or pass --require-auth) to enable it.
    # NOTE: Auth is ONLY applied for HTTP transports.  In stdio mode the internal
    # HTTP server is used exclusively by the in-process bridge — no external
    # clients ever reach it, so requiring auth would block the bridge itself.
    _require_auth_flag = getattr(args, "require_auth", None)
    _auth_env_enabled = os.environ.get(
        "AGENT_DECOMPILE_AUTH_ENABLED",
        "",
    ).lower() in ("true", "1", "yes", "on")
    _is_http_transport = args.transport in _HTTP_TRANSPORTS
    auth_config: AuthConfig | None = None
    if _is_http_transport and (_require_auth_flag or _auth_env_enabled):
        auth_config = AuthConfig(
            require_auth=bool(_require_auth_flag),
            default_server_host=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or os.environ.get("AGENT_DECOMPILE_SERVER_HOST") or getattr(args, "ghidra_server_host", None)),
            default_server_port=int(
                os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT") or os.environ.get("AGENT_DECOMPILE_SERVER_PORT") or getattr(args, "ghidra_server_port", None) or 13100,
            ),
            default_username=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or os.environ.get("AGENT_DECOMPILE_SERVER_USERNAME") or getattr(args, "ghidra_server_username", None)),
            default_password=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or os.environ.get("AGENT_DECOMPILE_SERVER_PASSWORD") or getattr(args, "ghidra_server_password", None)),
            default_repository=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENT_DECOMPILE_REPOSITORY") or getattr(args, "ghidra_server_repository", None)),
        )

    # Resolve transport configuration
    port = args.port if args.port is not None else _env_port()
    host = args.host if args.host is not None else _env_host()

    # ---------------------------------------------------------------
    # Local mode: full PyGhidra / JVM startup
    # ---------------------------------------------------------------
    sys.stderr.write("[main] Local mode: starting full PyGhidra / JVM\n")

    # Setup project paths
    project_directory, project_name, project_path_gpr = _setup_project_paths(parser, args)
    sys.stderr.write(f"[main] project_directory={project_directory!r}, project_name={project_name!r}, project_path_gpr={project_path_gpr!r}\n")

    # Initialize PyGhidra
    _initialize_pyghidra(args.verbose_analysis)

    launcher, project_manager = init_agentdecompile_context(
        input_paths=args.input_paths,
        project_name=project_name,
        project_directory=project_directory,
        project_path_gpr=project_path_gpr,
        force_analysis=args.force_analysis,
        verbose_analysis=args.verbose_analysis,
        no_symbols=args.no_symbols,
        gdts=[str(p) for p in args.gdt] if args.gdt else [],
        program_options_path=str(args.program_options) if args.program_options else None,
        gzfs_path=str(args.gzfs_path) if args.gzfs_path else None,
        threaded=args.threaded,
        max_workers=args.max_workers,
        wait_for_analysis=args.wait_for_analysis,
        list_project_binaries=args.list_project_binaries,
        delete_project_binary=args.delete_project_binary,
        symbols_path=str(args.symbols_path) if args.symbols_path else None,
        sym_file_path=str(args.sym_file_path) if args.sym_file_path else None,
        port=port,
        host=host,
        config_file=args.config,
        auth_config=auth_config,
        tls_certfile=tls_certfile,
        tls_keyfile=tls_keyfile,
    )

    # Run the appropriate transport mode
    try:
        runtime_port = launcher.get_port()
        if runtime_port is None:
            raise RuntimeError("Launcher did not provide a server port")

        if args.transport == "stdio":
            run_async(_run_stdio_mode(launcher, project_manager, runtime_port))
        elif args.transport in _HTTP_TRANSPORTS:
            run_async(_run_http_mode(host, runtime_port))
        else:
            sys.stderr.write(f"Unknown transport: {args.transport}\n")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
    finally:
        _cleanup_resources(launcher, project_manager)


def proxy_main() -> None:
    """Entry point for agentdecompile-proxy: forward MCP to a remote backend (no local PyGhidra).

    Use this command when you want to expose a remote AgentDecompile MCP server over stdio
    or HTTP without running a local Ghidra instance. Backend URL is required via
    --backend-url, --mcp-server-url, or env AGENT_DECOMPILE_MCP_SERVER_URL / AGENTDECOMPILE_MCP_SERVER_URL.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="AgentDecompile MCP proxy: forward MCP requests to a remote backend (no local PyGhidra/JVM)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--backend-url",
        "--server-url",
        dest="backend_url",
        type=str,
        default=None,
        help="Remote MCP backend URL (http(s)://host:port[/mcp/message]); env: AGENT_DECOMPILE_BACKEND_URL",
    )
    parser.add_argument(
        "--mcp-server-url",
        dest="mcp_server_url",
        type=str,
        default=None,
        help="Fallback backend URL; env: AGENT_DECOMPILE_MCP_SERVER_URL or AGENTDECOMPILE_MCP_SERVER_URL",
    )
    parser.add_argument(
        "-t",
        "--transport",
        choices=["stdio", "streamable-http", "sse", "http"],
        default="stdio",
        help="Transport: stdio (forward over stdio) or HTTP (expose proxy on host:port)",
    )
    parser.add_argument("-p", "--port", type=int, default=None, help="Port for HTTP proxy (default: 8080)")
    parser.add_argument("-o", "--host", type=str, default=None, help="Host for HTTP proxy (default: 127.0.0.1)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logs")
    parser.add_argument("--tls-cert", dest="tls_certfile", type=str, default=None, help="TLS cert (PEM) for HTTPS proxy")
    parser.add_argument("--tls-key", dest="tls_keyfile", type=str, default=None, help="TLS key (PEM) for HTTPS proxy")
    parser.add_argument("--require-auth", dest="require_auth", action="store_true", help="Require HTTP Basic auth on proxy")
    parser.add_argument("--no-require-auth", dest="require_auth", action="store_false", help="Do not require auth")
    parser.set_defaults(require_auth=None)
    parser.add_argument("--ghidra-server-host", type=str, default=None, help="Auth: Ghidra server host")
    parser.add_argument("--ghidra-server-port", type=int, default=None, help="Auth: Ghidra server port")
    parser.add_argument("--ghidra-server-username", type=str, default=None, help="Auth: Ghidra server username")
    parser.add_argument("--ghidra-server-password", type=str, default=None, help="Auth: Ghidra server password")
    parser.add_argument("--ghidra-server-repository", type=str, default=None, help="Auth: Ghidra server repository")
    args = parser.parse_args()

    backend_url = _resolve_proxy_backend_url(
        getattr(args, "backend_url", None),
        getattr(args, "mcp_server_url", None),
    )
    if not backend_url or not backend_url.strip():
        sys.stderr.write("agentdecompile-proxy requires a backend URL. Set --backend-url or --mcp-server-url, or env AGENT_DECOMPILE_MCP_SERVER_URL / AGENTDECOMPILE_MCP_SERVER_URL.\n")
        sys.exit(1)
    backend_url = normalize_backend_url(backend_url.strip())

    _configure_logging(getattr(args, "verbose", False))
    tls_certfile = args.tls_certfile or os.environ.get("AGENT_DECOMPILE_TLS_CERT") or None
    tls_keyfile = args.tls_keyfile or os.environ.get("AGENT_DECOMPILE_TLS_KEY") or None
    if bool(tls_certfile) != bool(tls_keyfile):
        parser.error("--tls-cert and --tls-key must be provided together")
    _require_auth_flag = getattr(args, "require_auth", None)
    _auth_env = os.environ.get("AGENT_DECOMPILE_AUTH_ENABLED", "").lower() in ("true", "1", "yes", "on")
    _is_http = args.transport in _HTTP_TRANSPORTS
    auth_config = None
    if _is_http and (_require_auth_flag or _auth_env):
        auth_config = AuthConfig(
            require_auth=bool(_require_auth_flag),
            default_server_host=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or os.environ.get("AGENT_DECOMPILE_SERVER_HOST") or getattr(args, "ghidra_server_host", None)),
            default_server_port=int(
                os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT") or os.environ.get("AGENT_DECOMPILE_SERVER_PORT") or getattr(args, "ghidra_server_port", None) or 13100,
            ),
            default_username=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or os.environ.get("AGENT_DECOMPILE_SERVER_USERNAME") or getattr(args, "ghidra_server_username", None)),
            default_password=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or os.environ.get("AGENT_DECOMPILE_SERVER_PASSWORD") or getattr(args, "ghidra_server_password", None)),
            default_repository=(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENT_DECOMPILE_REPOSITORY") or getattr(args, "ghidra_server_repository", None)),
        )
    port = args.port if args.port is not None else _env_port()
    host = args.host if args.host is not None else _env_host()

    from agentdecompile_cli.mcp_server.proxy_server import (
        AgentDecompileMcpProxyServer,
        ProxyServerConfig,
    )

    sys.stderr.write(f"Proxy mode: forwarding to {backend_url}\n")

    if args.transport == "stdio":
        from agentdecompile_cli.bridge import AgentDecompileStdioBridge

        bridge = AgentDecompileStdioBridge(backend_url)
        try:
            run_async(bridge.run())
        except KeyboardInterrupt:
            sys.stderr.write("\nShutdown complete\n")
        return

    proxy_server = AgentDecompileMcpProxyServer(
        ProxyServerConfig(
            host=host,
            port=port,
            backend_url=backend_url,
            tls_certfile=tls_certfile,
            tls_keyfile=tls_keyfile,
        ),
        auth_config=auth_config,
    )
    try:
        started_port = proxy_server.start()
        sys.stderr.write(
            f"AgentDecompile proxy running at http://{host}:{started_port}/mcp/message\n",
        )
        sys.stderr.write(f"Forwarding requests to backend {backend_url}\n")
        sys.stderr.write("Press Ctrl+C to stop.\n")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
    finally:
        proxy_server.stop()


if __name__ == "__main__":
    main()
