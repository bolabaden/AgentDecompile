"""LEGACY: Content has been merged into launcher.py which is the single source of truth.
This file is kept for backward-compatibility and will be removed by the project owner.
Prefer importing from agentdecompile_cli.launcher.

Server entry point with project initialization and transport selection.

Provides init_agentdecompile_context() and a main() that supports:
- Project path (.gpr file or directory) and project name
- Transport: stdio (bridge to Python MCP server) or streamable-http (Python MCP server on host:port)
- List/delete project binaries (then exit)
- Import binaries (input_paths) before serving

Environment (1:1 with Python AgentDecompileLauncher / ConfigManager):
- AGENT_DECOMPILE_PROJECT_PATH: Path to .gpr file (persistent project)
- AGENT_DECOMPILE_HOST: Server bind host (applied when no config file)
- AGENT_DECOMPILE_PORT: Server port (applied when no config file)
- AGENT_DECOMPILE_FORCE_IGNORE_LOCK: Force ignore project lock files (risky)
- AGENT_DECOMPILE_SERVER_USERNAME, AGENT_DECOMPILE_SERVER_PASSWORD: Shared project auth
- AGENT_DECOMPILE_SERVER_HOST, AGENT_DECOMPILE_SERVER_PORT: Ghidra server for shared projects
- AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY, AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from pathlib import Path

from agentdecompile_cli.launcher import AgentDecompileLauncher
from agentdecompile_cli.project_manager import ProjectManager
from agentdecompile_cli.utils import get_client, run_async

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


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
    use_random_port = port is None
    launcher = AgentDecompileLauncher(config_file=config_file, use_random_port=use_random_port)
    project_manager: ProjectManager | None = None
    if not os.getenv("AGENT_DECOMPILE_PROJECT_PATH"):
        project_manager = ProjectManager()

    # Start the server (caller must have called pyghidra.start() before)
    started_port = launcher.start(
        port=port,
        host=host,
        project_directory=project_directory if project_path_gpr is None else None,
        project_name=project_name if project_path_gpr is None else None,
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
                sys.stderr.write(f"Error listing programs: {e}\n")
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
            client = get_client(host="127.0.0.1", port=started_port)
            async with client:
                for path in bin_paths:
                    try:
                        await client.call_tool("open", {"path": str(path.resolve()), "runAnalysis": True})
                        sys.stderr.write(f"Imported: {path}\n")
                    except Exception as e:
                        sys.stderr.write(f"Import failed for {path}: {e}\n")

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
        type=int,
        default=None,
        help="Port for HTTP transports (default: AGENT_DECOMPILE_PORT or 8080)",
    )
    g_server.add_argument(
        "-o",
        "--host",
        type=str,
        default=None,
        help="Host for HTTP transports (default: AGENT_DECOMPILE_HOST or 127.0.0.1)",
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

    # Apply env defaults for host/port (1:1 Java headless)
    port = args.port if args.port is not None else _env_port()
    host = args.host if args.host is not None else _env_host()

    # Resolve project path (.gpr vs directory)
    project_path = args.project_path.resolve()
    if project_path.suffix.lower() == ".gpr":
        if args.project_name != "my_project":
            parser.error("Cannot use --project-name with a .gpr file")
        project_directory = str(project_path.parent)
        project_name = project_path.stem
        project_path_gpr = project_path
    else:
        project_directory = str(project_path)
        project_name = args.project_name
        project_path_gpr = None

    # PyGhidra and filters (same as __main__)
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
        pyghidra.start(verbose=args.verbose_analysis)
        if _redirect_java_outputs:
            _redirect_java_outputs()
        sys.stderr.write("PyGhidra initialized\n")

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
            port=port if args.transport != "stdio" else None,
            host=host if args.transport != "stdio" else None,
            config_file=args.config,
        )
    except Exception as e:
        if sys.stdout != original_stdout:
            sys.stdout = original_stdout
        if sys.stderr != original_stderr:
            sys.stderr = original_stderr
        sys.stderr.write(f"Initialization error: {e}\n")
        raise
        # sys.exit(1)

    port = launcher.get_port()
    assert port is not None

    try:
        if args.transport == "stdio":
            from agentdecompile_cli.__main__ import AgentDecompileCLI

            cli = AgentDecompileCLI(
                launcher=launcher,
                project_manager=project_manager,
                backend=port,
            )
            run_async(cli.run())
        elif args.transport in ["streamable-http", "http", "sse"]:
            bind_host = host
            sys.stderr.write(f"AgentDecompile server running at http://{bind_host}:{port}/mcp/message\n")
            sys.stderr.write("Press Ctrl+C to stop.\n")
            while True:
                time.sleep(3600)
        else:
            sys.stderr.write(f"Unknown transport: {args.transport}\n")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
    finally:
        if launcher:
            launcher.stop()
        if project_manager and hasattr(project_manager, "cleanup"):
            try:
                project_manager.cleanup()
            except Exception:
                pass


if __name__ == "__main__":
    main()
