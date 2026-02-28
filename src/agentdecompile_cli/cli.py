"""Interactive CLI client for AgentDecompile MCP server.

Matches TOOLS_LIST.md and vendor pyghidra-mcp README functionality. Supports both
existing AgentDecompile tool names/parameters and the operations described there.

Usage:
  # Start server (in another terminal)
  mcp-agentdecompile-server -t streamable-http --project-path ./projects /path/to/binary
  # Or docker:
    docker run --rm -it -v /path/to/binary:/binary -v ./projects:/projects agentdecompile:latest \

  # Use CLI
  agentdecompile-cli list binaries
  agentdecompile-cli decompile --binary /myapp main
  agentdecompile-cli search symbols --binary /myapp malloc -l 20
  agentdecompile-cli search strings --binary /myapp regex "error|warning" -l 50
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
import json
import multiprocessing
import sys

from collections.abc import Coroutine
from pathlib import Path
from types import FunctionType, SimpleNamespace
from typing import Any

import click

from agentdecompile_cli import __version__
from agentdecompile_cli.executor import (
    format_output,
    get_client,
    handle_command_error,
    resolve_backend_url,
    run_async,
)
from agentdecompile_cli.ghidrecomp.decompile import decompile
from agentdecompile_cli.registry import (
    RESOURCE_URI_DEBUG_INFO,
    RESOURCE_URI_PROGRAMS,
    RESOURCE_URI_STATIC_ANALYSIS,
    to_snake_case,
    tool_registry,
)

THREAD_COUNT = multiprocessing.cpu_count()
_dynamic_commands_registered = False


def _get_opts(ctx: click.Context) -> dict[str, Any]:
    """Global options from context (set by main group)."""
    return ctx.obj or {}


def _client(ctx: click.Context) -> Any:
    opts = _get_opts(ctx)
    url = resolve_backend_url(
        opts.get("server_url"),
        opts.get("host"),
        opts.get("port"),
    )
    if url:
        return get_client(url=url)
    return get_client(
        host=opts.get("host", "127.0.0.1"),
        port=opts.get("port", 8080),
    )


def _fmt(ctx: click.Context) -> str:
    return _get_opts(ctx).get("format", "text")


def _extract_text(result: Any) -> str | None:
    contents: list[Any] = getattr(result, "contents", None) or []
    for c in contents:
        text = getattr(c, "text", None)
        if text:
            return text
    return None


def _parse_json(result: Any) -> dict | list | None:
    text = _extract_text(result)
    if not text:
        return None
    try:
        return json.loads(text) if isinstance(text, str) else text
    except (json.JSONDecodeError, TypeError):
        return None


def _get_error_result_message(data: Any) -> str | None:
    """If data is a tool error result (success: false, error present), return the error message; else None."""
    if not isinstance(data, dict):
        return None
    if data.get("success") is not False or "error" not in data:
        return None
    return str(data.get("error", "Tool returned an error"))


async def _call(ctx: click.Context, tool: str, **kwargs: Any) -> None:
    """Call tool on the remote MCP server via HTTP client.

    The CLI is a pure HTTP client — it NEVER executes tools locally.  All tool
    calls are forwarded to the MCP server (which runs with PyGhidra and has
    access to Ghidra APIs).
    """
    from agentdecompile_cli.bridge import ServerNotRunningError  # noqa: PLC0415

    # Drop None values
    payload: dict[str, Any] = {k: v for k, v in kwargs.items() if v is not None}

    # Canonicalize tool + args through the shared registry path when known.
    call_tool_name = tool
    if tool_registry.is_valid_tool(tool):
        call_tool_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(tool))
        payload = tool_registry.parse_arguments(payload, call_tool_name)
    call_tool_name = to_snake_case(call_tool_name)

    try:
        client = _client(ctx)
        async with client:
            data = await client.call_tool(call_tool_name, payload)
    except ServerNotRunningError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error calling tool '{call_tool_name}': {exc}", err=True)
        sys.exit(1)

    # data is already a dict from AgentDecompileMcpClient._extract_result()
    err_msg = _get_error_result_message(data)
    if err_msg is not None:
        click.echo(err_msg, err=True)
        sys.exit(1)
    click.echo(format_output(data, _fmt(ctx)))


async def _call_raw(ctx: click.Context, tool: str, payload: dict[str, Any]) -> Any:
    """Call tool and return raw result for programmatic CLI workflows."""
    from agentdecompile_cli.bridge import ServerNotRunningError  # noqa: PLC0415

    safe_payload: dict[str, Any] = {k: v for k, v in payload.items() if v is not None}
    call_tool_name = tool
    if tool_registry.is_valid_tool(tool):
        call_tool_name = tool_registry.get_display_name(tool_registry.canonicalize_tool_name(tool))
        safe_payload = tool_registry.parse_arguments(safe_payload, call_tool_name)
    call_tool_name = to_snake_case(call_tool_name)
    try:
        client = _client(ctx)
        async with client:
            return await client.call_tool(call_tool_name, safe_payload)
    except ServerNotRunningError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error calling tool '{call_tool_name}': {exc}", err=True)
        sys.exit(1)


def _parse_tool_payload(arguments: str) -> dict[str, Any]:
    """Parse CLI JSON argument payload for generic tool commands."""
    # Strip whitespace and leading/trailing quotes (PowerShell may pass them)
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


def _validate_known_tool(name: str) -> None:
    if tool_registry.is_valid_tool(name):
        return
    click.echo(
        f"Note: '{name}' is not in the known tool list (agentdecompile-cli tool --list-tools). Proceeding anyway.",
        err=True,
    )


def _run_async(coro: Coroutine[Any, Any, None]) -> None:
    try:
        run_async(coro)
    except (asyncio.CancelledError, Exception) as e:
        handle_command_error(e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Global options and main group
# ---------------------------------------------------------------------------


def _add_global_options(cmd: click.Command | FunctionType) -> click.Command | FunctionType:
    cmd = click.option("--host", default="127.0.0.1", help="Server host")(cmd)
    cmd = click.option("--port", type=int, default=8080, help="Server port")(cmd)
    cmd = click.option(
        "--server-url",
        help="Full server URL (overrides --host/--port)",
    )(cmd)
    cmd = click.option(
        "-f",
        "--format",
        type=click.Choice(["json", "table", "text"]),
        default="text",
        help="Output format",
    )(cmd)
    return cmd


def _create_dynamic_commands(cli_group: click.Group) -> None:
    """Dynamically create CLI commands from the tool registry."""
    for tool_name in tool_registry.get_tools():
        tool_params = tool_registry.get_tool_params(tool_name)

        # Create parameter options for this tool
        def tool_command(_tool_name: str = tool_name, **kwargs: Any) -> None:
            """Dynamically generated tool command."""
            ctx = click.get_current_context()
            # Remove None values and format arguments
            args = {k: v for k, v in kwargs.items() if v is not None}

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

            # Check if parameter is required
            required = param in ["programPath", "addressOrSymbol", "action", "mode"]

            # Add the option decorator
            tool_command = click.option(
                option_name,
                snake_param,
                type=option_type,
                required=required,
                help=f"{snake_param} parameter",
            )(tool_command)

        command_name = to_snake_case(tool_name)

        # Add global options and register the command
        tool_command = _add_global_options(tool_command)

        # Register snake_case command unless an explicit command already exists.
        if command_name not in cli_group.commands:
            command_obj = cli_group.command(command_name)(tool_command)
        else:
            command_obj = cli_group.commands[command_name]

        # Also register canonical kebab-case alias from TOOLS_LIST when distinct.
        if tool_name != command_name and tool_name not in cli_group.commands:
            cli_group.add_command(command_obj, tool_name)


def _ensure_dynamic_commands_registered() -> None:
    global _dynamic_commands_registered
    if _dynamic_commands_registered:
        return
    _create_dynamic_commands(main)
    _dynamic_commands_registered = True


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", type=int, default=8080, help="Server port")
@click.option("--server-url", help="Full server URL (overrides --host/--port)")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "table", "text"]),
    default="text",
    help="Output format",
)
@click.version_option(None, "--version", "-V", package_name="agentdecompile")
@click.pass_context
def main(
    ctx: click.Context,
    host: str,
    port: int,
    server_url: str | None,
    format: str,
) -> None:
    """AgentDecompile CLI – all tools from TOOLS_LIST.md (30+ tools)."""
    ctx.obj = {
        "host": host,
        "port": port,
        "server_url": server_url,
        "format": format,
    }

    # Ensure command surface includes canonical + snake_case tool commands.
    _ensure_dynamic_commands_registered()


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
    pass


@list_grp.command(
    "binaries",
    help="List all programs in the project (ghidra://programs)",
)
@click.pass_context
def list_binaries(ctx: click.Context) -> None:
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
            click.echo(format_output(names, _fmt(ctx)))
        else:
            click.echo("No programs in project.")

    _run_async(_run())


@list_grp.command("imports", help="List imports (manage-symbols mode=imports)")
@click.option(
    "-b",
    "--binary",
    "program_path",
    required=True,
    help="Program path in project",
)
@click.option("--max-results", type=int, default=75)
@click.option("--start-index", type=int, default=0)
@click.option("--library-filter", help="Filter by library name")
@click.option("--no-group-by-library", is_flag=True, help="Do not group by library")
@click.pass_context
def list_imports(
    ctx: click.Context,
    program_path: str,
    max_results: int,
    start_index: int,
    library_filter: str | None,
    no_group_by_library: bool,
) -> None:
    payload: dict[str, Any] = {
        "programPath": program_path,
        "mode": "imports",
        "maxResults": max_results,
        "startIndex": start_index,
    }
    if library_filter is not None:
        payload["libraryFilter"] = library_filter
    if no_group_by_library:
        payload["groupByLibrary"] = False
    _run_async(_call(ctx, "manage-symbols", **payload))


@list_grp.command("exports", help="List exports (manage-symbols mode=exports)")
@click.option("-b", "--binary", "program_path", required=True)
@click.option("--max-results", type=int, default=75)
@click.option("--start-index", type=int, default=0)
@click.pass_context
def list_exports(
    ctx: click.Context,
    program_path: str,
    max_results: int,
    start_index: int,
) -> None:
    _run_async(
        _call(
            ctx,
            "manage-symbols",
            programPath=program_path,
            mode="exports",
            maxResults=max_results,
            startIndex=start_index,
        ),
    )


@list_grp.command(
    "project-files",
    help="List project file/folder hierarchy (list-project-files)",
)
@click.pass_context
def list_project_files(ctx: click.Context) -> None:
    _run_async(_call(ctx, "list-project-files"))


@list_grp.command("open-programs", help="List open programs (list-open-programs, GUI)")
@click.pass_context
def list_open_programs(ctx: click.Context) -> None:
    _run_async(_call(ctx, "list-open-programs"))


# ---------------------------------------------------------------------------
# Data (get-data, apply-data-type, create-label)
# ---------------------------------------------------------------------------


@main.group(
    "data",
    help="Data at address (get-data, apply-data-type, create-label)",
)
def data_grp() -> None:
    pass


@data_grp.command("get", help="Get data/code unit at address (get-data)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("address_or_symbol")
@click.pass_context
def data_get(ctx: click.Context, program_path: str, address_or_symbol: str) -> None:
    _run_async(
        _call(
            ctx,
            "get-data",
            programPath=program_path,
            addressOrSymbol=address_or_symbol,
        ),
    )


@data_grp.command("apply-type", help="Apply data type at address (apply-data-type)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("address_or_symbol")
@click.option("--data-type", "data_type_string", required=True)
@click.option("--archive-name", "archive_name")
@click.pass_context
def data_apply_type(
    ctx: click.Context,
    program_path: str,
    address_or_symbol: str,
    data_type_string: str,
    archive_name: str | None,
) -> None:
    payload: dict[str, Any] = {
        "programPath": program_path,
        "addressOrSymbol": address_or_symbol,
        "dataTypeString": data_type_string,
    }
    if archive_name is not None:
        payload["archiveName"] = archive_name
    _run_async(_call(ctx, "apply-data-type", **payload))


@data_grp.command("create-label", help="Create label at address (create-label)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("address_or_symbol")
@click.option("--name", "labelName", required=True)
@click.option("--primary", "setAsPrimary", is_flag=True)
@click.pass_context
def data_create_label(
    ctx: click.Context,
    program_path: str,
    address_or_symbol: str,
    label_name: str,
    set_as_primary: bool,
) -> None:
    _run_async(
        _call(
            ctx,
            "create-label",
            programPath=program_path,
            addressOrSymbol=address_or_symbol,
            labelName=label_name,
            setAsPrimary=set_as_primary,
        ),
    )


# ---------------------------------------------------------------------------
# Resources (program list, static analysis, debug info)
# ---------------------------------------------------------------------------


@main.group(
    "resource",
    help="Read MCP resources: programs, static-analysis-results, agentdecompile-debug-info",
)
def resource_grp() -> None:
    pass


async def _read_resource(ctx: click.Context, uri: str) -> None:
    client = _client(ctx)
    async with client:
        result = await client.read_resource(uri)
    data = _parse_json(result)
    click.echo(format_output(data or result, _fmt(ctx)))


@resource_grp.command("programs", help="Read ghidra://programs (same as list binaries)")
@click.pass_context
def resource_programs(ctx: click.Context) -> None:
    _run_async(_read_resource(ctx, RESOURCE_URI_PROGRAMS))


@resource_grp.command(
    "static-analysis",
    help="Read ghidra://static-analysis-results (SARIF 2.1.0)",
)
@click.pass_context
def resource_static_analysis(ctx: click.Context) -> None:
    _run_async(_read_resource(ctx, RESOURCE_URI_STATIC_ANALYSIS))


@resource_grp.command(
    "debug-info",
    help="Read ghidra://agentdecompile-debug-info (JSON)",
)
@click.pass_context
def resource_debug_info(ctx: click.Context) -> None:
    _run_async(_read_resource(ctx, RESOURCE_URI_DEBUG_INFO))


# ---------------------------------------------------------------------------
# get-functions (decompile, disassemble, info, calls)
# ---------------------------------------------------------------------------


@main.group(
    "functions",
    help="Get function details (get-functions): decompile, disassemble, info, calls",
)
def functions_grp() -> None:
    pass


@functions_grp.command("decompile", help="Decompile a function (view=decompile)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("identifier")
@click.option("--offset", type=int, default=1, help="Line offset (1-based)")
@click.option("--limit", type=int, default=50)
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
    program_path: str,
    identifier: str,
    offset: int,
    limit: int,
    include_callers: bool,
    include_callees: bool,
    include_comments: bool,
    no_incoming_refs: bool,
    no_ref_context: bool,
) -> None:
    async def _run():
        client = _client(ctx)
        async with client:
            result = await client.call_tool(
                "get-functions",
                {
                    "programPath": program_path,
                    "identifier": identifier,
                    "view": "decompile",
                    "offset": offset,
                    "limit": limit,
                    "includeCallers": include_callers,
                    "includeCallees": include_callees,
                    "includeComments": include_comments,
                    "includeIncomingReferences": False if no_incoming_refs else True,
                    "includeReferenceContext": False if no_ref_context else True,
                },
            )
        data = _parse_json(result)
        if isinstance(data, dict) and "decompilation" in data:
            click.echo(data.get("decompilation", data))
        else:
            click.echo(format_output(data or result, _fmt(ctx)))

    _run_async(_run())


@functions_grp.command(
    "disassemble",
    help="Disassembly for a function (view=disassemble)",
)
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("identifier")
@click.pass_context
def functions_disassemble(
    ctx: click.Context,
    program_path: str,
    identifier: str,
) -> None:
    _run_async(
        _call(
            ctx,
            "get-functions",
            programPath=program_path,
            identifier=identifier,
            view="disassemble",
        ),
    )


@functions_grp.command("info", help="Function metadata (view=info)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("identifier")
@click.pass_context
def functions_info(ctx: click.Context, program_path: str, identifier: str) -> None:
    _run_async(
        _call(
            ctx,
            "get-functions",
            programPath=program_path,
            identifier=identifier,
            view="info",
        ),
    )


@functions_grp.command("calls", help="Internal calls (view=calls)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("identifier")
@click.pass_context
def functions_calls(ctx: click.Context, program_path: str, identifier: str) -> None:
    _run_async(
        _call(
            ctx,
            "get-functions",
            programPath=program_path,
            identifier=identifier,
            view="calls",
        ),
    )


# ---------------------------------------------------------------------------
# manage-symbols (all modes)
# ---------------------------------------------------------------------------


@main.group(
    "symbols",
    help="Manage symbols (manage-symbols): classes, namespaces, imports, exports, create_label, symbols, count, rename_data, demangle",
)
def symbols_grp() -> None:
    pass


@symbols_grp.command("run", help="Run manage-symbols with --mode and optional params")
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
@click.option("--limit", "--max-results", "limit", type=int)
@click.option("--start-index", "start_index", type=int)
@click.option("--offset", type=int)
@click.option("--max-count", "max_count", type=int)
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
    limit: int | None,
    max_count: int | None,
    group_by_library: bool,
    include_external: bool,
    filter_default_names: bool,
    demangle_all: bool,
) -> None:
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
    if limit is not None:
        payload["limit"] = limit
    if max_count is not None:
        payload["maxCount"] = max_count
    payload["groupByLibrary"] = group_by_library
    payload["includeExternal"] = include_external
    payload["filterDefaultNames"] = filter_default_names
    if mode == "demangle":
        payload["demangleAll"] = demangle_all
    _run_async(_call(ctx, "manage-symbols", **payload))


# --- Convenience subcommands (``symbols classes``, ``symbols imports``, …) ---

def _symbols_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``symbols <mode>`` shorthand subcommands."""

    @symbols_grp.command(mode_name, help=help_text or f"manage-symbols mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--limit", "--max-results", "limit", type=int)
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
        limit: int | None,
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
        if limit is not None:
            payload["limit"] = limit
        if library_filter:
            payload["libraryFilter"] = library_filter
        payload["groupByLibrary"] = group_by_library
        payload["includeExternal"] = include_external
        payload["filterDefaultNames"] = filter_default_names
        _run_async(_call(ctx, "manage-symbols", **payload))

    return _cmd


for _mode in ("classes", "namespaces", "imports", "exports", "symbols", "count", "demangle"):
    _symbols_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-strings
# ---------------------------------------------------------------------------


@main.group("strings", help="Manage strings (manage-strings): list, regex, count, similarity")
def strings_grp() -> None:
    pass


@strings_grp.command("run", help="Run manage-strings with --mode and optional params")
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
@click.option("--max-count", "maxCount", type=int)
@click.option("--offset", type=int)
@click.option("--limit", "--max-results", "limit", type=int)
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
    max_count: int | None,
    offset: int | None,
    limit: int | None,
    include_referencing_functions: bool,
) -> None:
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
    if max_count is not None:
        payload["maxCount"] = max_count
    if offset is not None:
        payload["offset"] = offset
    if limit is not None:
        payload["limit"] = limit
    payload["includeReferencingFunctions"] = include_referencing_functions
    _run_async(_call(ctx, "manage-strings", **payload))


# --- Convenience subcommands (``strings list``, ``strings regex``, …) ---

def _strings_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``strings <mode>`` shorthand subcommands."""

    @strings_grp.command(mode_name, help=help_text or f"manage-strings mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--pattern")
    @click.option("--search-string", "search_string")
    @click.option("--filter")
    @click.option("--offset", type=int)
    @click.option("--limit", "--max-results", "limit", type=int)
    @click.option("--include-referencing-functions", "include_refs", is_flag=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        pattern: str | None,
        search_string: str | None,
        filter: str | None,
        offset: int | None,
        limit: int | None,
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
        if limit is not None:
            payload["limit"] = limit
        payload["includeReferencingFunctions"] = include_refs
        _run_async(_call(ctx, "manage-strings", **payload))

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
@click.option("--max-count", "maxCount", type=int)
@click.option("--offset", type=int)
@click.option("--limit", type=int)
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
    max_count: int | None,
    offset: int | None,
    limit: int | None,
    filter_default_names: bool,
    filter_by_tag: str | None,
    untagged: bool,
    has_tags: bool,
    verbose: bool,
) -> None:
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
    if max_count is not None:
        payload["maxCount"] = max_count
    if offset is not None:
        payload["offset"] = offset
    if limit is not None:
        payload["limit"] = limit
    payload["filterDefaultNames"] = filter_default_names
    if filter_by_tag is not None and filter_by_tag.strip():
        payload["filterByTag"] = filter_by_tag
    payload["untagged"] = untagged
    payload["hasTags"] = has_tags
    payload["verbose"] = verbose
    _run_async(_call(ctx, "list-functions", **payload))


# --- Convenience subcommands (``list-functions all``, ``list-functions search``, …) ---

def _list_functions_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``list-functions <mode>`` shorthand subcommands."""

    @list_functions_grp.command(mode_name, help=help_text or f"list-functions mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--query")
    @click.option("--offset", type=int)
    @click.option("--limit", type=int)
    @click.option("--filter-default-names/--no-filter-default-names", "filter_default_names", default=True)
    @click.option("--verbose", is_flag=True)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        query: str | None,
        offset: int | None,
        limit: int | None,
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
        if limit is not None:
            payload["limit"] = limit
        payload["filterDefaultNames"] = filter_default_names
        payload["verbose"] = verbose
        _run_async(_call(ctx, "list-functions", **payload))

    return _cmd


for _mode in ("all", "search", "similarity", "undefined", "count", "by_identifiers"):
    _list_functions_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-function
# ---------------------------------------------------------------------------


@main.group(
    "function",
    help="Manage function (manage-function): create, rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes",
)
def function_grp() -> None:
    pass


@function_grp.command("run", help="Run manage-function with --action and optional params")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--action",
    type=click.Choice(
        [
            "create",
            "rename_function",
            "rename_variable",
            "set_prototype",
            "set_variable_type",
            "change_datatypes",
        ],
    ),
    required=True,
)
@click.option("--address", multiple=True)
@click.option("--function-identifier", "functionIdentifier", multiple=True)
@click.option("--name")
@click.option("--functions", help="JSON array of function rename objects")
@click.option("--old-name", "oldName")
@click.option("--new-name", "newName")
@click.option(
    "--variable-mappings",
    "variableMappings",
    help="oldName1:newName1,oldName2:newName2",
)
@click.option("--prototype", "prototype", multiple=True)
@click.option("--variable-name", "variableName")
@click.option("--new-type", "newType")
@click.option("--datatype-mappings", "datatypeMappings", help="varName1:type1,varName2:type2")
@click.option("--archive-name", "archiveName")
@click.option(
    "--create-if-not-exists/--no-create-if-not-exists",
    "createIfNotExists",
    default=True,
)
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
    _run_async(_call(ctx, "manage-function", **payload))


# ---------------------------------------------------------------------------
# manage-function-tags
# ---------------------------------------------------------------------------


@main.group(
    "function-tags",
    help="Manage function tags (manage-function-tags): get, set, add, remove, list",
)
def function_tags_grp() -> None:
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
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if function:
        payload["function"] = list(function) if len(function) != 1 else function[0]
    if tags:
        payload["tags"] = list(tags)
    _run_async(_call(ctx, "manage-function-tags", **payload))


# ---------------------------------------------------------------------------
# match-function
# ---------------------------------------------------------------------------


@main.command("match-function", help="Match functions across programs (match-function)")
@click.option("-b", "--binary", "program_path")
@click.option("--function-identifier", "functionIdentifier", multiple=True)
@click.option("--target-program-paths", "targetProgramPaths", multiple=True)
@click.option("--max-instructions", "maxInstructions", type=int)
@click.option("--min-similarity", "minSimilarity", type=float)
@click.option("--propagate-names/--no-propagate-names", "propagateNames", default=True)
@click.option("--propagate-tags/--no-propagate-tags", "propagateTags", default=True)
@click.option("--propagate-comments/--no-propagate-comments", "propagateComments", default=False)
@click.option(
    "--filter-default-names/--no-filter-default-names",
    "filterDefaultNames",
    default=True,
)
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
    _run_async(_call(ctx, "match-function", **payload))


# ---------------------------------------------------------------------------
# inspect-memory
# ---------------------------------------------------------------------------


@main.group(
    "memory",
    help="Inspect memory (inspect-memory): blocks, read, data_at, data_items, segments",
)
def memory_grp() -> None:
    pass


@memory_grp.command("run", help="Run inspect-memory with --mode")
@click.option("-b", "--binary", "program_path", required=True)
@click.option(
    "--mode",
    type=click.Choice(["blocks", "read", "data_at", "data_items", "segments"]),
    required=True,
)
@click.option("--address")
@click.option("--length", type=int)
@click.option("--offset", type=int)
@click.option("--limit", type=int)
@click.pass_context
def memory_run(
    ctx: click.Context,
    program_path: str,
    mode: str,
    address: str | None,
    length: int | None,
    offset: int | None,
    limit: int | None,
) -> None:
    payload: dict[str, Any] = {"programPath": program_path, "mode": mode}
    if address is not None and address.strip():
        payload["address"] = address
    if length is not None:
        payload["length"] = length
    if offset is not None:
        payload["offset"] = offset
    if limit is not None:
        payload["limit"] = limit
    _run_async(_call(ctx, "inspect-memory", **payload))


# ---------------------------------------------------------------------------
# open
# ---------------------------------------------------------------------------


@main.command("open", help="Open project or program (open)")
@click.argument("path", type=click.Path(exists=False), required=False, default=None)
@click.option(
    "--extensions",
    help="Comma-separated extensions for bulk open (e.g. exe,dll)",
)
@click.option(
    "--open_all_programs/--no-open_all_programs",
    "--open-all-programs/--no-open-all-programs",
    "open_all_programs",
    default=True,
)
@click.option("--destination_folder", "--destination-folder", "destination_folder", default="/")
@click.option(
    "--analyze_after_import/--no-analyze_after_import",
    "--analyze-after-import/--no-analyze-after-import",
    "analyze_after_import",
    default=True,
)
@click.option(
    "--enable_version_control/--no-enable_version_control",
    "--enable-version-control/--no-enable-version-control",
    "enable_version_control",
    default=True,
)
@click.option("--server_username", "--server-username", "server_username")
@click.option("--server_password", "--server-password", "server_password")
@click.option("--server_host", "--server-host", "server_host")
@click.option("--server_port", "--server-port", "server_port", type=int)
@click.pass_context
def open_cmd(
    ctx: click.Context,
    path: str | None,
    extensions: str | None,
    open_all_programs: bool,
    destination_folder: str,
    analyze_after_import: bool,
    enable_version_control: bool,
    server_username: str | None,
    server_password: str | None,
    server_host: str | None,
    server_port: int | None,
) -> None:
    payload: dict[str, Any] = {}
    is_shared_server_mode = bool(server_host and server_host.strip())

    # When connecting to a remote Ghidra shared-project server, the MCP
    # backend typically runs on the *same* host (Docker exposes the Ghidra
    # server ports and the MCP HTTP port side-by-side).  If the caller
    # provided --server_host but did NOT override the global --host /
    # --server-url (which still points at localhost), automatically route
    # the MCP client connection to the remote host on the default MCP port.
    if is_shared_server_mode:
        opts = ctx.ensure_object(dict)
        if opts.get("host") == "127.0.0.1" and not opts.get("server_url"):
            opts["host"] = server_host

    if path is not None:
        if is_shared_server_mode:
            payload["path"] = path
        else:
            payload["path"] = str(Path(path).resolve()) if path != "/" else path
    if extensions is not None:
        payload["extensions"] = extensions
    payload["openAllPrograms"] = open_all_programs
    payload["destinationFolder"] = destination_folder
    payload["analyzeAfterImport"] = analyze_after_import
    payload["enableVersionControl"] = enable_version_control
    if server_username is not None and server_username.strip():
        payload["serverUsername"] = server_username
    if server_password is not None and server_password.strip():
        payload["serverPassword"] = server_password
    if server_host is not None and server_host.strip():
        payload["serverHost"] = server_host
    if server_port is not None:
        payload["serverPort"] = server_port
    _run_async(_call(ctx, "open", **payload))


# ---------------------------------------------------------------------------
# get-references
# ---------------------------------------------------------------------------


@main.group(
    "references",
    help="Cross-references (get-references): to, from, both, function, referencers_decomp, import, thunk",
)
def references_grp() -> None:
    pass


@references_grp.command("run", help="Run get-references with --target and --mode")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--target",
    required=True,
    help="Address, symbol, function, or import name",
)
@click.option(
    "--mode",
    type=click.Choice(
        ["to", "from", "both", "function", "referencers_decomp", "import", "thunk"],
    ),
    default="both",
)
@click.option("--direction", type=click.Choice(["to", "from", "both"]))
@click.option("--offset", type=int)
@click.option("--limit", "--max-results", "limit", type=int)
@click.option("--library-name", "libraryName")
@click.option("--start-index", "startIndex", type=int)
@click.option("--max-referencers", "maxReferencers", type=int)
@click.option(
    "--include-ref-context/--no-include-ref-context",
    "includeRefContext",
    default=True,
)
@click.option(
    "--include-data-refs/--no-include-data-refs",
    "includeDataRefs",
    default=True,
)
@click.pass_context
def references_run(
    ctx: click.Context,
    program_path: str | None,
    target: str,
    mode: str,
    direction: str | None,
    offset: int | None,
    limit: int | None,
    library_name: str | None,
    start_index: int | None,
    max_referencers: int | None,
    include_ref_context: bool,
    include_data_refs: bool,
) -> None:
    payload: dict[str, Any] = {"target": target, "mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if direction is not None:
        payload["direction"] = direction
    if offset is not None:
        payload["offset"] = offset
    if limit is not None:
        payload["limit"] = limit
    if library_name is not None:
        payload["libraryName"] = library_name
    if start_index is not None:
        payload["startIndex"] = start_index
    if max_referencers is not None:
        payload["maxReferencers"] = max_referencers
    payload["includeRefContext"] = include_ref_context
    payload["includeDataRefs"] = include_data_refs
    _run_async(_call(ctx, "get-references", **payload))


# --- Convenience subcommands (``references to``, ``references from``, …) ---

def _references_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``references <mode>`` shorthand subcommands."""

    @references_grp.command(mode_name, help=help_text or f"get-references mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--target", required=True, help="Address, symbol, function, or import name")
    @click.option("--direction", type=click.Choice(["to", "from", "both"]))
    @click.option("--offset", type=int)
    @click.option("--limit", "--max-results", "limit", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        target: str,
        direction: str | None,
        offset: int | None,
        limit: int | None,
    ) -> None:
        payload: dict[str, Any] = {"target": target, "mode": mode_name}
        if program_path:
            payload["programPath"] = program_path
        if direction is not None:
            payload["direction"] = direction
        if offset is not None:
            payload["offset"] = offset
        if limit is not None:
            payload["limit"] = limit
        _run_async(_call(ctx, "get-references", **payload))

    return _cmd


for _mode in ("to", "from", "both", "function", "referencers_decomp", "import", "thunk"):
    _references_mode_command(_mode)


# ---------------------------------------------------------------------------
# manage-data-types
# ---------------------------------------------------------------------------


@main.group(
    "datatypes",
    help="Manage data types (manage-data-types): archives, list, by_string, apply",
)
def datatypes_grp() -> None:
    pass


@datatypes_grp.command("run", help="Run manage-data-types with --action")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--action",
    type=click.Choice(["archives", "list", "by_string", "apply"]),
    required=True,
)
@click.option("--archive-name", "archiveName")
@click.option("--category-path", "categoryPath", default="/")
@click.option("--include-subcategories", "includeSubcategories", is_flag=True)
@click.option("--start-index", "startIndex", type=int)
@click.option("--max-count", "maxCount", type=int)
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
    max_count: int | None,
    data_type_string: str | None,
    address_or_symbol: str | None,
) -> None:
    payload: dict[str, Any] = {"action": action}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if archive_name is not None:
        payload["archiveName"] = archive_name
    payload["categoryPath"] = category_path
    payload["includeSubcategories"] = include_subcategories
    if start_index is not None:
        payload["startIndex"] = start_index
    if max_count is not None:
        payload["maxCount"] = max_count
    if data_type_string is not None:
        payload["dataTypeString"] = data_type_string
    if address_or_symbol is not None:
        payload["addressOrSymbol"] = address_or_symbol
    _run_async(_call(ctx, "manage-data-types", **payload))


# --- Convenience subcommands (``datatypes archives``, ``datatypes list``, …) ---

def _datatypes_action_command(action_name: str, help_text: str | None = None):
    """Factory for ``datatypes <action>`` shorthand subcommands."""

    @datatypes_grp.command(action_name, help=help_text or f"manage-data-types action={action_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--archive-name", "archiveName")
    @click.option("--category-path", "categoryPath", default="/")
    @click.option("--include-subcategories", "includeSubcategories", is_flag=True)
    @click.option("--start-index", "startIndex", type=int)
    @click.option("--max-count", "maxCount", type=int)
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
        max_count: int | None,
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
        if max_count is not None:
            payload["maxCount"] = max_count
        if data_type_string is not None:
            payload["dataTypeString"] = data_type_string
        if address_or_symbol is not None:
            payload["addressOrSymbol"] = address_or_symbol
        _run_async(_call(ctx, "manage-data-types", **payload))

    return _cmd


for _action in ("archives", "list", "by_string", "apply"):
    _datatypes_action_command(_action)


# ---------------------------------------------------------------------------
# manage-structures
# ---------------------------------------------------------------------------


@main.group(
    "structures",
    help="Manage structures (manage-structures): parse, validate, create, add_field, modify_field, modify_from_c, info, apply, delete, parse_header",
)
def structures_grp() -> None:
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
    _run_async(_call(ctx, "manage-structures", **payload))


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
        _run_async(_call(ctx, "manage-structures", **payload))

    return _cmd


for _action in ("parse", "validate", "create", "add_field", "modify_field", "modify_from_c", "info", "apply", "delete", "parse_header"):
    _structures_action_command(_action)


# ---------------------------------------------------------------------------
# manage-comments
# ---------------------------------------------------------------------------


@main.group(
    "comments",
    help="Manage comments (manage-comments): set, get, remove, search, search_decomp",
)
def comments_grp() -> None:
    pass


@comments_grp.command("run", help="Run manage-comments with --action")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--action",
    type=click.Choice(["set", "get", "remove", "search", "search_decomp"]),
    required=True,
)
@click.option("--address-or-symbol", "addressOrSymbol")
@click.option("--function")
@click.option("--line-number", "lineNumber", type=int)
@click.option("--comment")
@click.option(
    "--comment-type",
    "commentType",
    type=click.Choice(["pre", "eol", "post", "plate", "repeatable"]),
)
@click.option("--comments", help="JSON array of comment objects")
@click.option("--start")
@click.option("--end")
@click.option("--comment-types", "commentTypes")
@click.option("--search-text", "searchText")
@click.option("--pattern")
@click.option("--case-sensitive", "caseSensitive", is_flag=True)
@click.option("--max-results", "maxResults", type=int)
@click.option(
    "--override-max-functions-limit",
    "overrideMaxFunctionsLimit",
    is_flag=True,
)
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
    max_results: int | None,
    override_max_functions_limit: bool,
) -> None:
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
    if max_results is not None:
        payload["maxResults"] = max_results
    payload["overrideMaxFunctionsLimit"] = override_max_functions_limit
    _run_async(_call(ctx, "manage-comments", **payload))


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
    @click.option("--max-results", "maxResults", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        address_or_symbol: str | None,
        function: str | None,
        comment: str | None,
        comment_type: str | None,
        search_text: str | None,
        max_results: int | None,
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
        if max_results is not None:
            payload["maxResults"] = max_results
        _run_async(_call(ctx, "manage-comments", **payload))

    return _cmd


for _action in ("set", "get", "remove", "search", "search_decomp"):
    _comments_action_command(_action)


# ---------------------------------------------------------------------------
# manage-bookmarks
# ---------------------------------------------------------------------------


@main.group(
    "bookmarks",
    help="Manage bookmarks (manage-bookmarks): set, get, search, remove, removeAll, categories",
)
def bookmarks_grp() -> None:
    pass


@bookmarks_grp.command("run", help="Run manage-bookmarks with --action")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--action",
    type=click.Choice(["set", "get", "search", "remove", "removeAll", "categories"]),
    required=True,
)
@click.option("--address-or-symbol", "addressOrSymbol")
@click.option(
    "--type",
    "type_",
    type=click.Choice(["Note", "Warning", "TODO", "Bug", "Analysis"]),
)
@click.option("--category")
@click.option("--comment")
@click.option("--bookmarks", help="JSON array of bookmark objects")
@click.option("--search-text", "searchText")
@click.option("--max-results", "maxResults", type=int)
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
    max_results: int | None,
    remove_all: bool,
) -> None:
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
    if max_results is not None:
        payload["maxResults"] = max_results
    payload["removeAll"] = remove_all
    _run_async(_call(ctx, "manage-bookmarks", **payload))


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
    @click.option("--max-results", "maxResults", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        address_or_symbol: str | None,
        type_: str | None,
        category: str | None,
        comment: str | None,
        search_text: str | None,
        max_results: int | None,
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
        if max_results is not None:
            payload["maxResults"] = max_results
        _run_async(_call(ctx, "manage-bookmarks", **payload))

    return _cmd


for _action in ("set", "get", "search", "remove", "categories"):
    _bookmarks_action_command(_action)


# ---------------------------------------------------------------------------
# analyze-data-flow
# ---------------------------------------------------------------------------


@main.command(
    "dataflow",
    help="Trace data flow (analyze-data-flow): backward, forward, variable_accesses",
)
@click.option("-b", "--binary", "program_path")
@click.option("--function-address", "functionAddress", required=True)
@click.option("--start-address", "startAddress")
@click.option("--variable-name", "variableName")
@click.option(
    "--direction",
    type=click.Choice(["backward", "forward", "variable_accesses"]),
    required=True,
)
@click.pass_context
def dataflow(
    ctx: click.Context,
    program_path: str | None,
    function_address: str,
    start_address: str | None,
    variable_name: str | None,
    direction: str,
) -> None:
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
    _run_async(_call(ctx, "analyze-data-flow", **payload))


# ---------------------------------------------------------------------------
# get-call-graph
# ---------------------------------------------------------------------------


@main.group(
    "callgraph",
    help="Call graph (get-call-graph): graph, tree, callers, callees, callers_decomp, common_callers",
)
def callgraph_grp() -> None:
    pass


@callgraph_grp.command("run", help="Run get-call-graph")
@click.option("-b", "--binary", "program_path")
@click.option("--function", "functionIdentifier", required=True)
@click.option(
    "--mode",
    type=click.Choice(
        ["graph", "tree", "callers", "callees", "callers_decomp", "common_callers"],
    ),
    default="graph",
)
@click.option("--depth", type=int)
@click.option("--direction", type=click.Choice(["callers", "callees"]))
@click.option("--max-depth", "maxDepth", type=int)
@click.option("--start-index", "startIndex", type=int)
@click.option("--max-callers", "maxCallers", type=int)
@click.option(
    "--include-call-context/--no-include-call-context",
    "includeCallContext",
    default=True,
)
@click.option(
    "--function-addresses",
    "functionAddresses",
    help="Comma-separated for common_callers",
)
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
    _run_async(_call(ctx, "get-call-graph", **payload))


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
        _run_async(_call(ctx, "get-call-graph", **payload))

    return _cmd


for _mode in ("graph", "tree", "callers", "callees", "callers_decomp", "common_callers"):
    _callgraph_mode_command(_mode)


# ---------------------------------------------------------------------------
# search-constants
# ---------------------------------------------------------------------------


@main.group(
    "constants",
    help="Search constants (search-constants): specific, range, common",
)
def constants_grp() -> None:
    pass


@constants_grp.command("run", help="Run search-constants")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--mode",
    type=click.Choice(["specific", "range", "common"]),
    required=True,
)
@click.option("--value")
@click.option("--min-value", "minValue")
@click.option("--max-value", "maxValue")
@click.option("--max-results", "maxResults", type=int)
@click.option("--include-small-values", "includeSmallValues", is_flag=True)
@click.option("--top-n", "topN", type=int)
@click.pass_context
def constants_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    value: str | None,
    min_value: str | None,
    max_value: str | None,
    max_results: int | None,
    include_small_values: bool,
    top_n: int | None,
) -> None:
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if value is not None:
        payload["value"] = value
    if min_value is not None:
        payload["minValue"] = min_value
    if max_value is not None:
        payload["maxValue"] = max_value
    if max_results is not None:
        payload["maxResults"] = max_results
    payload["includeSmallValues"] = include_small_values
    if top_n is not None:
        payload["topN"] = top_n
    _run_async(_call(ctx, "search-constants", **payload))


# --- Convenience subcommands (``constants specific``, ``constants range``, …) ---

def _constants_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``constants <mode>`` shorthand subcommands."""

    @constants_grp.command(mode_name, help=help_text or f"search-constants mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--value")
    @click.option("--min-value", "minValue")
    @click.option("--max-value", "maxValue")
    @click.option("--max-results", "maxResults", type=int)
    @click.option("--top-n", "topN", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        value: str | None,
        min_value: str | None,
        max_value: str | None,
        max_results: int | None,
        top_n: int | None,
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
        if max_results is not None:
            payload["maxResults"] = max_results
        if top_n is not None:
            payload["topN"] = top_n
        _run_async(_call(ctx, "search-constants", **payload))

    return _cmd


for _mode in ("specific", "range", "common"):
    _constants_mode_command(_mode)


# ---------------------------------------------------------------------------
# analyze-vtables
# ---------------------------------------------------------------------------


@main.group(
    "vtables",
    help="Analyze vtables (analyze-vtables): analyze, callers, containing",
)
def vtables_grp() -> None:
    pass


@vtables_grp.command("run", help="Run analyze-vtables")
@click.option("-b", "--binary", "program_path")
@click.option(
    "--mode",
    type=click.Choice(["analyze", "callers", "containing"]),
    required=True,
)
@click.option("--vtable-address", "vtableAddress")
@click.option("--function-address", "functionAddress")
@click.option("--max-entries", "maxEntries", type=int)
@click.option("--max-results", "maxResults", type=int)
@click.pass_context
def vtables_run(
    ctx: click.Context,
    program_path: str | None,
    mode: str,
    vtable_address: str | None,
    function_address: str | None,
    max_entries: int | None,
    max_results: int | None,
) -> None:
    payload: dict[str, Any] = {"mode": mode}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    if vtable_address is not None:
        payload["vtableAddress"] = vtable_address
    if function_address is not None:
        payload["functionAddress"] = function_address
    if max_entries is not None:
        payload["maxEntries"] = max_entries
    if max_results is not None:
        payload["maxResults"] = max_results
    _run_async(_call(ctx, "analyze-vtables", **payload))


# --- Convenience subcommands (``vtables analyze``, ``vtables callers``, …) ---

def _vtables_mode_command(mode_name: str, help_text: str | None = None):
    """Factory for ``vtables <mode>`` shorthand subcommands."""

    @vtables_grp.command(mode_name, help=help_text or f"analyze-vtables mode={mode_name}")
    @click.option("-b", "--binary", "program_path")
    @click.option("--vtable-address", "vtableAddress")
    @click.option("--function-address", "functionAddress")
    @click.option("--max-entries", "maxEntries", type=int)
    @click.option("--max-results", "maxResults", type=int)
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        program_path: str | None,
        vtable_address: str | None,
        function_address: str | None,
        max_entries: int | None,
        max_results: int | None,
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
        if max_results is not None:
            payload["maxResults"] = max_results
        _run_async(_call(ctx, "analyze-vtables", **payload))

    return _cmd


for _mode in ("analyze", "callers", "containing"):
    _vtables_mode_command(_mode)


# ---------------------------------------------------------------------------
# suggest
# ---------------------------------------------------------------------------


@main.command(
    "suggest",
    help="Context-aware suggestions (suggest): comments, names, tags, types",
)
@click.option("-b", "--binary", "program_path", required=True)
@click.option("--suggestion-type", "suggestionType", required=True)
@click.option("--address")
@click.option("--function")
@click.option("--data-type", "dataType")
@click.option("--variable-address", "variableAddress")
@click.pass_context
def suggest_cmd(
    ctx: click.Context,
    program_path: str,
    suggestion_type: str,
    address: str | None,
    function: str | None,
    data_type: str | None,
    variable_address: str | None,
) -> None:
    payload: dict[str, Any] = {
        "programPath": program_path,
        "suggestionType": suggestion_type,
    }
    if address is not None:
        payload["address"] = address
    if function is not None:
        payload["function"] = function
    if data_type is not None:
        payload["dataType"] = data_type
    if variable_address is not None:
        payload["variableAddress"] = variable_address
    _run_async(_call(ctx, "suggest", **payload))


# ---------------------------------------------------------------------------
# Project: checkin, analyze, change-processor, manage-files, get-current-*, open-in-code-browser
# ---------------------------------------------------------------------------


@main.command("checkin", help="Checkin program (checkin-program)")
@click.option("-b", "--binary", "program_path", required=True)
@click.option("-m", "--message", required=True)
@click.option("--keep-checked-out", "keepCheckedOut", is_flag=True)
@click.pass_context
def checkin(
    ctx: click.Context,
    program_path: str,
    message: str,
    keep_checked_out: bool,
) -> None:
    _run_async(
        _call(
            ctx,
            "checkin-program",
            programPath=program_path,
            message=message,
            keepCheckedOut=keep_checked_out,
        ),
    )


@main.command("analyze", help="Run auto-analysis (analyze-program)")
@click.option("-b", "--binary", "program_path", required=True)
@click.pass_context
def analyze(ctx: click.Context, program_path: str) -> None:
    _run_async(_call(ctx, "analyze-program", programPath=program_path))


@main.command("change-processor", help="Change processor (change-processor)")
@click.option("-b", "--binary", "program_path", required=True)
@click.option("--language-id", "languageId", required=True)
@click.option("--compiler-spec-id", "compilerSpecId")
@click.pass_context
def change_processor(
    ctx: click.Context,
    program_path: str,
    language_id: str,
    compiler_spec_id: str | None,
) -> None:
    payload: dict[str, Any] = {"programPath": program_path, "languageId": language_id}
    if compiler_spec_id is not None:
        payload["compilerSpecId"] = compiler_spec_id
    _run_async(_call(ctx, "change-processor", **payload))


@main.group(
    "files",
    help="Manage files/repositories (manage-files): list, info, create, edit, move, import/export, checkout",
)
def files_grp() -> None:
    pass


@files_grp.command("run", help="Run manage-files with --operation")
@click.option(
    "--operation",
    type=click.Choice(
        [
            "import",
            "export",
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
        ]
    ),
    required=True,
)
@click.option("--path")
@click.option("-b", "--binary", "program_path")
@click.option("--new-path", "new_path")
@click.option("--new-name", "new_name")
@click.option("--content")
@click.option("--encoding", default="utf-8")
@click.option("--create-parents/--no-create-parents", "create_parents", default=True)
@click.option("--destination-folder", "destinationFolder", default="/")
@click.option("--recursive/--no-recursive", default=True)
@click.option("--max-results", "max_results", type=int)
@click.option("--max-depth", "maxDepth", type=int)
@click.option(
    "--analyze-after-import/--no-analyze-after-import",
    "analyzeAfterImport",
    default=True,
)
@click.option(
    "--strip-leading-path/--no-strip-leading-path",
    "stripLeadingPath",
    default=True,
)
@click.option("--strip-all-container-path", "stripAllContainerPath", is_flag=True)
@click.option("--mirror-fs", "mirrorFs", is_flag=True)
@click.option(
    "--enable-version-control/--no-enable-version-control",
    "enableVersionControl",
    default=True,
)
@click.option(
    "--export-type",
    "exportType",
    type=click.Choice(["program", "function_info", "strings"]),
)
@click.option("--format", "format_", type=click.Choice(["json", "csv"]))
@click.option("--include-parameters", "includeParameters", is_flag=True)
@click.option("--include-variables", "includeVariables", is_flag=True)
@click.option("--include-comments", "includeComments", is_flag=True)
@click.option("--keep", is_flag=True)
@click.option("--force", is_flag=True)
@click.option("--exclusive", is_flag=True)
@click.pass_context
def files_run(
    ctx: click.Context,
    operation: str,
    path: str | None,
    program_path: str | None,
    new_path: str | None,
    new_name: str | None,
    content: str | None,
    encoding: str,
    create_parents: bool,
    destination_folder: str,
    recursive: bool,
    max_results: int | None,
    max_depth: int | None,
    analyze_after_import: bool,
    strip_leading_path: bool,
    strip_all_container_path: bool,
    mirror_fs: bool,
    enable_version_control: bool,
    export_type: str | None,
    format_: str | None,
    include_parameters: bool,
    include_variables: bool,
    include_comments: bool,
    keep: bool,
    force: bool,
    exclusive: bool,
) -> None:
    payload: dict[str, Any] = {"operation": operation}
    if path is not None:
        payload["path"] = path
    if program_path is not None:
        payload["programPath"] = program_path
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
    if max_results is not None:
        payload["maxResults"] = max_results
    if max_depth is not None:
        payload["maxDepth"] = max_depth
    payload["analyzeAfterImport"] = analyze_after_import
    payload["stripLeadingPath"] = strip_leading_path
    payload["stripAllContainerPath"] = strip_all_container_path
    payload["mirrorFs"] = mirror_fs
    payload["enableVersionControl"] = enable_version_control
    if export_type is not None:
        payload["exportType"] = export_type
    if format_ is not None:
        payload["format"] = format_
    payload["includeParameters"] = include_parameters
    payload["includeVariables"] = include_variables
    payload["includeComments"] = include_comments
    payload["keep"] = keep
    payload["force"] = force
    payload["exclusive"] = exclusive
    _run_async(_call(ctx, "manage-files", **payload))


@main.command("current-program", help="Get current program (get-current-program, GUI)")
@click.option("-b", "--binary", "program_path")
@click.pass_context
def current_program(ctx: click.Context, program_path: str | None) -> None:
    payload: dict[str, Any] = {}
    if program_path is not None and program_path.strip():
        payload["programPath"] = program_path
    _run_async(_call(ctx, "get-current-program", **payload))


@main.command("current-address", help="Get current address (get-current-address, GUI)")
@click.pass_context
def current_address(ctx: click.Context) -> None:
    _run_async(_call(ctx, "get-current-address"))


@main.command(
    "current-function",
    help="Get current function (get-current-function, GUI)",
)
@click.pass_context
def current_function(ctx: click.Context) -> None:
    _run_async(_call(ctx, "get-current-function"))


@main.command(
    "open-in-code-browser",
    help="Open program in Code Browser (open-program-in-code-browser, GUI)",
)
@click.option("-b", "--binary", "program_path", required=True)
@click.pass_context
def open_in_code_browser(ctx: click.Context, program_path: str) -> None:
    _run_async(_call(ctx, "open-program-in-code-browser", programPath=program_path))


@main.command(
    "open-all-in-code-browser",
    help="Open all programs matching extensions in Code Browser (open-all-programs-in-code-browser, GUI)",
)
@click.option(
    "--extensions",
    default="exe,dll",
    help="Comma-separated file extensions to open (default: exe,dll)",
)
@click.option(
    "--folder-path",
    "folderPath",
    default="/",
    help="Project folder to search (default: /)",
)
@click.pass_context
def open_all_in_code_browser(
    ctx: click.Context,
    extensions: str,
    folder_path: str,
) -> None:
    _run_async(
        _call(
            ctx,
            "open-all-programs-in-code-browser",
            extensions=extensions,
            folderPath=folder_path,
        ),
    )


# ---------------------------------------------------------------------------
# capture-agentdecompile-debug-info
# ---------------------------------------------------------------------------


@main.command(
    "debug-info",
    help="Capture debug info zip (capture-agentdecompile-debug-info)",
)
@click.option("--message")
@click.pass_context
def debug_info(ctx: click.Context, message: str | None) -> None:
    payload: dict[str, Any] = {}
    if message:
        payload["message"] = message
    _run_async(_call(ctx, "capture-agentdecompile-debug-info", **payload))


# ---------------------------------------------------------------------------
# delete (stub)
# ---------------------------------------------------------------------------


@main.command("delete", help="Delete program (not implemented in AgentDecompile)")
@click.option("-b", "--binary", "program_path", required=True)
def delete_cmd(program_path: str) -> None:
    click.echo("Delete program is not implemented in AgentDecompile.", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Convenience aliases (match previous CLI / pyghidra-mcp style)
# ---------------------------------------------------------------------------


@main.command("import", help="Import a binary into the project (open with path)")
@click.argument("path", type=click.Path(exists=False))
@click.option("--no-analyze", is_flag=True, help="Skip analysis after import")
@click.pass_context
def import_cmd(ctx: click.Context, path: str, no_analyze: bool) -> None:
    opts = ctx.ensure_object(dict)
    host = opts.get("host", "127.0.0.1")
    is_remote = host not in ("127.0.0.1", "localhost", "::1")
    # Only resolve path locally when connecting to a local server;
    # for remote servers the path refers to the remote filesystem.
    resolved_path = path if is_remote else str(Path(path).resolve())
    _run_async(
        _call(
            ctx,
            "open",
            path=resolved_path,
            analyzeAfterImport=not no_analyze,
        ),
    )


# Alias for pyghidra-mcp compatibility (Click's command() treats second positional as cls)
main.add_command(main.commands["import"], "import-binary")


@main.command("read", help="Read bytes at address (inspect-memory mode=read)")
@click.option("-b", "--binary", "program_path", required=True)
@click.argument("address")
@click.option("-s", "--size", "length", type=int, default=32)
@click.pass_context
def read_cmd(ctx: click.Context, program_path: str, address: str, length: int) -> None:
    _run_async(
        _call(
            ctx,
            "inspect-memory",
            programPath=program_path,
            mode="read",
            address=address,
            length=length,
        ),
    )


@main.command("metadata", help="Binary metadata (get-current-program)")
@click.option("-b", "--binary", "program_path", required=True)
@click.pass_context
def metadata_cmd(ctx: click.Context, program_path: str) -> None:
    _run_async(_call(ctx, "get-current-program", programPath=program_path))


# ---------------------------------------------------------------------------
# eval – execute arbitrary Ghidra/PyGhidra API code (execute-script)
# ---------------------------------------------------------------------------


@main.command(
    "eval",
    help=(
        "Execute Ghidra/PyGhidra API code on the server. "
        "The full Ghidra API is available (currentProgram, flatApi, toAddr, …). "
        "Example: eval -b /myapp 'currentProgram.getName()'"
    ),
)
@click.argument("code")
@click.option(
    "-b",
    "--binary",
    "program_path",
    help="Program path in the project (optional in GUI mode)",
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
    kwargs: dict[str, Any] = {"code": code, "timeout": timeout}
    if program_path:
        kwargs["programPath"] = program_path
    _run_async(_call(ctx, "execute-script", **kwargs))


# ---------------------------------------------------------------------------
# Generic tool call (any MCP tool by name + JSON args)
# ---------------------------------------------------------------------------


@main.command(
    "tool",
    help='Call any MCP tool by name with JSON arguments. Example: tool get-data \'{"programPath":"/a","addressOrSymbol":"0x1000"}\'',
)
@click.argument("name", required=True)
@click.argument(
    "arguments",
    required=False,
    default="{}",
)
@click.option(
    "--list-tools",
    is_flag=True,
    help="List valid tool names and exit",
)
@click.pass_context
def tool_cmd(
    ctx: click.Context,
    name: str,
    arguments: str,
    list_tools: bool,
) -> None:
    """Invoke any MCP tool by name; arguments as JSON object (camelCase keys)."""
    available_tools = tool_registry.get_tools()
    if list_tools:
        click.echo("Valid tool names:")
        for t in sorted(available_tools):
            click.echo(f"  {t}")
        return

    payload = _parse_tool_payload(arguments)
    _validate_known_tool(name)
    _run_async(_call(ctx, name, **payload))


@main.command(
    "tool-seq",
    help=(
        "Run a sequence of MCP tool calls from JSON. "
        "Format: [{\"name\":\"open\",\"arguments\":{...}}, ...]"
    ),
)
@click.argument("steps", required=True)
@click.option("--continue-on-error", is_flag=True, help="Continue remaining steps after a tool failure")
@click.pass_context
def tool_seq_cmd(ctx: click.Context, steps: str, continue_on_error: bool) -> None:
    """Invoke a sequence of tools without using ad-hoc python scripts."""
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
            data = await _call_raw(ctx, name, arguments)
            step_result = {
                "index": index,
                "name": name,
                "success": not (
                    isinstance(data, dict)
                    and data.get("success") is False
                    and "error" in data
                ),
                "result": data,
            }
            results.append(step_result)

            if not step_result["success"] and not continue_on_error:
                click.echo(format_output({"success": False, "steps": results}, _fmt(ctx)))
                sys.exit(1)

        click.echo(format_output({"success": True, "steps": results}, _fmt(ctx)))

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
