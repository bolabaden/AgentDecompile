from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re

from argparse import Namespace
from pathlib import Path
from time import time
from typing import TYPE_CHECKING, Any

from pyghidra import HeadlessPyGhidraLauncher, open_program

from agentdecompile_cli.ghidrecomp.bsim import gen_bsim_sigs_for_program, has_bsim
from agentdecompile_cli.ghidrecomp.callgraph import gen_callgraph
from agentdecompile_cli.ghidrecomp.sast import check_tools, generate_sast_summary, preprocess_c_files, run_codeql_scan, run_semgrep_scan
from agentdecompile_cli.ghidrecomp.utility import analyze_program, apply_gdt, get_pdb, save_program_as_gzf, set_pdb, set_remote_pdbs, setup_symbol_server
from agentdecompile_cli.tools.decompile_tool import DecompileTool

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    from ghidra.app.decompiler import (
        DecompInterface as GhidraDecompInterface,
        DecompileResults as GhidraDecompileResults,
    )
    from ghidra.program.model.listing import (
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra_builtins import *

MAX_PATH_LEN = 50


def get_filename(func: GhidraFunction) -> str:
    return f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}"


def get_md5_file_digest(path: str) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    path = Path(path)

    md5 = hashlib.md5()

    with path.open("rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)

    return f"{md5.hexdigest()}"


def gen_proj_bin_name_from_path(path: Path) -> str:
    """Generate unique project name from binary for Ghidra Project"""
    return "-".join((path.name, get_md5_file_digest(path.absolute())[:6]))


def get_bin_output_path(output_path: Path, bin_name: str) -> Path:
    return Path(output_path) / "results" / "bins" / bin_name


def setup_decompliers(
    program: GhidraProgram,
    thread_count: int = 2,
) -> dict[int, GhidraDecompInterface]:
    """Setup decompliers to use during diff bins. Each one must be initialized with a program."""
    from ghidra.app.decompiler import (
        DecompInterface as GhidraDecompInterface,
        DecompileOptions as GhidraDecompileOptions,
    )

    decompilers: dict[int, GhidraDecompInterface] = {}
    decomp_options = GhidraDecompileOptions()
    decomp_options.grabFromProgram(program)

    for i in range(thread_count):
        decompilers.setdefault(i, GhidraDecompInterface())
        decompilers[i].setOptions(decomp_options)
        decompilers[i].openProgram(program)

    print(f"Setup {thread_count} decompliers")

    return decompilers


def decompile_func(
    func: GhidraFunction,
    decompilers: dict[int, GhidraDecompInterface],
    thread_id: int = 0,
    timeout: int = 0,
    monitor: Any | None = None,
) -> list[str | None]:
    """Decompile function and return [funcname, decompilation]

    This function now delegates to the unified DecompileTool for consistency
    between MCP provider and CLI interfaces.
    """
    try:
        # Create unified tool instance with the appropriate decompiler
        if thread_id not in decompilers:
            raise ValueError(f"No decompiler available for thread {thread_id}")

        # Create a minimal program info for the unified tool
        from agentdecompile_cli.context import ProgramInfo

        program = func.getProgram()
        program_info = ProgramInfo(
            program_path=str(program.getExecutablePath()),
            current_program=program,
            project=None,
            domain_file=None,
        )

        decompile_tool = DecompileTool(program_info, decompilers[thread_id])

        # Use unified tool's CLI interface method
        return decompile_tool.decompile_function_for_cli(
            func=func,
            decompilers=decompilers,
            thread_id=thread_id,
            timeout=timeout,
            monitor=monitor,
        )

    except Exception as e:
        print(f"Error using unified decompile tool: {e}")
        # Fallback to original implementation if unified tool fails
        return _decompile_func_fallback(func, decompilers, thread_id, timeout, monitor)


def _decompile_func_fallback(
    func: GhidraFunction,
    decompilers: dict[int, GhidraDecompInterface],
    thread_id: int = 0,
    timeout: int = 0,
    monitor: Any | None = None,
) -> list[str | None]:
    """Fallback implementation for backward compatibility."""
    from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor

    if monitor is None:
        monitor = GhidraConsoleTaskMonitor()

    result: GhidraDecompileResults = decompilers[thread_id].decompileFunction(func, timeout, monitor)

    if result.getErrorMessage() == "":
        code = result.decompiledFunction.getC()
        sig = result.decompiledFunction.getSignature()
    else:
        code = result.getErrorMessage()
        sig = None

    return [get_filename(func), code, sig]


def decompile_to_single_file(
    path: Path,
    prog: GhidraProgram,
    create_header: bool = True,
    create_file: bool = True,
    emit_types: bool = True,
    exclude_tags: bool = False,
    tags: str | None = None,
    verbose: bool = True,
) -> None:
    """Use Ghidra's CppExporter to decompile all functions to a single file"""
    from ghidra.app.util.exporter import CppExporter as GhidraCppExporter
    from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor
    from java.io import File

    c_file = File(path.absolute())

    if verbose:
        monitor = GhidraConsoleTaskMonitor()
    else:
        monitor = GhidraConsoleTaskMonitor().DUMMY

    try:
        # Ghidra CppExporter before 10.3.3 and later
        decompiler = GhidraCppExporter(None, create_header, create_file, emit_types, exclude_tags, tags)
    except TypeError:
        # Ghidra CppExporter before 10.3.3
        decompiler = GhidraCppExporter(create_header, create_file, emit_types, exclude_tags, tags)

    decompiler.export(c_file, prog, prog.getMemory(), monitor)


def decompile(
    args: Namespace,
) -> tuple[
    list[GhidraFunction],
    list[list[str | None]],
    Path,
    str,
    str,
    list[list[Any]],
    list[str],
]:
    print(f"Starting decompliations: {args}")

    bin_path = Path(args.bin)
    bin_proj_name = gen_proj_bin_name_from_path(bin_path)
    thread_count = args.thread_count

    output_path = Path(args.output_path)
    bin_output_path = get_bin_output_path(output_path, bin_proj_name)
    decomp_path = bin_output_path / "decomps"
    output_path.mkdir(exist_ok=True, parents=True)
    bin_output_path.mkdir(exist_ok=True, parents=True)
    decomp_path.mkdir(exist_ok=True, parents=True)

    if args.project_path == "ghidra_projects":
        project_location = output_path / args.project_path
    else:
        project_location = Path(args.project_path)

    gzf_path = None
    if args.gzf:
        if args.gzf_path == "gzfs":
            gzf_path = output_path / args.gzf_path
        else:
            gzf_path = Path(args.gzf_path)

        gzf_path.mkdir(exist_ok=True, parents=True)

    if args.symbols_path == "symbols":
        symbols_path = output_path / args.symbols_path
    else:
        symbols_path = Path(args.symbols_path)

    if args.bsim_sig_path == "bsim_xmls":
        bsim_sig_path = output_path / args.bsim_sig_path
    else:
        bsim_sig_path = output_path / Path(args.bsim_sig_path)

    # turn on verbose
    launcher = HeadlessPyGhidraLauncher(True)

    # set max % of host RAM
    launcher.add_vmargs(f"-XX:MaxRAMPercentage={args.max_ram_percent}")
    if args.print_flags:
        launcher.add_vmargs("-XX:+PrintFlagsFinal")

    try:
        launcher.start()
    except ValueError as e:
        if "minimum required version" in str(e).lower():
            print("\nError:")
            print(f"[Version Error] {e}")
            print("Resolution options:")
            print("  - Upgrade Ghidra to version 12.0 or newer")
            print("  - OR downgrade pyghidra to 2.2.1 for Ghidra 11.x")
            print("    Run: pip install pyghidra==2.2.1")
            exit(1)
        raise e

    from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor

    monitor = GhidraConsoleTaskMonitor()

    # Setup and analyze project
    with open_program(bin_path, project_location=project_location, project_name=bin_proj_name, analyze=False) as flat_api:
        program: GhidraProgram = flat_api.getCurrentProgram()

        if not args.skip_symbols:
            if args.sym_file_path:
                set_pdb(program, args.sym_file_path)
            else:
                setup_symbol_server(symbols_path)

                set_remote_pdbs(program, True)

            pdb = get_pdb(program)
            if pdb is None:
                print(f"Failed to find pdb for {program}")

        # apply GDT
        if args.gdt:
            for gdt_path in args.gdt:
                print(f"Applying gdt {gdt_path}...")
                apply_gdt(program, gdt_path, verbose=args.va)

        gdt_names = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            print(f"Using file gdts: {gdt_names}")

        # analyze program if we haven't yet
        analyze_program(program, verbose=args.va, force_analysis=args.fa, gzf_path=gzf_path)

    # Save copy of program in gzf after analysis
    if args.gzf:
        from ghidra.base.project import GhidraProject as GhidraGhidraProject

        try:
            project = GhidraGhidraProject.openProject(Path(project_location / bin_proj_name), bin_proj_name, True)
            program = project.openProgram("/", bin_path.name, True)
            save_program_as_gzf(program, gzf_path / bin_proj_name, project)
        finally:
            project.close(program)
            project.close()

    # decompile and callgraph all the things
    with open_program(bin_path, project_location=project_location, project_name=bin_proj_name, analyze=False) as flat_api:
        all_funcs: list[GhidraFunction] = []
        skip_count: int = 0

        program: GhidraProgram = flat_api.getCurrentProgram()

        for f in program.functionManager.getFunctions(True):
            if args.filters:
                if any([re.search(fil, f.name, re.IGNORECASE) for fil in args.filters]):
                    all_funcs.append(f)
                else:
                    skip_count += 1
            else:
                all_funcs.append(f)

        if skip_count > 0:
            print(f"Skipped {skip_count} functions that failed to match any of {args.filters}")

        decompilations: list[list[str | None]] = []
        callgraphs: list[list[Any]] = []

        if args.cppexport:
            print(f"Decompiling {len(all_funcs)} functions using Ghidra's CppExporter")
            c_file = decomp_path / Path(bin_path.name + ".c")
            start = time()
            decompile_to_single_file(c_file, program)
            print(f"Decompiled {len(all_funcs)} functions for {program.name} in {time() - start}")
            print(f"Wrote results to {c_file} and {c_file.stem + '.h'}")
        else:
            print(f"Decompiling {len(all_funcs)} functions using {thread_count} threads")

            decompilers = setup_decompliers(program, thread_count)
            completed: int = 0

            # Decompile all files
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (
                    executor.submit(decompile_func, func, decompilers, thread_id % thread_count, monitor=monitor)
                    for thread_id, func in enumerate(all_funcs)
                    if args.skip_cache or not (decomp_path / (get_filename(func) + ".c")).exists()
                )

                for future in concurrent.futures.as_completed(futures):
                    decompilations.append(future.result())
                    completed += 1
                    if (completed % 100) == 0:
                        print(f"Decompiled {completed} and {int(completed / len(all_funcs) * 100)}%")

            print(f"Decompiled {completed} functions for {program.name} in {time() - start}")
            print(f"{len(all_funcs) - completed} decompilations already existed.")

            # Save all decomps
            start = time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = (executor.submit((decomp_path / (name + ".c")).write_text, decomp) for name, decomp, sig in decompilations)

                for future in concurrent.futures.as_completed(futures):
                    pass

            print(f"Wrote {completed} decompilations for {program.name} to {decomp_path} in {time() - start}")

            # Generate callgrpahs for functions
            if args.callgraphs:
                start = time()
                completed = 0
                callgraph_path = bin_output_path / "callgraphs"
                callgraphs_completed_path = callgraph_path / "completed_callgraphs.json"
                if callgraphs_completed_path.exists():
                    callgraphs_completed = json.loads(callgraphs_completed_path.read_text())
                else:
                    callgraphs_completed = []

                callgraph_path.mkdir(exist_ok=True)

                if args.cg_direction == "both":
                    directions = ["called", "calling"]
                else:
                    directions = [args.cg_direction]

                max_display_depth = None
                if args.max_display_depth is not None:
                    max_display_depth = int(args.max_display_depth)

                with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = (
                        executor.submit(
                            gen_callgraph,
                            func,
                            max_display_depth,
                            direction,
                            args.max_time_cg_gen,
                            get_filename(func),
                            not args.no_call_refs,
                            args.condense_threshold,
                            args.top_layers,
                            args.bottom_layers,
                            wrap_mermaid=True,
                        )
                        for direction in directions
                        for func in all_funcs
                        if args.skip_cache or (get_filename(func) not in callgraphs_completed and re.search(args.callgraph_filter, func.name) is not None)
                    )

                    for future in concurrent.futures.as_completed(futures):
                        callgraphs.append(future.result())
                        name, direction, callgraph, graphs = callgraphs[-1]

                        for ctype, chart in graphs:
                            if ctype == "mermaid_url":
                                # Special case: write the URL into its own md file
                                (callgraph_path / f"{name}.url.{direction}.md").write_text(chart)
                            else:
                                # Normal case: write chart content
                                (callgraph_path / f"{name}.{ctype}.{direction}.md").write_text(chart)

                        callgraphs_completed.append(name)

                        completed += 1
                        if (completed % 100) == 0:
                            per_complete = int(completed / len(all_funcs) * 100 * len(directions))
                            print(f"\nGenerated callgraph {completed} and {per_complete}%\n")

                callgraphs_completed_path.write_text(json.dumps(callgraphs_completed))
                print(f"Callgraphed {completed} functions for {program.name} in {time() - start}")
                print(f"Wrote {completed} callgraphs for {program.name} to {callgraph_path} in {time() - start}")
                print(f"{len(all_funcs) - completed} callgraphs already existed.")

        # BSim
        _gensig = None
        _manager = None
        if args.bsim:
            if has_bsim():
                start = time()
                print(f"Generating BSim sigs for {len(all_funcs)} functions for {program.name}")
                sig_name, func_count, cat_count = gen_bsim_sigs_for_program(program, bsim_sig_path, args.bsim_template, args.bsim_cat, all_funcs)
                print(f"Generated BSim sigs for {func_count} functions in {time() - start}")
                print(f"Sigs are in {bsim_sig_path / sig_name}")
            else:
                print("WARN: Skipping BSim. BSim not present")

        # SAST scanning
        sast_sarifs: list[str] = []
        if args.sast:
            print("Running SAST scanning...")
            try:
                check_tools()
                # Parse rules
                semgrep_rules: list[str] = []
                if args.semgrep_rules:
                    # Handle both multiple --semgrep-rules arguments and comma-separated values
                    for rule_arg in args.semgrep_rules:
                        semgrep_rules.extend([r.strip() for r in rule_arg.split(",") if r.strip()])
                codeql_rules: list[str] = args.codeql_rules.split(",") if args.codeql_rules else []

                # Preprocess decompiled files for SAST analysis
                preprocess_c_files(decomp_path)

                # Run semgrep
                sast_path = bin_output_path / "sast"
                sarif_path = run_semgrep_scan(decomp_path, semgrep_rules, sast_path / "semgrep.sarif")
                sast_sarifs.append(sarif_path)

                # Run CodeQL (placeholder)
                codeql_sarif_path = run_codeql_scan(decomp_path, codeql_rules, sast_path / "codeql.sarif")
                if codeql_sarif_path:
                    sast_sarifs.append(codeql_sarif_path)

                # Generate SAST summary
                if sast_sarifs:
                    try:
                        summary = generate_sast_summary(sast_sarifs, str(decomp_path))
                        summary_path = sast_path / "sast_summary.json"
                        with summary_path.open("w") as f:
                            json.dump(summary, f, indent=2)
                        print(f"SAST summary written to {summary_path}")
                        print(f"Total findings: {summary['total_findings']}, Files scanned: {summary['files_scanned']}")
                    except Exception as e:
                        print(f"Warning: Failed to generate SAST summary: {e.__class__.__name__}: {e}")

                print(f"SAST scanning completed for {program.name}")

            except RuntimeError as e:
                print(f"Error during SAST scanning: {e.__class__.__name__}: {e}")

        return (all_funcs, decompilations, bin_output_path, str(program.compiler), str(program.languageID), callgraphs, sast_sarifs)
