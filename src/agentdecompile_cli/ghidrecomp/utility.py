from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra

    from ghidra_builtins import *  # noqa: F403


def analyze_program(
    program: ghidra.program.model.listing.Program,
    verbose: bool = False,
    force_analysis: bool = False,
    save: bool = False,
    gzf_path: Path | None = None,
) -> None:
    """Modified pyghidra.core._analyze_program"""
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import ConsoleTaskMonitor

    if verbose:
        print("Enabling verbose analysis...")
        monitor = ConsoleTaskMonitor()
        flat_api = FlatProgramAPI(program, monitor)
    else:
        flat_api = FlatProgramAPI(program)

    if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis:
        print(f"Analyzing program {program.name}...")

        GhidraScriptUtil.acquireBundleHostReference()
        try:
            print("Running analyzers...")
            flat_api.analyzeAll(program)
            if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                GhidraProgramUtilities.setAnalyzedFlag(program, True)
            elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                GhidraProgramUtilities.markProgramAnalyzed(program)
            else:
                raise Exception("Missing set analyzed flag method!")

            if save:
                flat_api.saveProgram(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
    else:
        print(f"{program} already analyzed... skipping")


def save_program_as_gzf(
    program: ghidra.program.model.listing.Program,
    gzf_path: Path,
    project: ghidra.framework.model.Project,
) -> None:
    from java.io import File

    # from java.io import IOException
    print(f"Saving gzf archive to {gzf_path}.gzf")

    # GhidraProject.saveAsPackedFile(program, File(f'{gzf_path.absolute()},{program.name}.gzf'), True)
    # project.close()
    project.saveAsPackedFile(program, File(f"{gzf_path}.gzf"), True)


def setup_symbol_server(
    symbols_path: str | Path,
    level: int = 1,
    server_urls: Sequence[str] | None = None,
) -> None:
    """Setup symbols to allow Ghidra to download as needed
    1. Configures symbol_path as local symbol store path
    2. Sets Index level for local symbol path
    - Level 0 indexLevel is a special Ghidra construct - plain directory with a collection of Pdb files
    - Level 1, with pdb files stored directly underthe root directory
    - Level 2, using the first 2 characters of the pdb filename as a bucket to place each pdb file-directory in
    [symbol-store-folder-tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree)
    """
    from ghidra.framework import Application
    from java.io import File
    from java.net import URI
    from java.util import ArrayList
    from pdb_ import PdbPlugin
    from pdb_.symbolserver import HttpSymbolServer, LocalSymbolStore, SymbolServerService

    print("Setting up Symbol Server for symbols...")
    print(f"path: {symbols_path} level: {level}")

    symbols_path = Path(symbols_path).absolute()

    # Configure local symbols directory
    symbolsDir = File(symbols_path)
    localSymbolStore = LocalSymbolStore(symbols_path)

    # Create local symbol server
    # pdb/symbolserver/LocalSymbolStore.java#L67
    localSymbolStore.create(symbolsDir, level)

    # Configure well known symbol urls
    if server_urls is None:
        # load wellknown servers
        # Ghidra/Features/PDB/src/main/java/pdb/symbolserver/ui/WellKnownSymbolServerLocation.java#L89
        known_urls = []
        pdbUrlFiles = Application.findFilesByExtensionInApplication(".pdburl")
        for pdbFile in pdbUrlFiles:
            data = Path(pdbFile.absolutePath).read_text()
            print(f"Loaded well known {pdbFile.absolutePath}' length: {len(data)}'")
            for line in data.splitlines(True):
                cat, location, warning = line.split("|")
                known_urls.append(location)
        server_urls = known_urls
    elif not isinstance(server_urls, list):
        raise TypeError("server_urls must be a list of urls")

    symServers = ArrayList()

    for url in server_urls:
        symServers.add(HttpSymbolServer(URI.create(url)))

    symbolServerService = SymbolServerService(localSymbolStore, symServers)

    PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)

    print(f"Symbol Server Configured path: {symbolServerService.toString().strip()}")


def get_pdb(prog: ghidra.program.model.listing.Program) -> java.io.File | None:
    """Searches the currently configured symbol server paths for a Pdb symbol file."""
    from ghidra.util.task import ConsoleTaskMonitor
    from pdb_ import PdbPlugin
    from pdb_.symbolserver import FindOption

    if hasattr(FindOption, "ALLOW_UNTRUSTED"):
        # Ghidra 11.2 +
        find_opts = FindOption.of(FindOption.ALLOW_UNTRUSTED)
    else:
        # Ghidra < 11.2
        find_opts = FindOption.of(FindOption.ALLOW_REMOTE)

    # Ghidra/Features/PDB/src/main/java/pdb/PdbPlugin.java#L191
    pdb = PdbPlugin.findPdb(prog, find_opts, ConsoleTaskMonitor())

    return pdb


def set_pdb(program: ghidra.program.model.listing.Program, path: str | Path) -> None:
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from java.io import File

    symbol_path = Path(path)
    print(f"Setting pdb to {symbol_path}")
    pdbFile = File(symbol_path)
    PdbUniversalAnalyzer.setPdbFileOption(program, pdbFile)


def set_remote_pdbs(program: ghidra.program.model.listing.Program, allow: bool) -> None:
    """Enable or disable remote PDB downloads"""
    from ghidra.app.plugin.core.analysis import PdbAnalyzer, PdbUniversalAnalyzer
    # Enable Remote Symbol Servers

    if hasattr(PdbUniversalAnalyzer, "setAllowUntrustedOption"):
        # Ghidra 11.2 +
        PdbUniversalAnalyzer.setAllowUntrustedOption(program, True)
        PdbAnalyzer.setAllowUntrustedOption(program, True)
    else:
        # Ghidra < 11.2
        PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
        PdbAnalyzer.setAllowRemoteOption(program, True)


def apply_gdt(
    program: ghidra.program.model.listing.Program,
    gdt_path: str | Path,
    verbose: bool = False,
) -> None:
    """Apply GDT to program"""
    from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
    from ghidra.program.model.data import FileDataTypeManager
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File
    from java.util import List

    gdt_path = Path(gdt_path)

    if verbose:
        print("Enabling verbose gdt..")
        monitor = ConsoleTaskMonitor()
    else:
        monitor = ConsoleTaskMonitor().DUMMY_MONITOR

    archiveGDT = File(gdt_path)
    archiveDTM = FileDataTypeManager.openFileArchive(archiveGDT, False)
    always_replace = True
    createBookmarksEnabled = True
    cmd = ApplyFunctionDataTypesCmd(List.of(archiveDTM), None, SourceType.USER_DEFINED, always_replace, createBookmarksEnabled)
    cmd.applyTo(program, monitor)
