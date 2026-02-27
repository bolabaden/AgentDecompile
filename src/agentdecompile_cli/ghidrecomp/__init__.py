from __future__ import annotations

# Expose API
from agentdecompile_cli.ghidrecomp.decompile import decompile
from agentdecompile_cli.ghidrecomp.callgraph import CallGraph, get_calling, get_called, gen_callgraph
from agentdecompile_cli.ghidrecomp.sast import check_tools, run_semgrep_scan, run_codeql_scan, merge_sarif_files, generate_sast_summary, preprocess_c_files

__all__ = [
    "CallGraph",
    "check_tools",
    "decompile",
    "gen_callgraph",
    "generate_sast_summary",
    "get_called",
    "get_calling",
    "merge_sarif_files",
    "preprocess_c_files",
    "run_codeql_scan",
    "run_semgrep_scan",
]
