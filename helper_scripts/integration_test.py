#!/usr/bin/env python3
"""Integration smoke checks for AgentDecompile Python components.

This helper stays local-only (no remote backend required) and focuses on:
- import surface validity
- provider manager initialization and tool/resource advertisement shape
- normalization behavior for flexible tool/argument names

Examples:
  python helper_scripts/integration_test.py
  python helper_scripts/integration_test.py --checks imports,normalization --json
  python helper_scripts/integration_test.py --strict
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@dataclass
class CheckResult:
    name: str
    passed: bool
    duration_ms: float
    detail: str


def _ok(name: str, started: float, detail: str) -> CheckResult:
    return CheckResult(name=name, passed=True, duration_ms=(time.perf_counter() - started) * 1000.0, detail=detail)


def _fail(name: str, started: float, exc: Exception) -> CheckResult:
    return CheckResult(
        name=name,
        passed=False,
        duration_ms=(time.perf_counter() - started) * 1000.0,
        detail=f"{exc.__class__.__name__}: {exc}",
    )


def check_imports() -> CheckResult:
    started = time.perf_counter()
    name = "imports"
    try:
        from agentdecompile_cli.mcp_server.server import PythonMcpServer  # noqa: F401
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager  # noqa: F401
        from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager  # noqa: F401
        from agentdecompile_cli.mcp_server.providers import (  # noqa: F401
            BookmarkToolProvider,
            CallGraphToolProvider,
            CommentToolProvider,
            ConstantSearchToolProvider,
            CrossReferencesToolProvider,
            DataFlowToolProvider,
            DataToolProvider,
            DecompilerToolProvider,
            FunctionToolProvider,
            GetFunctionToolProvider,
            ImportExportToolProvider,
            MemoryToolProvider,
            ProjectToolProvider,
            StringToolProvider,
            StructureToolProvider,
            SymbolToolProvider,
            VtableToolProvider,
        )
        return _ok(name, started, "All target modules imported successfully")
    except Exception as exc:
        return _fail(name, started, exc)


def check_server_components() -> CheckResult:
    started = time.perf_counter()
    name = "server-components"
    try:
        from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

        tools = ToolProviderManager().list_tools()
        resources = ResourceProviderManager().list_resources()
        if not isinstance(tools, list) or len(tools) == 0:
            raise ValueError("ToolProviderManager.list_tools() must return a non-empty list")
        if not isinstance(resources, list):
            raise ValueError("ResourceProviderManager.list_resources() must return a list")
        return _ok(name, started, f"tools={len(tools)} resources={len(resources)}")
    except Exception as exc:
        return _fail(name, started, exc)


def check_protocol_shape() -> CheckResult:
    started = time.perf_counter()
    name = "protocol-shape"
    try:
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

        tools = ToolProviderManager().list_tools()
        bad: list[str] = []
        for tool in tools:
            tname = getattr(tool, "name", "")
            tdesc = getattr(tool, "description", "")
            tschema = getattr(tool, "inputSchema", None)
            if not isinstance(tname, str) or not tname.strip():
                bad.append(f"name:{tool}")
            if not isinstance(tdesc, str):
                bad.append(f"description:{tname or '?'}")
            if not isinstance(tschema, dict):
                bad.append(f"inputSchema:{tname or '?'}")
        if bad:
            raise ValueError(f"Invalid tool schema entries: {bad[:10]}")
        return _ok(name, started, f"validated={len(tools)}")
    except Exception as exc:
        return _fail(name, started, exc)


def check_normalization() -> CheckResult:
    started = time.perf_counter()
    name = "normalization"
    try:
        from agentdecompile_cli.registry import normalize_identifier

        pairs: list[tuple[str, str]] = [
            ("manage-symbols", "managesymbols"),
            ("Manage_Symbols", "managesymbols"),
            ("@@manage symbols@@", "managesymbols"),
            ("programPath", "programpath"),
            ("program_path", "programpath"),
        ]
        for raw, expected in pairs:
            got = normalize_identifier(raw)
            if got != expected:
                raise ValueError(f"normalize_identifier({raw!r}) => {got!r}, expected {expected!r}")
        return _ok(name, started, f"validated={len(pairs)}")
    except Exception as exc:
        return _fail(name, started, exc)


def run_selected_checks(checks: list[str]) -> list[CheckResult]:
    registry: dict[str, Callable[[], CheckResult]] = {
        "imports": check_imports,
        "server-components": check_server_components,
        "protocol-shape": check_protocol_shape,
        "normalization": check_normalization,
    }
    results: list[CheckResult] = []
    for check in checks:
        results.append(registry[check]())
    return results


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local integration smoke checks for AgentDecompile")
    parser.add_argument(
        "--checks",
        default="imports,server-components,protocol-shape,normalization",
        help="Comma-separated checks to run. Allowed: imports,server-components,protocol-shape,normalization",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Use non-zero exit if any check fails (default behavior). Reserved for explicit CI usage.",
    )
    return parser.parse_args(argv)


def _print_human(results: list[CheckResult]) -> None:
    print("=" * 72)
    print("AgentDecompile integration smoke checks")
    print("=" * 72)
    for item in results:
        status = "PASS" if item.passed else "FAIL"
        print(f"[{status}] {item.name:18} {item.duration_ms:8.2f} ms  {item.detail}")
    print("-" * 72)
    passed = sum(1 for item in results if item.passed)
    print(f"Summary: {passed}/{len(results)} passed")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    requested = [token.strip() for token in args.checks.split(",") if token.strip()]
    allowed = {"imports", "server-components", "protocol-shape", "normalization"}
    unknown = [item for item in requested if item not in allowed]
    if unknown:
        print(f"Unknown checks: {', '.join(unknown)}", file=sys.stderr)
        return 2

    results = run_selected_checks(requested)
    failed = [item for item in results if not item.passed]

    if args.json:
        payload: dict[str, Any] = {
            "requested": requested,
            "passed": len(results) - len(failed),
            "failed": len(failed),
            "results": [asdict(item) for item in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_human(results)

    if failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())