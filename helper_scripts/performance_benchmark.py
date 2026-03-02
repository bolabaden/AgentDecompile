#!/usr/bin/env python3
"""Local performance benchmark helper for AgentDecompile internals.

Benchmarks local Python operations (no remote backend):
- component startup
- tool listing throughput
- normalization throughput
- provider/module import overhead

Examples:
  python helper_scripts/performance_benchmark.py
  python helper_scripts/performance_benchmark.py --iterations 50 --json
  python helper_scripts/performance_benchmark.py --output tmp/benchmark.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Callable

try:
    import psutil  # pyright: ignore[reportMissingImports, reportMissingTypeStubs]
except Exception:
    psutil = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@dataclass
class BenchmarkResult:
    name: str
    duration_ms: float
    memory_mb: float
    success: bool
    error: str = ""
    iterations: int = 1


class BenchmarkRunner:
    def __init__(self) -> None:
        self._process = psutil.Process() if psutil else None

    def memory_mb(self) -> float:
        if self._process is None:
            return 0.0
        return self._process.memory_info().rss / (1024 * 1024)

    def _measure(self, name: str, fn: Callable[[], None], *, iterations: int = 1) -> BenchmarkResult:
        start_mem = self.memory_mb()
        start = time.perf_counter()
        try:
            for _ in range(iterations):
                fn()
            duration = (time.perf_counter() - start) * 1000.0
            delta_mem = self.memory_mb() - start_mem
            return BenchmarkResult(
                name=name,
                duration_ms=duration,
                memory_mb=delta_mem,
                success=True,
                iterations=iterations,
            )
        except Exception as exc:
            return BenchmarkResult(
                name=name,
                duration_ms=0.0,
                memory_mb=0.0,
                success=False,
                error=f"{exc.__class__.__name__}: {exc}",
                iterations=iterations,
            )

    def bench_server_startup(self) -> BenchmarkResult:
        def _run() -> None:
            from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
            from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

            tm = ToolProviderManager()
            rm = ResourceProviderManager()
            tools = tm.list_tools()
            resources = rm.list_resources()
            if not tools or not isinstance(tools, list):
                raise ValueError("tool manager did not return non-empty tool list")
            if not isinstance(resources, list):
                raise ValueError("resource manager did not return list")

        return self._measure("server_startup", _run)

    def bench_tool_listing(self, *, iterations: int) -> BenchmarkResult:
        def _run() -> None:
            from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

            tools = ToolProviderManager().list_tools()
            if not isinstance(tools, list):
                raise ValueError("list_tools() must return list")

        return self._measure("tool_listing", _run, iterations=iterations)

    def bench_normalization(self, *, iterations: int) -> BenchmarkResult:
        def _run() -> None:
            from agentdecompile_cli.registry import normalize_identifier

            samples = [
                "manage-symbols",
                "Manage_Symbols",
                "@@manage symbols@@",
                "programPath",
                "program_path",
                "PROGRAM PATH",
                "get-functions",
                "getFunctions",
                "GET_FUNCTIONS",
            ]
            for token in samples:
                normalize_identifier(token)

        return self._measure("normalization", _run, iterations=iterations)

    def bench_import_overhead(self) -> BenchmarkResult:
        def _run() -> None:
            from agentdecompile_cli.config import config_manager  # noqa: F401
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
                ScriptToolProvider,
                StringToolProvider,
                StructureToolProvider,
                SymbolToolProvider,
                VtableToolProvider,
            )

        return self._measure("module_imports", _run)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local performance benchmarks for AgentDecompile")
    parser.add_argument("--iterations", type=int, default=20, help="Iterations for throughput-oriented benchmarks")
    parser.add_argument("--json", action="store_true", help="Print JSON output instead of human-readable table")
    parser.add_argument("--output", type=str, default="", help="Optional file path for JSON output")
    return parser.parse_args(argv)


def summarize(results: list[BenchmarkResult]) -> dict[str, Any]:
    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    average_duration = mean([r.duration_ms for r in succeeded]) if succeeded else 0.0
    return {
        "total": len(results),
        "passed": len(succeeded),
        "failed": len(failed),
        "avg_duration_ms": average_duration,
        "results": [asdict(r) for r in results],
    }


def print_human(results: list[BenchmarkResult]) -> None:
    print("=" * 78)
    print("AgentDecompile performance benchmarks")
    print("=" * 78)
    for r in results:
        status = "PASS" if r.success else "FAIL"
        if r.success:
            print(
                f"[{status}] {r.name:18} duration={r.duration_ms:9.2f} ms  "
                f"memory_delta={r.memory_mb:7.2f} MB  iterations={r.iterations}"
            )
        else:
            print(f"[{status}] {r.name:18} error={r.error}")
    payload = summarize(results)
    print("-" * 78)
    print(
        f"Summary: {payload['passed']}/{payload['total']} passed, "
        f"avg_duration={payload['avg_duration_ms']:.2f} ms"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.iterations <= 0:
        print("--iterations must be > 0", file=sys.stderr)
        return 2

    runner = BenchmarkRunner()
    results: list[BenchmarkResult] = [
        runner.bench_server_startup(),
        runner.bench_tool_listing(iterations=args.iterations),
        runner.bench_normalization(iterations=args.iterations * 25),
        runner.bench_import_overhead(),
    ]

    payload = summarize(results)
    if args.json:
        rendered = json.dumps(payload, indent=2)
        print(rendered)
    else:
        print_human(results)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return 0 if payload["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
