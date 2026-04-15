#!/usr/bin/env python3
"""Comprehensive, robust profile analysis tool for identifying performance bottlenecks.

This script analyzes cProfile output files (.prof) and provides detailed
breakdowns of function execution times, call counts, and call chains.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import pstats
import sys

from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

DEFAULT_PROFILE_PATHS = [
    Path("tests/cProfile/test_component_equivalence_20251203_160047.prof"),
    Path("tslpatchdata/test_kotordiff_profile.prof"),
    Path("profile.prof"),
    Path("cProfile.prof"),
]


class StatsProtocol(Protocol):
    @property
    def total_calls(self) -> int: ...

    @property
    def prim_calls(self) -> int: ...

    @property
    def total_tt(self) -> float: ...

    stats: dict[tuple[str, str, int], tuple[int, int, float, float, dict[str, int]]]

    def strip_dirs(self) -> None: ...

    def sort_stats(self, *keys: str) -> "StatsProtocol": ...

    def print_stats(self, *amount: int) -> None: ...

    def print_callers(self, *amount: int) -> None: ...

    def print_callees(self, *amount: int) -> None: ...


def get_default_profile_paths() -> list[Path]:
    return DEFAULT_PROFILE_PATHS.copy()


def find_profile_file(profile_file: Path | None, use_defaults: bool) -> Path:
    if profile_file is not None:
        if not profile_file.exists():
            print(f"Error: Profile file not found: {profile_file}", file=sys.stderr)
            sys.exit(1)
        return profile_file

    if not use_defaults:
        print(
            "Error: profile_file is required (or use --default-paths to try common paths)",
            file=sys.stderr,
        )
        sys.exit(1)

    for path in get_default_profile_paths():
        if path.exists():
            print(f"Using default profile file: {path}", file=sys.stderr)
            return path

    print("Error: No profile file found. Use --default-paths to try common paths.", file=sys.stderr)
    sys.exit(1)


def add_callers(stats: pstats.Stats) -> None:
    stats_dict = cast("StatsProtocol", stats).stats
    for func_key, func_stats in stats_dict.items():
        if len(func_stats) >= 5:
            ncalls, prim_calls, tottime, cumtime, callers_dict = func_stats
            if not isinstance(callers_dict, dict):
                stats_dict[func_key] = (ncalls, prim_calls, tottime, cumtime, {})


def add_callees(stats: pstats.Stats) -> None:
    _ = stats


def filter_stats(stats: pstats.Stats, pattern: str | None) -> pstats.Stats:
    if pattern is None:
        return stats

    pattern_lower = pattern.lower()
    add_callers(stats)
    add_callees(stats)

    filtered_stats = pstats.Stats()
    stats_dict = cast("StatsProtocol", stats).stats
    filtered_dict = cast("StatsProtocol", filtered_stats).stats

    for func_key, func_stats in stats_dict.items():
        func_name = f"{func_key[0]}:{func_key[1]}({func_key[2]})"
        if pattern_lower in func_name.lower():
            filtered_dict[func_key] = func_stats

    object.__setattr__(filtered_stats, "stats", filtered_dict)
    return filtered_stats


def format_compact_stats(stats: pstats.Stats, top_n: int, sort_key: str) -> str:
    stats.sort_stats(sort_key)
    lines: list[str] = []
    lines.append(f"Top {top_n} by {sort_key}:")
    lines.append("-" * 80)

    stats_dict = cast("StatsProtocol", stats).stats
    count = 0
    for func_key, func_stats in stats_dict.items():
        if count >= top_n:
            break
        if len(func_stats) >= 4:
            ncalls, _prim_calls, tottime, cumtime = func_stats[0], func_stats[1], func_stats[2], func_stats[3]
            func_name = f"{func_key[0]}:{func_key[1]}({func_key[2]})"
            if sort_key == "cumulative":
                time_val = cumtime
            elif sort_key == "tottime":
                time_val = tottime
            else:
                time_val = ncalls

            if sort_key == "ncalls":
                lines.append(f"  {ncalls:>10,} calls  {func_name}")
            else:
                lines.append(f"  {time_val:>10.4f}s  {func_name}")
        count += 1

    return "\n".join(lines)


def export_json(
    stats: pstats.Stats,
    prof_file: Path,
    top_cumulative: int,
    top_self: int,
    top_calls: int,
) -> dict[str, Any]:
    stats_protocol = cast("StatsProtocol", stats)
    result: dict[str, Any] = {
        "profile_file": str(prof_file),
        "analysis_time": datetime.now().isoformat(),
        "total_calls": stats_protocol.total_calls,
        "total_execution_time": stats_protocol.total_tt,
        "functions": {
            "by_cumulative_time": [],
            "by_self_time": [],
            "by_call_count": [],
        },
    }

    stats_dict = stats_protocol.stats

    stats.sort_stats("cumulative")
    count = 0
    for func_key, func_stats in stats_dict.items():
        if count >= top_cumulative:
            break
        if len(func_stats) >= 4:
            ncalls, _prim_calls, tottime, cumtime = func_stats[0], func_stats[1], func_stats[2], func_stats[3]
            result["functions"]["by_cumulative_time"].append(
                {
                    "function": f"{func_key[0]}:{func_key[1]}({func_key[2]})",
                    "ncalls": ncalls,
                    "tottime": tottime,
                    "cumtime": cumtime,
                }
            )
        count += 1

    stats.sort_stats("tottime")
    count = 0
    for func_key, func_stats in stats_dict.items():
        if count >= top_self:
            break
        if len(func_stats) >= 4:
            ncalls, _prim_calls, tottime, cumtime = func_stats[0], func_stats[1], func_stats[2], func_stats[3]
            result["functions"]["by_self_time"].append(
                {
                    "function": f"{func_key[0]}:{func_key[1]}({func_key[2]})",
                    "ncalls": ncalls,
                    "tottime": tottime,
                    "cumtime": cumtime,
                }
            )
        count += 1

    stats.sort_stats("ncalls")
    count = 0
    for func_key, func_stats in stats_dict.items():
        if count >= top_calls:
            break
        if len(func_stats) >= 4:
            ncalls, _prim_calls, tottime, cumtime = func_stats[0], func_stats[1], func_stats[2], func_stats[3]
            result["functions"]["by_call_count"].append(
                {
                    "function": f"{func_key[0]}:{func_key[1]}({func_key[2]})",
                    "ncalls": ncalls,
                    "tottime": tottime,
                    "cumtime": cumtime,
                }
            )
        count += 1

    return result


@contextlib.contextmanager
def redirect_stdout_to_stream(stream: TextIO):
    old_stdout = sys.stdout
    try:
        sys.stdout = stream
        yield
    finally:
        sys.stdout = old_stdout


def print_stats_to_stream(stats: pstats.Stats, amount: int, stream: TextIO) -> None:
    with redirect_stdout_to_stream(stream):
        stats.print_stats(amount)


def print_callers_to_stream(stats: pstats.Stats, amount: int, stream: TextIO) -> None:
    with redirect_stdout_to_stream(stream):
        stats.print_callers(amount)


def print_callees_to_stream(stats: pstats.Stats, amount: int, stream: TextIO) -> None:
    with redirect_stdout_to_stream(stream):
        stats.print_callees(amount)


def analyze_profile(
    prof_file: Path,
    output_file: Path | None = None,
    top_cumulative: int = 50,
    top_self: int = 50,
    top_calls: int = 30,
    top_callers: int = 30,
    top_callees: int = 30,
    filter_pattern: str | None = None,
    output_format: str = "text",
) -> None:
    if not prof_file.exists():
        print(f"Error: Profile file not found: {prof_file}", file=sys.stderr)
        sys.exit(1)

    try:
        stats = pstats.Stats(str(prof_file))
    except Exception as e:
        print(f"Error: Failed to load profile file: {e}", file=sys.stderr)
        sys.exit(1)

    stats.strip_dirs()
    if filter_pattern:
        stats = filter_stats(stats, filter_pattern)

    if output_format == "text" and output_file and output_file.suffix.lower() == ".json":
        output_format = "json"

    output_stream: TextIO | None = None
    should_close = False
    if output_file and output_format != "json":
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_stream = output_file.open("w", encoding="utf-8")
        should_close = True
    elif output_format != "json":
        output_stream = sys.stdout

    try:
        if output_format == "json":
            result = export_json(stats, prof_file, top_cumulative, top_self, top_calls)
            json_output = json.dumps(result, indent=2)
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(json_output, encoding="utf-8")
                print(f"Analysis complete. Results written to: {output_file}", file=sys.stdout)
            else:
                print(json_output, file=sys.stdout)
            return

        if output_format == "compact":
            if output_stream is None:
                output_stream = sys.stdout
            stats_protocol = cast("StatsProtocol", stats)
            print(f"Profile: {prof_file}", file=output_stream)
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=output_stream)
            print(
                f"Total calls: {stats_protocol.total_calls:,}, Total time: {stats_protocol.total_tt:.2f}s",
                file=output_stream,
            )
            print(file=output_stream)
            print(format_compact_stats(stats, top_cumulative, "cumulative"), file=output_stream)
            print(file=output_stream)
            print(format_compact_stats(stats, top_self, "tottime"), file=output_stream)
            print(file=output_stream)
            print(format_compact_stats(stats, top_calls, "ncalls"), file=output_stream)
            if output_file:
                print(f"Analysis complete. Results written to: {output_file}", file=sys.stdout)
            return

        if output_stream is None:
            output_stream = sys.stdout

        stats_protocol = cast("StatsProtocol", stats)
        print("=" * 100, file=output_stream)
        print("COMPREHENSIVE PROFILE ANALYSIS - PERFORMANCE BOTTLENECKS", file=output_stream)
        print("=" * 100, file=output_stream)
        print(f"\nProfile file: {prof_file}", file=output_stream)
        print(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=output_stream)
        print(f"Total function calls: {stats_protocol.total_calls:,}", file=output_stream)
        print(f"Total execution time: {stats_protocol.total_tt:.2f} seconds", file=output_stream)
        print(f"Total cumulative time: {stats_protocol.total_tt:.2f} seconds", file=output_stream)
        if filter_pattern:
            print(f"Filter pattern: {filter_pattern}", file=output_stream)
        print(file=output_stream)

        if top_cumulative > 0:
            stats.sort_stats("cumulative")
            print("\n" + "=" * 100, file=output_stream)
            print(f"TOP {top_cumulative} FUNCTIONS BY CUMULATIVE TIME", file=output_stream)
            print("=" * 100, file=output_stream)
            print("(Includes time spent in called functions - shows call chain bottlenecks)", file=output_stream)
            print_stats_to_stream(stats, top_cumulative, output_stream)

        if top_self > 0:
            stats.sort_stats("tottime")
            print("\n" + "=" * 100, file=output_stream)
            print(f"TOP {top_self} FUNCTIONS BY SELF TIME (EXCLUDING SUBCALLS)", file=output_stream)
            print("=" * 100, file=output_stream)
            print("(Where CPU time is actually spent - the real bottlenecks)", file=output_stream)
            print_stats_to_stream(stats, top_self, output_stream)

        if top_calls > 0:
            stats.sort_stats("ncalls")
            print("\n" + "=" * 100, file=output_stream)
            print(f"TOP {top_calls} FUNCTIONS BY CALL COUNT", file=output_stream)
            print("=" * 100, file=output_stream)
            print("(Functions called most frequently - may indicate inefficient loops)", file=output_stream)
            print_stats_to_stream(stats, top_calls, output_stream)

        if top_callers > 0:
            stats.sort_stats("cumulative")
            print("\n" + "=" * 100, file=output_stream)
            print(f"CALLERS ANALYSIS - TOP {top_callers}", file=output_stream)
            print("=" * 100, file=output_stream)
            print("(Who calls the hot functions - shows the call chain)", file=output_stream)
            print_callers_to_stream(stats, top_callers, output_stream)

        if top_callees > 0:
            print("\n" + "=" * 100, file=output_stream)
            print(f"CALLEES ANALYSIS - TOP {top_callees}", file=output_stream)
            print("=" * 100, file=output_stream)
            print("(What the hot functions call - shows what makes them slow)", file=output_stream)
            stats.sort_stats("cumulative")
            print_callees_to_stream(stats, top_callees, output_stream)

        if output_file:
            print(f"\nAnalysis complete. Results written to: {output_file}", file=sys.stdout)
        else:
            print("\nAnalysis complete.", file=sys.stdout)

    except Exception as e:
        print(f"Error: Analysis failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if should_close and output_stream is not None:
            output_stream.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive, robust profile analysis tool for identifying performance bottlenecks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "profile_file",
        nargs="?",
        default=None,
        type=lambda x: Path(x) if x else None,
        help="Path to the .prof profile file to analyze (required if not using --default-paths)",
    )
    parser.add_argument("--output", "-o", type=Path, default=None, help="Path to write output file (default: print to stdout)")
    parser.add_argument("--format", "-f", choices=["text", "json", "compact"], default="text", help="Output format: text (default), json, or compact")
    parser.add_argument("--top-cumulative", type=int, default=50, help="Number of top functions by cumulative time to show (default: 50, 0 to skip)")
    parser.add_argument("--top-self", type=int, default=50, help="Number of top functions by self time to show (default: 50, 0 to skip)")
    parser.add_argument("--top-calls", type=int, default=30, help="Number of top functions by call count to show (default: 30, 0 to skip)")
    parser.add_argument("--top-callers", type=int, default=30, help="Number of top callers to show (default: 30, 0 to skip)")
    parser.add_argument("--top-callees", type=int, default=30, help="Number of top callees to show (default: 30, 0 to skip)")
    parser.add_argument("--no-callers", action="store_true", help="Skip callers analysis")
    parser.add_argument("--no-callees", action="store_true", help="Skip callees analysis")
    parser.add_argument("--filter", type=str, default=None, help="Filter functions by name pattern (case-insensitive)")
    parser.add_argument("--default-paths", action="store_true", help="Try common default profile file paths if profile_file not provided")

    args = parser.parse_args()

    if args.top_cumulative < 0 or args.top_self < 0 or args.top_calls < 0 or args.top_callers < 0 or args.top_callees < 0:
        print("Error: top-* arguments must be non-negative", file=sys.stderr)
        sys.exit(1)

    prof_file = find_profile_file(args.profile_file, args.default_paths)
    top_callers = 0 if args.no_callers else args.top_callers
    top_callees = 0 if args.no_callees else args.top_callees

    analyze_profile(
        prof_file=prof_file,
        output_file=args.output,
        top_cumulative=args.top_cumulative,
        top_self=args.top_self,
        top_calls=args.top_calls,
        top_callers=top_callers,
        top_callees=top_callees,
        filter_pattern=args.filter,
        output_format=args.format,
    )


if __name__ == "__main__":
    main()