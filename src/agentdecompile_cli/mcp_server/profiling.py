"""Lightweight profiling utilities for MCP operations.

Captures cProfile artifacts, summarizes them for humans, and keeps a small
recent-run history that can be exposed through the debug-info resource.
"""

from __future__ import annotations

import cProfile
import io
import json
import logging
import os
import pstats
import subprocess
import sys
import tempfile
import time

from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

# Ring buffer of recent profile runs (path, metadata) for debug-info resource
_RECENT_PROFILE_RUNS: deque[dict[str, Any]] = deque(maxlen=10)
_PROFILE_LOCK = Lock()
_DEFAULT_ANALYZER_PATH = Path(r"C:\GitHub\PyKotor\helper_scripts\python\analyze_profile.py")
_DEFAULT_PROFILE_DIR = Path(tempfile.gettempdir()) / "agentdecompile-profiles"
_SUMMARY_TEXT_LIMIT = 6000


def get_profile_storage_dir() -> Path:
    """Directory where cProfile .prof files and analysis outputs are written; overridable via AGENTDECOMPILE_PROFILE_DIR."""
    override = str(os.getenv("AGENTDECOMPILE_PROFILE_DIR", "")).strip()
    return Path(override) if override else _DEFAULT_PROFILE_DIR


def get_profile_analyzer_path() -> Path | None:
    """Path to optional external script that post-processes .prof files; overridable via AGENTDECOMPILE_PROFILE_ANALYZER. Returns None if not set or path missing."""
    override = str(os.getenv("AGENTDECOMPILE_PROFILE_ANALYZER", "")).strip()
    candidate = Path(override) if override else _DEFAULT_ANALYZER_PATH
    return candidate if candidate.exists() else None


def list_recent_profiles() -> list[dict[str, Any]]:
    """Return a copy of the recent profile runs (for debug-info resource or tooling). Thread-safe."""
    with _PROFILE_LOCK:
        return [dict(entry) for entry in _RECENT_PROFILE_RUNS]


def _fallback_summary_json(profile_path: Path, *, top_n: int = 10) -> dict[str, Any]:
    """Build a small JSON summary from pstats when no external analyzer is available."""
    stats = pstats.Stats(str(profile_path))
    stats_dict = getattr(stats, "stats", {})
    by_cumulative = sorted(stats_dict.items(), key=lambda item: item[1][3], reverse=True)[:top_n]
    return {
        "profile_file": str(profile_path),
        "total_calls": getattr(stats, "total_calls", 0),
        "total_execution_time": getattr(stats, "total_tt", 0.0),
        "functions": {
            "by_cumulative_time": [
                {
                    "function": f"{func_key[0]}:{func_key[1]}({func_key[2]})",
                    "ncalls": func_stats[0],
                    "tottime": func_stats[2],
                    "cumtime": func_stats[3],
                }
                for func_key, func_stats in by_cumulative
            ]
        },
    }


def _fallback_summary_text(profile_path: Path, *, top_n: int = 20) -> str:
    stream = io.StringIO()
    stats = pstats.Stats(str(profile_path), stream=stream)
    stats.strip_dirs()
    stats.sort_stats("cumulative")
    stats.print_stats(top_n)
    return stream.getvalue()


def _summarize_profile(profile_path: Path) -> tuple[str, dict[str, Any], str]:
    """Produce (text_summary, json_summary, mode). Uses external analyzer if configured, else pstats fallback."""
    analyzer_path = get_profile_analyzer_path()
    if analyzer_path is not None:
        text_output = profile_path.with_suffix(".analysis.txt")
        json_output = profile_path.with_suffix(".analysis.json")
        try:
            subprocess.run(
                [
                    sys.executable,
                    str(analyzer_path),
                    str(profile_path),
                    "--output",
                    str(text_output),
                    "--format",
                    "text",
                    "--top-cumulative",
                    "20",
                    "--top-self",
                    "20",
                    "--top-calls",
                    "20",
                    "--top-callers",
                    "10",
                    "--top-callees",
                    "10",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(analyzer_path),
                    str(profile_path),
                    "--output",
                    str(json_output),
                    "--format",
                    "json",
                    "--top-cumulative",
                    "20",
                    "--top-self",
                    "20",
                    "--top-calls",
                    "20",
                    "--top-callers",
                    "10",
                    "--top-callees",
                    "10",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if text_output.exists() and json_output.exists():
                return (
                    text_output.read_text(encoding="utf-8", errors="replace"),
                    json.loads(json_output.read_text(encoding="utf-8", errors="replace")),
                    "external-analyzer",
                )
        except Exception as exc:
            logger.warning("Profile analyzer failed for %s: %s", profile_path, exc)

    return _fallback_summary_text(profile_path), _fallback_summary_json(profile_path), "pstats-fallback"


class ProfileCapture:
    """Context manager that records a cProfile run and retains a compact summary.

    On exit: writes .prof to profile storage dir, runs optional analyzer or pstats
    fallback, then appends a record (operation, duration, summary, path) to
    _RECENT_PROFILE_RUNS for debug-info or inspection.
    """

    def __init__(self, operation: str, *, target: str = "", metadata: dict[str, Any] | None = None) -> None:
        self.operation = operation
        self.target = target
        self.metadata: dict[str, Any] = dict(metadata or {})
        self._profiler = cProfile.Profile()
        self._start = 0.0

    def add_metadata(self, **kwargs: Any) -> None:
        self.metadata.update(kwargs)

    def __enter__(self) -> ProfileCapture:
        self._start = time.perf_counter()
        self._profiler.enable()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._profiler.disable()
        duration = time.perf_counter() - self._start
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        safe_operation = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in self.operation)
        profile_dir = get_profile_storage_dir()
        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_path = profile_dir / f"{safe_operation}-{timestamp}.prof"

        summary_text = ""
        summary_json: dict[str, Any] = {}
        summary_mode = "unavailable"
        try:
            self._profiler.dump_stats(str(profile_path))
            summary_text, summary_json, summary_mode = _summarize_profile(profile_path)
        except Exception as summary_exc:
            logger.warning("Failed to persist profile run for %s: %s", self.operation, summary_exc)

        record = {
            "operation": self.operation,
            "target": self.target or None,
            "durationSeconds": round(duration, 6),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "profilePath": str(profile_path),
            "summaryMode": summary_mode,
            "summaryText": summary_text[:_SUMMARY_TEXT_LIMIT],
            "summaryJson": summary_json,
            "metadata": dict(self.metadata),
            "success": exc_type is None,
        }
        if exc is not None:
            record["error"] = str(exc)

        with _PROFILE_LOCK:
            _RECENT_PROFILE_RUNS.appendleft(record)