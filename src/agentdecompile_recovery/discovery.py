"""Implicit acquisition discovery: FormatSniffer + AutoAdapters.

This module removes the need for explicit context flags.  A user points at any
path -- a binary, a folder, a decompiled source dump, notes, a JSONL facts file,
a GZF archive, or a Ghidra project -- and the sniffer classifies it, then the
auto-adapter routes it to the correct extractor.  Everything discovered is
advisory acquisition evidence; compile and objdiff gates remain the acceptance
boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- kind constants ---------------------------------------------------------

KIND_BINARY = "binary"
KIND_GHIDRA_PROJECT = "ghidra-project"
KIND_GHIDRA_ARCHIVE = "ghidra-archive"  # .gzf
KIND_FACTS_JSONL = "facts-jsonl"
KIND_SOURCE_DUMP = "source-dump"
KIND_NOTES = "notes"
KIND_JSON = "json"
KIND_DIRECTORY = "directory"
KIND_UNKNOWN = "unknown"

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
_NOTE_SUFFIXES = {".md", ".txt", ".log", ".yaml", ".yml", ".rst", ".org"}
_BINARY_SUFFIXES = {".exe", ".dll", ".sys", ".xbe", ".elf", ".so", ".o", ".obj", ".bin", ".dol", ".rel"}
_GHIDRA_PROJECT_SUFFIXES = {".gpr", ".rep"}
_GHIDRA_ARCHIVE_SUFFIXES = {".gzf"}

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_XBE_MAGIC = b"XBEH"


@dataclass
class SniffResult:
    """One classified input plus the routing decision for it."""

    path: Path
    kind: str
    reason: str
    adapter: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "reason": self.reason,
            "adapter": self.adapter,
            "detail": self.detail,
        }


def _read_head(path: Path, size: int = 4096) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _looks_binary(head: bytes) -> bool:
    if not head:
        return False
    if head[:4] == _ELF_MAGIC or head[:2] == _PE_MAGIC or head[:4] == _XBE_MAGIC:
        return True
    # High ratio of non-text bytes implies an image, not notes/source.
    nontext = sum(1 for b in head if b < 9 or (13 < b < 32) or b == 127)
    return len(head) > 0 and nontext / len(head) > 0.30


def _first_nonblank_lines(path: Path, limit: int = 20) -> list[str]:
    lines: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                stripped = raw.strip()
                if stripped:
                    lines.append(stripped)
                if len(lines) >= limit:
                    break
    except OSError:
        return []
    return lines


def _is_jsonl_facts(path: Path) -> bool:
    for line in _first_nonblank_lines(path, limit=5):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        if isinstance(row, dict):
            return True
        return False
    return False


def _looks_like_ghidra_project_dir(path: Path) -> bool:
    if any(path.glob("*.gpr")):
        return True
    if any(path.glob("*.rep")):
        return True
    if (path / "projectState").exists() or (path / "idata").exists():
        return True
    return False


def sniff_path(path: Path) -> SniffResult:
    """Classify a single path and choose its adapter."""

    resolved = path.expanduser()
    if not resolved.exists():
        return SniffResult(resolved, KIND_UNKNOWN, "path does not exist", adapter="skip")

    suffix = resolved.suffix.lower()

    if resolved.is_dir():
        if _looks_like_ghidra_project_dir(resolved):
            return SniffResult(resolved, KIND_GHIDRA_PROJECT, "directory holds Ghidra project state", adapter="ghidra")
        return SniffResult(resolved, KIND_DIRECTORY, "directory scanned for context files", adapter="context-pack")

    if suffix in _GHIDRA_ARCHIVE_SUFFIXES:
        return SniffResult(resolved, KIND_GHIDRA_ARCHIVE, "Ghidra .gzf archive", adapter="ghidra")
    if suffix in _GHIDRA_PROJECT_SUFFIXES:
        return SniffResult(resolved, KIND_GHIDRA_PROJECT, "Ghidra project file", adapter="ghidra")

    if suffix == ".jsonl" and _is_jsonl_facts(resolved):
        return SniffResult(resolved, KIND_FACTS_JSONL, "JSONL fact stream", adapter="context-pack")

    if suffix in _SOURCE_SUFFIXES:
        return SniffResult(resolved, KIND_SOURCE_DUMP, "C/C++ source dump", adapter="context-pack")

    if suffix in _NOTE_SUFFIXES:
        return SniffResult(resolved, KIND_NOTES, "unstructured/structured notes", adapter="context-pack")

    if suffix == ".json":
        return SniffResult(resolved, KIND_JSON, "structured JSON context", adapter="context-pack")

    head = _read_head(resolved)
    if suffix in _BINARY_SUFFIXES or _looks_binary(head):
        return SniffResult(resolved, KIND_BINARY, "binary image", adapter="ghidra", detail={"suffix": suffix})

    # Fallback: readable text with no known suffix is treated as notes.
    if head and b"\x00" not in head:
        return SniffResult(resolved, KIND_NOTES, "readable text treated as notes", adapter="context-pack")

    return SniffResult(resolved, KIND_UNKNOWN, "unrecognized format", adapter="skip")


def sniff_inputs(paths: list[Path]) -> list[SniffResult]:
    return [sniff_path(path) for path in paths]


@dataclass
class RoutedInputs:
    """AutoAdapters output: inputs grouped by the extractor that handles them."""

    context_paths: list[Path] = field(default_factory=list)
    ghidra_sources: list[SniffResult] = field(default_factory=list)
    skipped: list[SniffResult] = field(default_factory=list)
    results: list[SniffResult] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "contextPaths": [str(p) for p in self.context_paths],
            "ghidraSources": [r.to_json() for r in self.ghidra_sources],
            "skipped": [r.to_json() for r in self.skipped],
            "results": [r.to_json() for r in self.results],
        }


def route_inputs(paths: list[Path]) -> RoutedInputs:
    """Sniff every input and group it by adapter for downstream extraction."""

    routed = RoutedInputs()
    for result in sniff_inputs(paths):
        routed.results.append(result)
        if result.adapter == "context-pack":
            routed.context_paths.append(result.path)
        elif result.adapter == "ghidra":
            routed.ghidra_sources.append(result)
        else:
            routed.skipped.append(result)
    return routed
