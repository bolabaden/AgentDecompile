"""Corpus archive inventory and extraction-completeness checking.

Two problems this module solves:

1. **Listing** a corpus archive without extracting it.  A ZIP's central
   directory gives every path and uncompressed size for the cost of one seek.
   This lets an operator discover what is inside a 962 MB archive without
   paying 3.4 GB of disk and several minutes of wall-clock time.

2. **Detecting incomplete extractions.**  When ``sniff_path`` or a project
   resolver is given a directory that appears empty, the right question is
   "does a sibling archive exist, and if so, how many files are still
   missing?"  A silent wrong answer (reporting nothing when files are absent)
   is worse than a missing feature.

Both operations stream the central directory rather than reading the whole
archive into memory.

Public API
----------
- :func:`list_archive`   – yields :class:`ArchiveEntry` records
- :func:`archive_summary` – totals without per-entry detail
- :func:`check_extraction` – compares a directory against its source archive
- :func:`find_sibling_archive` – locate a ``.zip`` next to a directory
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

# Ghidra project / repository indicator paths inside an archive.
_GHIDRA_MARKERS = {
    "~index.dat",
    "~index.bak",
    "~journal.bak",
    "projectState",
}
# Directory suffixes that indicate a Ghidra project or repository.
_GHIDRA_DIR_SUFFIXES = {".gpr", ".rep", ".lock"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchiveEntry:
    """Metadata for one file inside a ZIP archive."""

    name: str
    compress_size: int
    file_size: int
    is_dir: bool
    ghidra_kind: str | None  # "project", "repository", or None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "compressSize": self.compress_size,
            "fileSize": self.file_size,
            "isDir": self.is_dir,
        }
        if self.ghidra_kind is not None:
            d["ghidraKind"] = self.ghidra_kind
        return d


@dataclass
class ArchiveSummary:
    """Aggregate totals for an archive."""

    archive_path: Path
    file_count: int
    dir_count: int
    total_compressed: int
    total_uncompressed: int
    ghidra_projects: list[str] = field(default_factory=list)
    ghidra_repositories: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "archivePath": str(self.archive_path),
            "fileCount": self.file_count,
            "dirCount": self.dir_count,
            "totalCompressedBytes": self.total_compressed,
            "totalUncompressedBytes": self.total_uncompressed,
            "ghidraProjects": self.ghidra_projects,
            "ghidraRepositories": self.ghidra_repositories,
        }


@dataclass
class ExtractionReport:
    """Result of comparing an extracted directory against its source archive."""

    archive_path: Path
    directory_path: Path
    missing: list[str] = field(default_factory=list)
    size_mismatch: list[dict[str, Any]] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return not self.missing and not self.size_mismatch

    @property
    def status(self) -> str:
        if self.is_complete and not self.extra:
            return "complete"
        if self.is_complete:
            return "complete-with-extras"
        return "incomplete"

    def to_json(self) -> dict[str, Any]:
        return {
            "archivePath": str(self.archive_path),
            "directoryPath": str(self.directory_path),
            "status": self.status,
            "missing": self.missing,
            "sizeMismatch": self.size_mismatch,
            "extra": self.extra,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ghidra_kind(name: str) -> str | None:
    """Classify a ZIP entry by its Ghidra project/repository role."""
    # Strip leading slash (ZIP entries sometimes start with one).
    parts = name.lstrip("/").split("/")
    for part in parts:
        _, dot, ext = part.rpartition(".")
        if dot and ("." + ext) in _GHIDRA_DIR_SUFFIXES:
            if ext == "rep":
                return "repository"
            return "project"
        if part in _GHIDRA_MARKERS:
            return "repository"
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_archive(archive_path: Path) -> Generator[ArchiveEntry, None, None]:
    """Yield one :class:`ArchiveEntry` per ZIP member, streaming the central directory.

    Directories are included with ``is_dir=True``.  The archive is never
    extracted; only the central directory is read.

    Parameters
    ----------
    archive_path:
        Path to a ``.zip`` file.

    Yields
    ------
    ArchiveEntry
        Metadata for each member in central-directory order.
    """
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            is_dir = info.filename.endswith("/")
            yield ArchiveEntry(
                name=info.filename,
                compress_size=info.compress_size,
                file_size=info.file_size,
                is_dir=is_dir,
                ghidra_kind=_ghidra_kind(info.filename),
            )


def archive_summary(archive_path: Path) -> ArchiveSummary:
    """Return aggregate totals for *archive_path* without extracting it.

    Reads only the ZIP central directory.  Large archives are not loaded
    into memory beyond the directory itself.
    """
    file_count = 0
    dir_count = 0
    total_compressed = 0
    total_uncompressed = 0
    ghidra_projects: set[str] = set()
    ghidra_repos: set[str] = set()

    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith("/"):
                dir_count += 1
                kind = _ghidra_kind(info.filename)
                if kind == "project":
                    ghidra_projects.add(info.filename.rstrip("/"))
                elif kind == "repository":
                    ghidra_repos.add(info.filename.rstrip("/"))
            else:
                file_count += 1
                total_compressed += info.compress_size
                total_uncompressed += info.file_size
                kind = _ghidra_kind(info.filename)
                if kind == "project":
                    # Collect the project directory from file paths too.
                    parts = info.filename.split("/")
                    for i, part in enumerate(parts):
                        if part.endswith(".gpr"):
                            ghidra_projects.add("/".join(parts[: i + 1]))
                elif kind == "repository":
                    parts = info.filename.split("/")
                    for i, part in enumerate(parts):
                        if part.endswith(".rep"):
                            ghidra_repos.add("/".join(parts[: i + 1]))

    return ArchiveSummary(
        archive_path=archive_path,
        file_count=file_count,
        dir_count=dir_count,
        total_compressed=total_compressed,
        total_uncompressed=total_uncompressed,
        ghidra_projects=sorted(ghidra_projects),
        ghidra_repositories=sorted(ghidra_repos),
    )


def check_extraction(archive_path: Path, directory_path: Path, check_extra: bool = True) -> ExtractionReport:
    """Compare an extracted directory against its source archive.

    Parameters
    ----------
    archive_path:
        The ``.zip`` that was (or is being) extracted.
    directory_path:
        Root of the extracted tree.
    check_extra:
        When ``True`` (default), also report files in *directory_path* that
        are not present in the archive.

    Returns
    -------
    ExtractionReport
        Populated with ``missing``, ``size_mismatch``, and optionally
        ``extra`` lists.
    """
    report = ExtractionReport(archive_path=archive_path, directory_path=directory_path)

    # Build a dict of {relative_name: expected_size} from the archive.
    archive_files: dict[str, int] = {}
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if not info.filename.endswith("/"):
                archive_files[info.filename] = info.file_size

    # Determine the common prefix to strip from archive names so they map to
    # relative paths inside directory_path.
    # Strip the longest common leading path component shared by *all* entries,
    # regardless of how the directory is named.  This handles archives that
    # embed a top-level folder of any name (e.g. "corpus-v2/" inside a
    # directory called "corpus").
    strip_prefix = ""
    if archive_files:
        all_keys = list(archive_files)
        # Find the common prefix across all names.
        common = all_keys[0].split("/")[0]
        if common and all(k.startswith(common + "/") for k in all_keys):
            strip_prefix = common + "/"

    def archive_rel(name: str) -> str:
        return name[len(strip_prefix):] if strip_prefix else name

    # Check for missing and size-mismatched files.
    for arc_name, expected_size in archive_files.items():
        rel = archive_rel(arc_name)
        disk_path = directory_path / rel
        if not disk_path.exists():
            report.missing.append(rel)
        else:
            actual_size = disk_path.stat().st_size
            if actual_size != expected_size:
                report.size_mismatch.append(
                    {
                        "path": rel,
                        "expectedBytes": expected_size,
                        "actualBytes": actual_size,
                    }
                )

    # Check for extra files on disk not in the archive.
    if check_extra and directory_path.is_dir():
        archive_rels = {archive_rel(n) for n in archive_files}
        for disk_file in directory_path.rglob("*"):
            if disk_file.is_file():
                try:
                    rel = str(disk_file.relative_to(directory_path))
                    # Normalise path separators to match ZIP convention.
                    rel_posix = rel.replace("\\", "/")
                    if rel_posix not in archive_rels:
                        report.extra.append(rel_posix)
                except ValueError:
                    pass

    return report


def find_sibling_archive(directory_path: Path) -> Path | None:
    """Return a ``.zip`` archive next to *directory_path* with the same stem.

    Returns ``None`` when no such archive exists.

    Example: ``/downloads/biodecompwarehouse/`` → ``/downloads/biodecompwarehouse.zip``
    """
    candidate = directory_path.with_suffix(".zip")
    if candidate.is_file():
        return candidate
    return None
