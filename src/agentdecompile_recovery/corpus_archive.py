"""Compatibility shim — import from ``agentdecompile_recovery.corpus.archive``."""

from .corpus.archive import (
    ArchiveEntry,
    ArchiveSummary,
    ExtractionReport,
    archive_summary,
    check_extraction,
    find_sibling_archive,
    list_archive,
    summarize_entries,
)

__all__ = [
    "ArchiveEntry",
    "ArchiveSummary",
    "ExtractionReport",
    "archive_summary",
    "check_extraction",
    "find_sibling_archive",
    "list_archive",
    "summarize_entries",
]
