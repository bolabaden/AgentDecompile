"""Tests for corpus archive inventory and extraction-completeness checking.

Covers:
- list_archive: complete read of ZIP central directory (streaming, no extraction)
- archive_summary: totals and Ghidra project/repository detection
- check_extraction: complete extraction, partial extraction, directory with no archive
- find_sibling_archive: locate a .zip next to a directory
- sniff_path integration: incomplete extraction triggers a detail warning
- CLI: list-archive and check-extraction subcommands
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus_archive import (
    ArchiveEntry,
    ArchiveSummary,
    ExtractionReport,
    archive_summary,
    check_extraction,
    find_sibling_archive,
    list_archive,
)
from agentdecompile_recovery.discovery import KIND_CORPUS_ARCHIVE, KIND_DIRECTORY, sniff_path

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_zip(path: Path, members: dict[str, bytes]) -> Path:
    """Create a ZIP at *path* with the given {name: content} members."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return path


CORPUS_MEMBERS = {
    "corpus/README.md": b"# corpus",
    "corpus/projects/myproject.rep/~index.dat": b"index data",
    "corpus/projects/myproject.rep/~index.bak": b"backup",
    "corpus/projects/myproject.rep/versioned/00/~00000001.db/data.dat": b"db content",
    "corpus/binaries/target.exe": b"\x4d\x5a" + b"\x00" * 10,
}


@pytest.fixture()
def corpus_zip(tmp_path: Path) -> Path:
    return _make_zip(tmp_path / "corpus.zip", CORPUS_MEMBERS)


@pytest.fixture()
def complete_dir(tmp_path: Path, corpus_zip: Path) -> Path:
    """A fully extracted directory matching corpus_zip."""
    out = tmp_path / "corpus"
    for name, content in CORPUS_MEMBERS.items():
        rel = name[len("corpus/"):]  # strip leading "corpus/"
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
    return out


@pytest.fixture()
def partial_dir(tmp_path: Path, corpus_zip: Path) -> Path:
    """A partially extracted directory — the ~index.dat and ~index.bak are missing."""
    out = tmp_path / "corpus"
    skip = {"corpus/projects/myproject.rep/~index.dat", "corpus/projects/myproject.rep/~index.bak"}
    for name, content in CORPUS_MEMBERS.items():
        if name in skip:
            continue
        rel = name[len("corpus/"):]
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
    return out


# ---------------------------------------------------------------------------
# list_archive
# ---------------------------------------------------------------------------


def test_list_archive_yields_all_members(corpus_zip: Path) -> None:
    entries = list(list_archive(corpus_zip))
    names = {e.name for e in entries}
    for member in CORPUS_MEMBERS:
        assert member in names, f"Expected {member} in archive entries"


def test_list_archive_file_sizes_match(corpus_zip: Path) -> None:
    entries = {e.name: e for e in list_archive(corpus_zip)}
    for name, content in CORPUS_MEMBERS.items():
        assert entries[name].file_size == len(content)


def test_list_archive_is_dir_false_for_files(corpus_zip: Path) -> None:
    entries = list(list_archive(corpus_zip))
    for e in entries:
        assert not e.is_dir, "All members here are files"


def test_list_archive_detects_ghidra_repository(corpus_zip: Path) -> None:
    entries = {e.name: e for e in list_archive(corpus_zip)}
    rep_entries = [e for e in entries.values() if e.ghidra_kind == "repository"]
    assert rep_entries, "Expected at least one entry tagged as Ghidra repository"


# ---------------------------------------------------------------------------
# archive_summary
# ---------------------------------------------------------------------------


def test_archive_summary_file_count(corpus_zip: Path) -> None:
    summary = archive_summary(corpus_zip)
    assert summary.file_count == len(CORPUS_MEMBERS)


def test_archive_summary_totals(corpus_zip: Path) -> None:
    summary = archive_summary(corpus_zip)
    expected_total = sum(len(c) for c in CORPUS_MEMBERS.values())
    assert summary.total_uncompressed == expected_total


def test_archive_summary_ghidra_repositories(corpus_zip: Path) -> None:
    summary = archive_summary(corpus_zip)
    assert any("myproject.rep" in r for r in summary.ghidra_repositories)


def test_archive_summary_to_json(corpus_zip: Path) -> None:
    summary = archive_summary(corpus_zip)
    obj = summary.to_json()
    assert obj["fileCount"] == len(CORPUS_MEMBERS)
    assert "totalUncompressedBytes" in obj
    assert isinstance(obj["ghidraRepositories"], list)


# ---------------------------------------------------------------------------
# check_extraction — complete
# ---------------------------------------------------------------------------


def test_check_extraction_complete(corpus_zip: Path, complete_dir: Path) -> None:
    report = check_extraction(corpus_zip, complete_dir)
    assert report.is_complete
    assert report.status in ("complete", "complete-with-extras")
    assert not report.missing
    assert not report.size_mismatch


# ---------------------------------------------------------------------------
# check_extraction — partial
# ---------------------------------------------------------------------------


def test_check_extraction_partial_missing(corpus_zip: Path, partial_dir: Path) -> None:
    report = check_extraction(corpus_zip, partial_dir)
    assert not report.is_complete
    assert report.status == "incomplete"
    missing_names = set(report.missing)
    assert "projects/myproject.rep/~index.dat" in missing_names
    assert "projects/myproject.rep/~index.bak" in missing_names


def test_check_extraction_partial_no_size_mismatch(corpus_zip: Path, partial_dir: Path) -> None:
    report = check_extraction(corpus_zip, partial_dir)
    assert not report.size_mismatch


def test_check_extraction_size_mismatch_detected(corpus_zip: Path, complete_dir: Path) -> None:
    """Corrupt one file on disk to trigger a size mismatch."""
    corrupted = complete_dir / "README.md"
    corrupted.write_bytes(b"truncated")
    report = check_extraction(corpus_zip, complete_dir)
    assert not report.is_complete
    paths = [item["path"] for item in report.size_mismatch]
    assert "README.md" in paths


def test_check_extraction_to_json(corpus_zip: Path, partial_dir: Path) -> None:
    report = check_extraction(corpus_zip, partial_dir)
    obj = report.to_json()
    assert obj["status"] == "incomplete"
    assert isinstance(obj["missing"], list)
    assert len(obj["missing"]) >= 2


# ---------------------------------------------------------------------------
# check_extraction — no matching archive
# ---------------------------------------------------------------------------


def test_check_extraction_empty_dir_no_archive(tmp_path: Path) -> None:
    """A directory with no matching archive: missing list equals all archive files."""
    archive = _make_zip(tmp_path / "data.zip", {"a.txt": b"hello", "b.txt": b"world"})
    empty_dir = tmp_path / "data"
    empty_dir.mkdir()
    report = check_extraction(archive, empty_dir)
    assert not report.is_complete
    assert set(report.missing) == {"a.txt", "b.txt"}


# ---------------------------------------------------------------------------
# find_sibling_archive
# ---------------------------------------------------------------------------


def test_find_sibling_archive_present(tmp_path: Path) -> None:
    d = tmp_path / "mydata"
    d.mkdir()
    z = tmp_path / "mydata.zip"
    z.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    assert find_sibling_archive(d) == z


def test_find_sibling_archive_absent(tmp_path: Path) -> None:
    d = tmp_path / "mydata"
    d.mkdir()
    assert find_sibling_archive(d) is None


# ---------------------------------------------------------------------------
# sniff_path integration
# ---------------------------------------------------------------------------


def test_sniff_path_corpus_zip(corpus_zip: Path) -> None:
    result = sniff_path(corpus_zip)
    assert result.kind == KIND_CORPUS_ARCHIVE
    assert result.adapter == "corpus-archive"


def test_sniff_path_complete_dir_no_warning(corpus_zip: Path, complete_dir: Path) -> None:
    result = sniff_path(complete_dir)
    assert result.kind == KIND_DIRECTORY
    # A complete extraction should not mention "incomplete" in the reason.
    assert "incomplete" not in result.reason.lower()


def test_sniff_path_partial_dir_warns(corpus_zip: Path, partial_dir: Path) -> None:
    result = sniff_path(partial_dir)
    assert result.kind == KIND_DIRECTORY
    assert "incomplete" in result.reason.lower()
    assert "siblingArchive" in result.detail
    assert result.detail["missingCount"] >= 2


def test_sniff_path_dir_no_sibling_archive(tmp_path: Path) -> None:
    d = tmp_path / "standalone"
    d.mkdir()
    result = sniff_path(d)
    assert result.kind == KIND_DIRECTORY
    # Should not warn about any archive.
    assert "siblingArchive" not in result.detail


# ---------------------------------------------------------------------------
# CLI — list-archive
# ---------------------------------------------------------------------------


def test_cli_list_archive_text(corpus_zip: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    rc = main(["list-archive", str(corpus_zip)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "README.md" in captured.out
    assert "files" in captured.out


def test_cli_list_archive_json(corpus_zip: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    rc = main(["list-archive", "--json", str(corpus_zip)])
    assert rc == 0
    captured = capsys.readouterr()
    obj = json.loads(captured.out)
    assert obj["summary"]["fileCount"] == len(CORPUS_MEMBERS)
    assert isinstance(obj["entries"], list)


def test_cli_list_archive_files_only(corpus_zip: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    # Make a zip with explicit directory entries.
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        tmp_zip = Path(f.name)
    with zipfile.ZipFile(tmp_zip, "w") as zf:
        zf.mkdir("subdir")  # explicit directory entry
        zf.writestr("subdir/file.txt", b"content")
    try:
        rc = main(["list-archive", "--files-only", str(tmp_zip)])
        captured = capsys.readouterr()
        assert rc == 0
        # With --files-only the output should not contain a line that is *only* a directory.
        # The directory entry would appear as "         -  subdir/" with the dash placeholder.
        assert "         -  subdir/" not in captured.out
        assert "file.txt" in captured.out
    finally:
        tmp_zip.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI — check-extraction
# ---------------------------------------------------------------------------


def test_cli_check_extraction_complete(corpus_zip: Path, complete_dir: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    rc = main(["check-extraction", str(corpus_zip), str(complete_dir)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "complete" in captured.out.lower()


def test_cli_check_extraction_incomplete(corpus_zip: Path, partial_dir: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    rc = main(["check-extraction", str(corpus_zip), str(partial_dir)])
    assert rc != 0
    captured = capsys.readouterr()
    assert "missing" in captured.out.lower()


def test_cli_check_extraction_json(corpus_zip: Path, partial_dir: Path, capsys: pytest.CaptureFixture) -> None:
    from agentdecompile_recovery.cli import main

    rc = main(["check-extraction", "--json", str(corpus_zip), str(partial_dir)])
    assert rc != 0
    captured = capsys.readouterr()
    obj = json.loads(captured.out)
    assert obj["status"] == "incomplete"
    assert len(obj["missing"]) >= 2
