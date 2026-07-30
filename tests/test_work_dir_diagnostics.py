"""Unit tests for G16 (rotational-disk work-dir guidance).

No monkeypatching of os/Path globals -- sys_block_root is injected as a real
temp-directory sysfs fake, so os.stat/os.major/os.minor/Path.resolve all run
unmodified against real filesystem objects.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentdecompile_recovery import work_dir_diagnostics

pytestmark = pytest.mark.unit


def _device_key(path: Path) -> str:
    stat_result = os.stat(path)
    return f"{os.major(stat_result.st_dev)}:{os.minor(stat_result.st_dev)}"


def test_rotational_disk_produces_warning(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    sys_block_root = tmp_path / "sys_dev_block"
    disk_dir = sys_block_root / _device_key(work_dir)
    (disk_dir / "queue").mkdir(parents=True)
    (disk_dir / "queue" / "rotational").write_text("1", encoding="utf-8")

    warning = work_dir_diagnostics.rotational_disk_warning(work_dir, sys_block_root=sys_block_root)
    assert warning is not None
    assert "rotational" in warning
    assert "G16" in warning
    assert str(work_dir) in warning


def test_ssd_produces_no_warning(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    sys_block_root = tmp_path / "sys_dev_block"
    disk_dir = sys_block_root / _device_key(work_dir)
    (disk_dir / "queue").mkdir(parents=True)
    (disk_dir / "queue" / "rotational").write_text("0", encoding="utf-8")

    assert work_dir_diagnostics.rotational_disk_warning(work_dir, sys_block_root=sys_block_root) is None


def test_partition_walks_up_to_parent_disk(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    sys_block_root = tmp_path / "sys_dev_block"
    sys_block_root.mkdir()
    parent_disk = tmp_path / "sys_block_sda"
    partition_dir = parent_disk / "sda1"
    (parent_disk / "queue").mkdir(parents=True)
    (parent_disk / "queue" / "rotational").write_text("1", encoding="utf-8")
    partition_dir.mkdir()
    (partition_dir / "partition").write_text("1", encoding="utf-8")
    # Real /sys/dev/block/<major>:<minor> entries are symlinks to the actual
    # block device location; fake that same indirection here so .resolve()
    # has something real to follow.
    (sys_block_root / _device_key(work_dir)).symlink_to(partition_dir, target_is_directory=True)

    warning = work_dir_diagnostics.rotational_disk_warning(work_dir, sys_block_root=sys_block_root)
    assert warning is not None
    assert "rotational" in warning


def test_missing_sys_block_entry_returns_none_not_raises(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    # sys_block_root exists but has no entry for this device -- resolve()
    # of a nonexistent path still succeeds (lexical resolution), but the
    # subsequent read_text() must fail gracefully.
    sys_block_root = tmp_path / "sys_dev_block_empty"
    assert work_dir_diagnostics.rotational_disk_warning(work_dir, sys_block_root=sys_block_root) is None


def test_unreadable_rotational_file_returns_none_not_raises(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    sys_block_root = tmp_path / "sys_dev_block"
    disk_dir = sys_block_root / _device_key(work_dir)
    disk_dir.mkdir(parents=True)
    # queue/rotational deliberately absent.
    assert work_dir_diagnostics.rotational_disk_warning(work_dir, sys_block_root=sys_block_root) is None


def test_real_filesystem_default_does_not_raise(tmp_path: Path) -> None:
    """Unmocked sanity check against the real /sys/dev/block on this machine
    (or its absence on non-Linux): whatever this machine's disk type is, the
    function must not raise -- advisory-only means graceful degradation."""
    result = work_dir_diagnostics.rotational_disk_warning(tmp_path)
    assert result is None or isinstance(result, str)
