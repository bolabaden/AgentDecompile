"""Tests for get_context_plugin.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.get_context_plugin import GetContextPlugin

pytestmark = pytest.mark.unit


def test_empty_script_produces_empty_context(tmp_path: Path):
    plugin = GetContextPlugin("", tmp_path)

    result, updated = plugin.execute({"functionName": "f", "targetObjectPath": "x.o"})

    assert result.status == "success"
    assert updated["contextContent"] == ""
    assert updated["contextFilePath"] == ""


def test_runs_script_and_captures_stdout(tmp_path: Path):
    plugin = GetContextPlugin("echo 'struct Foo { int x; };'", tmp_path)

    result, updated = plugin.execute({"functionName": "target_func", "targetObjectPath": "x.o"})

    assert result.status == "success"
    assert "struct Foo" in updated["contextContent"]
    assert Path(updated["contextFilePath"]).read_text(encoding="utf-8") == updated["contextContent"]


def test_substitutes_function_name_and_target_object_path_placeholders(tmp_path: Path):
    plugin = GetContextPlugin("echo '{{functionName}} -> {{targetObjectPath}}'", tmp_path)

    _result, updated = plugin.execute({"functionName": "my_func", "targetObjectPath": "/tmp/obj.o"})

    assert "my_func -> /tmp/obj.o" in updated["contextContent"]


def test_reports_failure_when_script_exits_nonzero(tmp_path: Path):
    plugin = GetContextPlugin("echo 'boom' >&2; exit 1", tmp_path)

    result, context = plugin.execute({"functionName": "f", "targetObjectPath": "x.o"})

    assert result.status == "failure"
    assert "boom" in result.error


def test_reports_failure_when_script_exceeds_timeout(tmp_path: Path):
    plugin = GetContextPlugin("sleep 10", tmp_path, timeout_seconds=1)

    result, context = plugin.execute({"functionName": "f", "targetObjectPath": "x.o"})

    assert result.status == "failure"
    assert "timed out" in result.error
    assert "contextContent" not in context


def test_cleanup_removes_temp_directory(tmp_path: Path):
    plugin = GetContextPlugin("echo hi", tmp_path)
    _result, updated = plugin.execute({"functionName": "f", "targetObjectPath": "x.o"})
    context_dir = Path(updated["contextFilePath"]).parent
    assert context_dir.is_dir()

    plugin.cleanup()

    assert not context_dir.exists()
