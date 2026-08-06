"""Tests for c_function_scan.py's ast-grep-based C function scanner."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.c_function_scan import scan_c_functions

pytestmark = pytest.mark.unit

_HAS_AST_GREP = shutil.which("ast-grep") is not None or shutil.which("sg") is not None


def test_returns_empty_list_when_binary_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_recovery.c_function_scan._resolve_binary", lambda: None)

    result = scan_c_functions(tmp_path, ["src"])

    assert result == []


def test_returns_empty_list_for_missing_source_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_recovery.c_function_scan._resolve_binary", lambda: "/usr/bin/ast-grep")
    calls: list[list[str]] = []

    def fake_runner(command, *, cwd):
        calls.append(command)
        return {"exitCode": 0, "stdout": "[]", "stderr": ""}

    result = scan_c_functions(tmp_path, ["nonexistent"], command_runner=fake_runner)

    assert result == []
    assert calls == []


def test_parses_injected_ast_grep_json_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_recovery.c_function_scan._resolve_binary", lambda: "/usr/bin/ast-grep")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int foo(void) { return 1; }\n", encoding="utf-8")

    fake_matches = [
        {
            "text": "int foo(void) { return 1; }",
            "file": "a.c",
            "metaVariables": {"single": {"NAME": {"text": "foo"}}},
        }
    ]

    def fake_runner(command, *, cwd):
        return {"exitCode": 0, "stdout": json.dumps(fake_matches), "stderr": ""}

    result = scan_c_functions(tmp_path, ["src"], command_runner=fake_runner)

    assert len(result) == 1
    assert result[0].name == "foo"
    assert result[0].c_code == "int foo(void) { return 1; }"
    assert result[0].c_module_path == "src/a.c"


def test_handles_non_json_stdout_gracefully(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_recovery.c_function_scan._resolve_binary", lambda: "/usr/bin/ast-grep")
    (tmp_path / "src").mkdir()

    def fake_runner(command, *, cwd):
        return {"exitCode": 1, "stdout": "not json", "stderr": "error"}

    result = scan_c_functions(tmp_path, ["src"], command_runner=fake_runner)

    assert result == []


@pytest.mark.skipif(not _HAS_AST_GREP, reason="requires ast-grep/sg on PATH")
def test_real_ast_grep_invocation_finds_a_function(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int bar(int x) {\n    return x + 1;\n}\n", encoding="utf-8")

    result = scan_c_functions(tmp_path, ["src"])

    names = [record.name for record in result]
    assert "bar" in names
