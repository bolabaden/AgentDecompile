"""Tests for ast_grep_context.py's ast-grep-CLI-backed codebase-context lookup."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.ast_grep_context import find_codebase_context

pytestmark = pytest.mark.unit


def _sg_json_item(text: str) -> dict:
    return {
        "text": text,
        "range": {
            "byteOffset": {"start": 0, "end": len(text)},
            "start": {"line": 0, "column": 0},
            "end": {"line": 0, "column": len(text)},
        },
        "file": "fake.h",
        "lines": text,
        "language": "C",
    }


def _fake_runner_for(
    *,
    func_decls: list[str],
    type_ids_by_declaration: dict[str, list[str]],
    type_defs: list[str],
):
    """Build a command_runner that answers each of the three ast-grep phases.

    Dispatches purely on the shape of the invocation (--stdin present or
    not, and which rule id is embedded in --inline-rules), mirroring how
    decomp_match.py's tests fake subprocess output without a real binary.
    """

    def runner(command: list[str], *, timeout_ms: int, input_text: str | None = None) -> dict:
        assert command[0] in ("ast-grep", "/usr/bin/ast-grep")
        rule_yaml = command[command.index("--inline-rules") + 1]

        if "find-func-decl" in rule_yaml:
            stdout = json.dumps([_sg_json_item(text) for text in func_decls])
        elif "find-type-ids" in rule_yaml:
            assert input_text is not None
            names = type_ids_by_declaration.get(input_text.strip(), [])
            stdout = json.dumps([_sg_json_item(name) for name in names])
        elif "find-type-def" in rule_yaml:
            stdout = json.dumps([_sg_json_item(text) for text in type_defs])
        else:
            raise AssertionError(f"unexpected rule: {rule_yaml}")

        return {
            "command": command,
            "exitCode": 0,
            "stdout": stdout,
            "stderr": "",
            "available": True,
        }

    return runner


def test_missing_binary_returns_empty_context_without_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    result = find_codebase_context("target_func", ["helper_func"], Path("/tmp/does-not-matter"))

    assert result.asm_declaration is None
    assert result.called_functions_declarations == {}
    assert result.type_definitions == []


def test_missing_binary_never_invokes_command_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    def boom(*_args, **_kwargs):
        raise AssertionError("command_runner should not be called when ast-grep is missing")

    result = find_codebase_context(
        "target_func",
        ["helper_func"],
        Path("/tmp/does-not-matter"),
        command_runner=boom,
    )
    assert result.asm_declaration is None


def test_finds_target_and_called_function_declarations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "ast-grep" else None)

    target_decl = "int target_func(Foo *f, u32 val);"
    helper_decl = "int helper_func(Foo *f, u32 val);"
    runner = _fake_runner_for(
        func_decls=[target_decl, helper_decl],
        type_ids_by_declaration={
            target_decl: ["Foo"],
            helper_decl: ["Foo"],
        },
        type_defs=["typedef struct Foo {\n    int x;\n} Foo;"],
    )

    result = find_codebase_context(
        "target_func",
        ["helper_func"],
        Path("/some/project"),
        command_runner=runner,
    )

    assert result.asm_declaration == target_decl
    assert result.called_functions_declarations == {"helper_func": helper_decl}
    assert result.type_definitions == ["typedef struct Foo {\n    int x;\n} Foo;"]


def test_ignores_primitive_typedef_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "ast-grep" else None)

    target_decl = "int target_func(u32 val);"

    calls: list[list[str]] = []

    def runner(command: list[str], *, timeout_ms: int, input_text: str | None = None) -> dict:
        rule_yaml = command[command.index("--inline-rules") + 1]
        if "find-func-decl" in rule_yaml:
            stdout = json.dumps([_sg_json_item(target_decl)])
        elif "find-type-ids" in rule_yaml:
            stdout = json.dumps([_sg_json_item("u32")])
        elif "find-type-def" in rule_yaml:
            # Should never be reached: u32 is filtered out as a primitive.
            calls.append(command)
            stdout = "[]"
        else:
            raise AssertionError(f"unexpected rule: {rule_yaml}")
        return {"command": command, "exitCode": 0, "stdout": stdout, "stderr": "", "available": True}

    result = find_codebase_context("target_func", [], Path("/some/project"), command_runner=runner)

    assert result.asm_declaration == target_decl
    assert result.type_definitions == []
    assert calls == []  # find-type-def phase skipped entirely when no non-primitive types remain


def test_no_declarations_found_yields_empty_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "ast-grep" else None)

    def runner(command: list[str], *, timeout_ms: int, input_text: str | None = None) -> dict:
        return {"command": command, "exitCode": 0, "stdout": "[]", "stderr": "", "available": True}

    result = find_codebase_context("missing_func", ["also_missing"], Path("/some/project"), command_runner=runner)

    assert result.asm_declaration is None
    assert result.called_functions_declarations == {}
    assert result.type_definitions == []


def test_non_json_stdout_is_treated_as_no_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "ast-grep" else None)

    def runner(command: list[str], *, timeout_ms: int, input_text: str | None = None) -> dict:
        return {"command": command, "exitCode": 1, "stdout": "not json", "stderr": "boom", "available": True}

    result = find_codebase_context("target_func", [], Path("/some/project"), command_runner=runner)

    assert result.asm_declaration is None
    assert result.type_definitions == []


@pytest.mark.skipif(
    shutil.which("ast-grep") is None and shutil.which("sg") is None,
    reason="ast-grep CLI not installed in this environment",
)
def test_real_ast_grep_cli_finds_declarations_and_type_defs(tmp_path: Path) -> None:
    header = tmp_path / "b.h"
    header.write_text(
        "typedef unsigned int u32;\n"
        "typedef struct Foo {\n"
        "    int x;\n"
        "} Foo;\n"
        "\n"
        "int target_func(Foo *f, u32 val);\n"
        "int helper_func(Foo *f, u32 val);\n",
        encoding="utf-8",
    )

    result = find_codebase_context("target_func", ["helper_func"], tmp_path)

    assert result.asm_declaration == "int target_func(Foo *f, u32 val);"
    assert result.called_functions_declarations == {"helper_func": "int helper_func(Foo *f, u32 val);"}
    assert len(result.type_definitions) == 1
    assert "struct Foo" in result.type_definitions[0]
