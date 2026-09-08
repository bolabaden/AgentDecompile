from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.llm_cleanup import (
    CliResult,
    build_get_function_command,
    cleanup_ghidra_c,
    extract_code_block,
    fetch_get_function_cli,
    render_cleanup_prompt,
)
from agentdecompile_recovery.corpus.pipeline import run_corpus_pipeline
from agentdecompile_recovery.corpus.registry import add_binary, new_corpus, save_corpus

pytestmark = pytest.mark.unit

BROKEN_C = "int add_one(int x) { return undeclared_ghidra_name + x; }\n"
FIXED_C = "int add_one(int x) { return x + 1; }\n"
GET_FUNCTION_TEXT = (
    "# get-function\n"
    "name: add_one\n"
    "address: 00401000\n"
    "prototype: int add_one(int x)\n"
    "```c\nint add_one(int x) { return undeclared_ghidra_name + x; }\n```\n"
)


def test_extract_fenced_c() -> None:
    assert extract_code_block("```c\nint f(void) { return 1; }\n```") == "int f(void) { return 1; }"
    assert extract_code_block("no code here") is None


def test_cleanup_rejects_shim_and_same_body() -> None:
    def shim_runner(command: list[str], prompt: str, timeout: int) -> CliResult:
        assert "-p" in command
        return CliResult(0, "```c\nvoid f(void) { __asm { nop } }\n```", "")

    out = cleanup_ghidra_c(
        body=BROKEN_C, errors="error C2065", get_function=GET_FUNCTION_TEXT, runner=shim_runner
    )
    assert out["ok"] is False
    assert "shim" in (out["reason"] or "")

    def same_runner(command: list[str], prompt: str, timeout: int) -> CliResult:
        return CliResult(0, f"```c\n{BROKEN_C}```", "")

    same = cleanup_ghidra_c(
        body=BROKEN_C, errors="error C2065", get_function=GET_FUNCTION_TEXT, runner=same_runner
    )
    assert same["ok"] is False


def test_cleanup_keeps_edited_c() -> None:
    def runner(command: list[str], prompt: str, timeout: int) -> CliResult:
        assert "agentdecompile-cli get-function" in prompt
        assert "address: 00401000" in prompt
        assert "undeclared" in prompt or "C2065" in prompt
        return CliResult(0, f"```c\n{FIXED_C}```", "")

    out = cleanup_ghidra_c(
        body=BROKEN_C,
        errors="error C2065: undeclared_ghidra_name",
        get_function=GET_FUNCTION_TEXT,
        runner=runner,
    )
    assert out["ok"] is True
    assert "undeclared_ghidra_name" not in (out["source"] or "")


def test_prompt_is_edit_not_rewrite() -> None:
    text = render_cleanup_prompt(
        body=BROKEN_C, errors="C2065", header="/* stubs */", get_function=GET_FUNCTION_TEXT
    )
    assert "Do not invent a new one from scratch" in text
    assert "Do not add __asm" in text
    assert "agentdecompile-cli get-function" in text
    assert "address: 00401000" in text


def test_cleanup_refuses_without_get_function() -> None:
    out = cleanup_ghidra_c(body="", errors="C2065")
    assert out["ok"] is False
    assert "get-function" in (out["reason"] or "")


def test_get_function_cli_command_is_the_real_subcommand() -> None:
    command = build_get_function_command(program_path="/K1/demo.exe", identifier="0x401000")
    assert "get-function" in command
    assert "--function" in command
    assert "0x401000" in command
    assert "--program_path" in command


def test_fetch_get_function_uses_cli_stdout() -> None:
    def runner(command: list[str], prompt: str, timeout: int) -> CliResult:
        assert command[command.index("get-function") :]
        assert "--function" in command
        return CliResult(0, GET_FUNCTION_TEXT, "")

    fetched = fetch_get_function_cli(
        program_path="/K1/demo.exe", identifier="add_one", runner=runner
    )
    assert fetched["ok"] is True
    assert "address: 00401000" in fetched["text"]


@pytest.mark.skipif(shutil.which("cc") is None and shutil.which("gcc") is None, reason="no C compiler")
def test_pipeline_llm_retries_after_preparse_fail(tmp_path: Path) -> None:
    corpus = new_corpus("llm-fixture")
    add_binary(corpus, binary_id="donor", path=tmp_path / "donor.bin", debug="stabs", donor=True)
    save_corpus(tmp_path / "corpus.json", corpus)
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "donor.functions.json").write_text(
        json.dumps(
            [
                {
                    "id": "add",
                    "name": "add_one",
                    "size": 32,
                    "source_file": "/depot/game/add.c",
                    "source": BROKEN_C,
                    "address": "00401000",
                    "get_function": GET_FUNCTION_TEXT,
                    "callees": [],
                }
            ]
        ),
        encoding="utf-8",
    )

    def runner(command: list[str], prompt: str, timeout: int) -> CliResult:
        assert "agentdecompile-cli get-function" in prompt
        assert "address: 00401000" in prompt
        return CliResult(0, f"```c\n{FIXED_C}```", "")

    work = tmp_path / "work"
    summary = run_corpus_pipeline(
        corpus,
        work_dir=work,
        snapshot_dir=snap,
        stop_after="leftover-recover",
        llm=True,
        llm_runner=runner,
    )
    compile_receipt = json.loads((work / "recover-source.json").read_text(encoding="utf-8"))
    compile = compile_receipt.get("compile") or compile_receipt
    assert compile.get("llmAttempted") >= 1
    assert compile.get("llmKept") >= 1
    leftover = json.loads((work / "leftover-recover.json").read_text(encoding="utf-8"))
    assert leftover["ran"] is True
    assert leftover.get("kept", leftover.get("count", 0)) >= 1
    state = json.loads((work / "functions-state.json").read_text(encoding="utf-8"))
    assert "undeclared_ghidra_name" not in state["donor"][0]["source"]
    assert summary["completeExecutable"] is False
