"""Unit tests for the headless rewrite fulfillment provider.

The provider closes challenger-lane mechanism 3 in-process. Previously a
campaign wrote a queue entry and stopped, and fulfillment required a human to
have separately launched a Claude Code session running /loop against the
rewrite-worker skill. If nobody had, requests sat pending forever.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.rewrite_context import build_context_pack
from agentdecompile_recovery.rewrite_provider import (
    CliResult,
    build_cli_command,
    fulfill_rewrite,
)

pytestmark = pytest.mark.unit


def _pack(candidate: str = "void f(void){ gCounter += 1; }"):
    return build_context_pack(
        function_name="FUN_004a23b0",
        entry="0x4a23b0",
        candidate_source=candidate,
        aligned_diff=[
            {"index": 0, "target": "add eax, eax", "candidate": "shl eax, 1", "differs": True, "diffKind": "DIFF_REPLACE"}
        ],
        mismatch_class="opcode-replacement",
    )


def _runner(response: str, returncode: int = 0):
    captured: dict = {}

    def run(command: list[str], prompt: str, timeout: int) -> CliResult:
        captured["command"] = command
        captured["prompt"] = prompt
        captured["timeout"] = timeout
        return CliResult(returncode=returncode, stdout=response, stderr="")

    run.captured = captured  # type: ignore[attr-defined]
    return run


def test_command_disables_all_tools() -> None:
    """The pack embeds binary-derived text; the model must get no tool access."""

    command = build_cli_command(cli="claude", model=None)

    assert "--tools" in command
    assert command[command.index("--tools") + 1] == ""


def test_command_uses_print_mode() -> None:
    command = build_cli_command(cli="claude", model=None)

    assert "-p" in command or "--print" in command


def test_command_includes_model_when_given() -> None:
    command = build_cli_command(cli="claude", model="claude-sonnet-5")

    assert "--model" in command
    assert command[command.index("--model") + 1] == "claude-sonnet-5"


def test_prompt_is_passed_on_stdin_not_argv() -> None:
    """Packs can be large and contain arbitrary bytes-derived text."""

    runner = _runner("```c\nvoid f(void){ gCounter = gCounter + 1; }\n```")

    fulfill_rewrite(_pack(), runner=runner)

    assert "add eax, eax" in runner.captured["prompt"]  # type: ignore[attr-defined]
    assert not any("add eax, eax" in part for part in runner.captured["command"])  # type: ignore[attr-defined]


def test_successful_rewrite_returns_completed_source() -> None:
    runner = _runner("```c\nvoid f(void){ gCounter = gCounter + 1; }\n```")

    result = fulfill_rewrite(_pack(), runner=runner)

    assert result["status"] == "completed"
    assert result["source"] == "void f(void){ gCounter = gCounter + 1; }"


def test_inline_assembly_result_is_failed_not_completed() -> None:
    """The content check is the gate; the prompt rule alone is not."""

    runner = _runner("```c\nvoid f(void){ __asm { inc dword ptr [gCounter] } }\n```")

    result = fulfill_rewrite(_pack(), runner=runner)

    assert result["status"] == "failed"
    assert "banned" in result["reason"].lower() or "readable" in result["reason"].lower()
    assert "source" not in result or result.get("source") is None


def test_unchanged_source_is_failed() -> None:
    """Returning the input verbatim is not a rewrite and must not consume a
    downstream compile+objdiff cycle."""

    candidate = "void f(void){ gCounter += 1; }"
    runner = _runner(f"```c\n{candidate}\n```")

    result = fulfill_rewrite(_pack(candidate), runner=runner)

    assert result["status"] == "failed"
    assert "unchanged" in result["reason"].lower()


def test_missing_fence_is_failed() -> None:
    runner = _runner("I cannot help with that request.")

    result = fulfill_rewrite(_pack(), runner=runner)

    assert result["status"] == "failed"
    assert "code block" in result["reason"].lower()


def test_cli_failure_is_failed_not_an_exception() -> None:
    runner = _runner("", returncode=1)

    result = fulfill_rewrite(_pack(), runner=runner)

    assert result["status"] == "failed"
    assert "exit" in result["reason"].lower() or "cli" in result["reason"].lower()


def test_runner_exception_is_contained() -> None:
    def boom(command: list[str], prompt: str, timeout: int) -> CliResult:
        raise OSError("claude not found")

    result = fulfill_rewrite(_pack(), runner=boom)

    assert result["status"] == "failed"
    assert "claude not found" in result["reason"]


def test_result_records_the_prompt_for_auditability() -> None:
    runner = _runner("```c\nvoid f(void){ gCounter = gCounter + 1; }\n```")

    result = fulfill_rewrite(_pack(), runner=runner)

    assert result["functionName"] == "FUN_004a23b0"
    assert "claimBoundary" in result
