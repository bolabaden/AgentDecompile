"""Headless fulfillment for challenger-lane mechanism 3.

The campaign previously wrote a rewrite request to a file queue and stopped.
Fulfillment required an operator to have separately launched a Claude Code
session running `/loop` against the `agentdecompile-rewrite-worker` skill; with
no such session, requests stayed pending indefinitely and the loop never
closed. This module lets a campaign fulfill its own requests by invoking the
local Claude Code CLI in print mode.

**No credentialed LLM API client is used here.** Fulfillment shells out to the
`claude` CLI already installed for the operator, with `--tools ""` so the model
gets no tool access at all. That isolation is required, not incidental: a
context pack embeds decompiler output and target disassembly derived from an
untrusted binary, and this pipeline's own premise is that such content cannot
be trusted at face value.

The objdiff gate is unchanged. Nothing here promotes anything.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any, Callable

from .rewrite_context import check_rewrite_content, extract_code_block, render_rewrite_prompt

SCHEMA = "agentdecompile.rewrite-fulfillment.v1"
CLAIM_BOUNDARY = (
    "a fulfilled rewrite is an unverified candidate; compile + objdiff zero "
    "remains the sole acceptance gate"
)

DEFAULT_CLI = "claude"
DEFAULT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class CliResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], str, int], CliResult]


def build_cli_command(*, cli: str = DEFAULT_CLI, model: str | None = None) -> list[str]:
    """Print-mode CLI invocation with every tool disabled.

    `--tools ""` is the isolation boundary. The prompt travels on stdin rather
    than argv: packs routinely exceed argv limits and carry binary-derived text.
    """

    command = [cli, "-p", "--output-format", "text", "--tools", ""]
    if model:
        command.extend(["--model", model])
    return command


def _subprocess_runner(command: list[str], prompt: str, timeout: int) -> CliResult:
    completed = subprocess.run(
        command,
        input=prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CliResult(returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)


def _failed(pack: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "failed",
        "functionName": pack.get("functionName"),
        "entry": pack.get("entry"),
        "reason": reason,
        "source": None,
        "claimBoundary": CLAIM_BOUNDARY,
    }


def fulfill_rewrite(
    pack: dict[str, Any],
    *,
    cli: str = DEFAULT_CLI,
    model: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Render a pack, invoke the CLI, and validate the returned candidate.

    Every failure mode -- CLI missing, non-zero exit, no fenced block, banned
    construct, unchanged source -- resolves to a `failed` result rather than an
    exception, so one bad rewrite cannot abort a campaign sweep.
    """

    prompt = render_rewrite_prompt(pack)
    command = build_cli_command(cli=cli, model=model)
    execute = runner or _subprocess_runner

    try:
        result = execute(command, prompt, timeout)
    except subprocess.TimeoutExpired:
        return _failed(pack, f"rewrite CLI timed out after {timeout}s")
    except (OSError, ValueError) as exc:
        return _failed(pack, str(exc))

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:200]
        return _failed(pack, f"rewrite CLI exited {result.returncode}: {detail}")

    source = extract_code_block(result.stdout)
    if source is None:
        return _failed(pack, "response contained no fenced code block")

    banned = check_rewrite_content(source)
    if banned is not None:
        return _failed(pack, banned)

    if source.strip() == str(pack.get("candidateSource") or "").strip():
        return _failed(pack, "candidate returned unchanged; no rewrite to verify")

    return {
        "schema": SCHEMA,
        "status": "completed",
        "functionName": pack.get("functionName"),
        "entry": pack.get("entry"),
        "source": source,
        "reason": None,
        "claimBoundary": CLAIM_BOUNDARY,
    }
