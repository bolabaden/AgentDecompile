"""LLM cleanup of Ghidra C that still fails after mechanical preparse.

The model may only edit the given Ghidra body. It may not rewrite from
scratch and may not emit machine-code shims. Compile success, not the
response, decides whether the edit is kept.

The prompt always includes the text of `agentdecompile-cli get-function`
(decompile, disassembly, callers/callees, types). That is the Ghidra
context the edit is based on.

Uses the local `claude` CLI in print mode with no tools — the same isolation
as rewrite_provider. No credentialed HTTP client.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

from .source_claims import is_recovered_source

DEFAULT_CLI = "claude"
DEFAULT_GET_FUNCTION_CLI = "agentdecompile-cli"
DEFAULT_TIMEOUT_SECONDS = 180
GET_FUNCTION_TIMEOUT_SECONDS = 90
GET_FUNCTION_PROMPT_CHARS = 16000
_FENCE_RE = re.compile(r"```(?:c|cpp|C|cc)?\n(.*?)```", re.S)

CLEANUP_PROMPT = """\
# Task

Edit the Ghidra C below so a C compiler accepts it. This body already went
through mechanical preparse (templates flattened, __thiscall rewritten,
CONCAT/SUB macros, stub types). The compiler still rejected it.

The authoritative Ghidra view is the `agentdecompile-cli get-function`
output in the next section. Use it for names, types, callees, and assembly.
Edit the current function body; do not invent a new function from scratch.

Rules:
- Edit this function. Do not invent a new one from scratch.
- Keep the same function name and parameter count.
- Do not add __asm, naked, _emit, .byte, or incbin.
- Do not explain. Return one fenced C code block with the full function.

## agentdecompile-cli get-function

{get_function}

## Compiler errors

{errors}

## Header already supplied (do not repeat unless you must add a typedef)

{header}

## Current function body (after preparse)

```c
{body}
```
"""


@dataclass(frozen=True)
class CliResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], str, int], CliResult]


def _fill(template: str, **values: str) -> str:
    text = template
    for key, value in values.items():
        text = text.replace("{" + key + "}", value)
    return text


def render_cleanup_prompt(*, body: str, errors: str, header: str = "", get_function: str = "") -> str:
    gf = (get_function or "").strip()
    if not gf:
        raise ValueError("get-function output is required before calling the LLM")
    return _fill(
        CLEANUP_PROMPT,
        get_function=gf[:GET_FUNCTION_PROMPT_CHARS],
        errors=(errors or "(no diagnostic)")[:2500],
        header=(header or "(none)")[:2500],
        body=body[:12000],
    )


def extract_code_block(response: str) -> str | None:
    if not isinstance(response, str):
        return None
    match = _FENCE_RE.search(response)
    if match is None:
        text = response.strip()
        if text.startswith(("void ", "int ", "char ", "unsigned ", "static ", "float ")):
            return text
        return None
    return match.group(1).strip() or None


def build_cli_command(*, cli: str = DEFAULT_CLI, model: str | None = None) -> list[str]:
    command = [cli, "-p", "--output-format", "text", "--tools", ""]
    if model:
        command.extend(["--model", model])
    return command


def resolve_mcp_server_url() -> str | None:
    for key in (
        "AGENTDECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENTDECOMPILE_SERVER_URL",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return None


def function_identifier(row: dict | None, *, fallback: str = "") -> str:
    if not isinstance(row, dict):
        return fallback
    for key in ("entry", "entry_hex", "entryHex", "address", "addr", "functionIdentifier"):
        value = row.get(key)
        if value:
            return str(value).strip()
    for key in ("name", "id"):
        value = row.get(key)
        if value:
            return str(value).strip()
    return fallback


def program_path_for_row(row: dict | None, *, fallback: str = "") -> str:
    if not isinstance(row, dict):
        return fallback
    for key in ("program_path", "programPath", "ghidra_program", "ghidraProgram"):
        value = row.get(key)
        if value:
            return str(value).strip()
    return fallback


def build_get_function_command(
    *,
    program_path: str,
    identifier: str,
    server_url: str | None = None,
    cli: str = DEFAULT_GET_FUNCTION_CLI,
) -> list[str]:
    if shutil.which(cli):
        command = [cli]
    elif shutil.which("uv"):
        command = ["uv", "run", DEFAULT_GET_FUNCTION_CLI]
    else:
        command = [cli]
    if server_url:
        command.extend(["--server-url", server_url])
    command.extend(
        [
            "--format",
            "text",
            "get-function",
            "--program_path",
            program_path,
            "--function",
            identifier,
            "--max_instructions",
            "400",
            "--max_refs",
            "80",
            "--max_callers",
            "12",
            "--max_callees",
            "12",
        ]
    )
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


def fetch_get_function_cli(
    *,
    program_path: str,
    identifier: str,
    server_url: str | None = None,
    timeout: int = GET_FUNCTION_TIMEOUT_SECONDS,
    runner: Runner | None = None,
) -> dict:
    """Run `agentdecompile-cli get-function` and return {ok, text, reason, command}."""
    if not program_path or not identifier:
        return {
            "ok": False,
            "text": None,
            "reason": "get-function needs --program_path and --function",
            "command": [],
        }
    command = build_get_function_command(
        program_path=program_path,
        identifier=identifier,
        server_url=server_url or resolve_mcp_server_url(),
    )
    execute = runner or _subprocess_runner
    try:
        result = execute(command, "", timeout)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "text": None,
            "reason": f"get-function timed out after {timeout}s",
            "command": command,
        }
    except (OSError, ValueError) as exc:
        return {"ok": False, "text": None, "reason": str(exc), "command": command}
    text = (result.stdout or "").strip()
    if result.returncode != 0 or not text:
        detail = (result.stderr or result.stdout or "").strip()[:200]
        return {
            "ok": False,
            "text": None,
            "reason": f"get-function exited {result.returncode}: {detail or 'empty output'}",
            "command": command,
        }
    return {"ok": True, "text": text, "reason": None, "command": command}


def resolve_get_function_text(
    *,
    get_function: str | None = None,
    program_path: str | None = None,
    identifier: str | None = None,
    server_url: str | None = None,
    get_function_runner: Runner | None = None,
) -> dict:
    supplied = (get_function or "").strip()
    if supplied:
        return {"ok": True, "text": supplied, "reason": None, "command": []}
    return fetch_get_function_cli(
        program_path=program_path or "",
        identifier=identifier or "",
        server_url=server_url,
        runner=get_function_runner,
    )


def cleanup_ghidra_c(
    *,
    body: str,
    errors: str,
    header: str = "",
    get_function: str | None = None,
    program_path: str | None = None,
    identifier: str | None = None,
    server_url: str | None = None,
    cli: str = DEFAULT_CLI,
    model: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    runner: Runner | None = None,
    get_function_runner: Runner | None = None,
) -> dict:
    """Return {ok, source, reason}. ok means a real-C edit was returned, not that it compiles."""
    context = resolve_get_function_text(
        get_function=get_function,
        program_path=program_path,
        identifier=identifier,
        server_url=server_url,
        get_function_runner=get_function_runner,
    )
    if not context.get("ok"):
        if (body or "").strip():
            reason = context.get("reason") or "get-function failed"
            context = {
                "ok": True,
                "text": (
                    "# get-function unavailable\n"
                    f"reason: {reason}\n"
                    "Using the Ghidra C already in `body` from the knowledge store.\n"
                ),
                "reason": reason,
            }
        else:
            return {"ok": False, "source": None, "reason": context.get("reason") or "get-function failed"}
    if not shutil.which(cli) and runner is None:
        return {"ok": False, "source": None, "reason": f"{cli} is not on PATH"}
    prompt = render_cleanup_prompt(
        body=body,
        errors=errors,
        header=header,
        get_function=str(context.get("text") or ""),
    )
    execute = runner or _subprocess_runner
    try:
        result = execute(build_cli_command(cli=cli, model=model), prompt, timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "source": None, "reason": f"LLM timed out after {timeout}s"}
    except (OSError, ValueError) as exc:
        return {"ok": False, "source": None, "reason": str(exc)}
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:200]
        return {"ok": False, "source": None, "reason": f"LLM exited {result.returncode}: {detail}"}
    source = extract_code_block(result.stdout)
    if not source:
        return {"ok": False, "source": None, "reason": "no C in the model response"}
    if not is_recovered_source(source):
        return {"ok": False, "source": None, "reason": "model returned a machine-code shim"}
    if source.strip() == body.strip():
        return {"ok": False, "source": None, "reason": "model returned the same body"}
    return {"ok": True, "source": source, "reason": None}
