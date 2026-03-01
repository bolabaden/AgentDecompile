from __future__ import annotations

import os
import subprocess
import time
from typing import Sequence

import pytest

REMOTE_URL = "http://170.9.241.140:8080/"
LOCAL_URL = "http://127.0.0.1:8081/"
PROGRAM_PATH = "/K1/k1_win_gog_swkotor.exe"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = "OpenKotOR"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = "MuchaShakaPaka"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = "170.9.241.140"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = "13100"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = "Odyssey"
    env["AGENT_DECOMPILE_BACKEND_URL"] = REMOTE_URL
    return env


def _run(cmd: Sequence[str], env: dict[str, str]) -> tuple[bool, int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
    return proc.returncode == 0, proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _remote_backend_available(env: dict[str, str]) -> bool:
    probe_cmd: list[str] = [
        "uvx",
        "--from",
        ".",
        "--with-editable",
        ".",
        "agentdecompile-cli",
        "--server-url",
        REMOTE_URL,
        "list",
        "project-files",
    ]
    ok, _, _, err = _run(probe_cmd, env)
    if ok:
        return True
    return "Cannot connect to AgentDecompile server" not in err


def _cmdline(cmd: Sequence[str]) -> str:
    return subprocess.list2cmdline(list(cmd))


def _describe_cli_call(cmd: Sequence[str]) -> tuple[str, str]:
    parts: list[str] = list(cmd)
    try:
        i = parts.index("agentdecompile-cli")
    except ValueError:
        return "unknown", "unable to locate agentdecompile-cli token"

    args: list[str] = parts[i + 1 :]
    if args[:2] == ["--server-url", REMOTE_URL] or args[:2] == ["--server-url", LOCAL_URL]:
        args = args[2:]

    if not args:
        return "none", "no command arguments"

    if args[0] == "tool":
        tool_name = args[1] if len(args) > 1 else ""
        tool_args = args[2] if len(args) > 2 else "{}"
        return tool_name, tool_args

    if args[0] == "references" and len(args) > 1:
        return f"references {args[1]}", " ".join(args[2:])

    if args[0] == "list" and len(args) > 1:
        return f"list {args[1]}", " ".join(args[2:])

    return args[0], " ".join(args[1:])


def _commands(server_url: str) -> list[tuple[str, list[str]]]:
    base = ["uvx", "--from", ".", "--with-editable", ".", "agentdecompile-cli", "--server-url", server_url]
    return [
        (
            "1) open shared program",
            base
            + [
                "open",
                "--server_host",
                "170.9.241.140",
                "--server_port",
                "13100",
                "--server_username",
                "OpenKotOR",
                "--server_password",
                "MuchaShakaPaka",
                PROGRAM_PATH,
            ],
        ),
        ("2) list project-files", base + ["list", "project-files"]),
        ("3) get-functions", base + ["get-functions", "--program_path", PROGRAM_PATH, "--limit", "5"]),
        (
            "4) search-symbols-by-name",
            base
            + [
                "search-symbols-by-name",
                "--program_path",
                PROGRAM_PATH,
                "--query",
                "main",
                "--max_results",
                "5",
            ],
        ),
        (
            "5) references to",
            base + ["references", "to", "--binary", PROGRAM_PATH, "--target", "WinMain", "--limit", "5"],
        ),
        (
            "6) get-current-program",
            base + ["tool", "get-current-program", f'{{"programPath":"{PROGRAM_PATH}"}}'],
        ),
        (
            "7a) list-imports",
            base + ["tool", "list-imports", f'{{"programPath":"{PROGRAM_PATH}","limit":5}}'],
        ),
        (
            "7b) list-exports",
            base + ["tool", "list-exports", f'{{"programPath":"{PROGRAM_PATH}","limit":5}}'],
        ),
    ]


def _print_exact_output(stdout_text: str, stderr_text: str) -> None:
    print("  --- stdout (exact) ---")
    print(stdout_text if stdout_text else "<empty>")
    print("  --- stderr (exact) ---")
    print(stderr_text if stderr_text else "<empty>")


def _run_phase(
    title: str,
    server_url: str,
    env: dict[str, str],
) -> tuple[bool, list[str]]:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)

    failures: list[str] = []

    for label, cmd in _commands(server_url):
        tool_name, tool_params = _describe_cli_call(cmd)
        print(f"\n[EXEC] {label}")
        print(f"  command: {_cmdline(cmd)}")
        print(f"  tool/command: {tool_name}")
        print(f"  parameters: {tool_params if tool_params else '<none>'}")

        ok, return_code, out, err = _run(cmd, env)
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {label} (exit={return_code})")
        _print_exact_output(out, err)

        if not ok:
            failures.append(
                f"{label} failed (exit={return_code})\ncommand: {_cmdline(cmd)}\nstdout:\n{out or '<empty>'}\nstderr:\n{err or '<empty>'}\n",
            )

    return len(failures) == 0, failures


def _wait_proxy_ready(
    env: dict[str, str],
    timeout_sec: int = 30,
) -> bool:
    deadline = time.time() + timeout_sec
    health_cmd: list[str] = [
        "uvx",
        "--from",
        ".",
        "--with-editable",
        ".",
        "agentdecompile-cli",
        "--server-url",
        LOCAL_URL,
        "tool",
        "list-imports",
        f'{{"programPath":"{PROGRAM_PATH}","limit":1}}',
    ]

    while time.time() < deadline:
        ok, _, _, _ = _run(health_cmd, env)
        if ok:
            return True
        time.sleep(1)

    return False


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.timeout(900)
def test_proxy_bootstrap_exact_commands() -> None:
    env = _env()

    if not _remote_backend_available(env):
        pytest.skip(f"Remote AgentDecompile backend unavailable at {REMOTE_URL}")

    remote_ok, remote_failures = _run_phase("PHASE 1: DIRECT REMOTE COMMANDS", REMOTE_URL, env)
    assert remote_ok, "Remote phase failed:\n" + "\n".join(remote_failures)

    proxy_cmd: list[str] = [
        "uvx",
        "--from",
        ".",
        "--with-editable",
        ".",
        "agentdecompile-proxy",
        "--backend",
        REMOTE_URL,
        "--http",
        "--host",
        "127.0.0.1",
        "--port",
        "8081",
    ]

    print("\nStarting local proxy server...")
    print(f"Proxy command: {_cmdline(proxy_cmd)}")
    proxy_proc = subprocess.Popen(proxy_cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        assert _wait_proxy_ready(env), "Local proxy did not become ready"

        proxy_ok, proxy_failures = _run_phase("PHASE 2: SAME COMMANDS VIA LOCAL PROXY", LOCAL_URL, env)
        assert proxy_ok, "Proxy phase failed:\n" + "\n".join(proxy_failures)
    finally:
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
