#!/usr/bin/env python3
"""Automate the strict ``/lfg`` Ghidra shared + local collaboration validation.

**Single entry point for agents and CI:** this module owns **all** orchestration — Ghidra Server
lifecycle (optional), ``agentdecompile-server`` subprocesses, every ``tool-seq`` phase, Ghidra +
MCP restarts for persistence proof, and a nested pytest run for transport/session tests. Do **not**
start long-lived MCP or Ghidra processes in a **foreground** Cursor terminal step; either run
``pytest tests/test_lfg_e2e.py -m lfg`` (servers are child processes) or use a **background**
terminal if you must start them manually.

It writes every JSON payload and subprocess transcript under ``<repo>/.lfg_run/<run_tag>_<ts>/``.

**Strict /lfg §0.2 / §7:** A shared ``open`` and a local-directory ``open`` must **not** share one
MCP server process without a restart in between. So after Ghidra restart + MCP restart, **§7a**
(shared proof) and **§7b** (local proof) are **two** ``tool-seq`` runs with **another** MCP
restart between them — same pattern as Track A → MCP restart → Track B. Proof JSON for P6 is
``P6_7a_*.steps.json`` and ``P6_7b_*.steps.json`` (three explicit read steps each, matching the
three check-ins / mutations).

**Preferred — pytest (sharded, 120s per test default)**::

    uv run pytest tests/test_lfg_e2e.py -m lfg -v --timeout=120

**Single-process full stack (CLI)** — all phases 1–9 in one process::

    uv run python scripts/lfg_validation.py --run-id … --manage-mcp --mcp-port 8099 …

**CLI** (same code path as pytest; Ghidra Server may already be running)::

    uv run python scripts/lfg_validation.py --run-id lfg20260321d \\
        --manage-mcp --mcp-port 8099 --manage-ghidra-server --prepare-local-dir

Public API for tests: :func:`run_lfg_cli`.

Requirements
------------
- ``GHIDRA_INSTALL_DIR`` points at a Ghidra install (for ``server/server.conf`` and PyGhidra).
- Shared Ghidra Server listening on the TCP base port given by ``-p####`` in ``server.conf``
  (unless ``--manage-ghidra-server`` starts it).
- Repository credentials valid for ``open`` with ``shared: true``.

Exit code ``0`` only if every phase succeeds (including nested pytest).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Sequence

LOG = logging.getLogger("lfg")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# Subprocess / wait ceilings (seconds). Override with env vars; prevents indefinite hangs.
# Values sized for cold PyGhidra/JVM + shared Ghidra Server on Windows CI; LFG pytest uses a 900s marker.
_DEFAULT_TOOL_SEQ_TIMEOUT = _env_float("LFG_TOOL_SEQ_TIMEOUT", 180.0)
_DEFAULT_MCP_HEALTH_TIMEOUT = _env_float("LFG_MCP_HEALTH_TIMEOUT", 240.0)
_DEFAULT_GHIDRA_TCP_TIMEOUT = _env_float("LFG_GHIDRA_TCP_TIMEOUT", 90.0)
_DEFAULT_NESTED_PYTEST_TIMEOUT = _env_float("LFG_NESTED_PYTEST_TIMEOUT", 300.0)
# 0 = no overall wall unless pytest/CLI passes --max-wall-seconds or sets LFG_MAX_WALL_SECONDS.
_DEFAULT_MAX_WALL = _env_float("LFG_MAX_WALL_SECONDS", 0.0)

# Subprocess output mirrored to the driver log (full transcripts stay in *.cli.*.log on disk).
_LFG_LOG_INFO_CHARS = 1000
# Extra characters logged only at DEBUG when the driver runs with ``-v`` / verbose logging.
_LFG_LOG_VERBOSE_GAP_CHARS = 700


# ---------------------------------------------------------------------------
# Paths / discovery
# ---------------------------------------------------------------------------


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_python_exe(repo_root: Path) -> Path:
    win_venv = repo_root / ".venv" / "Scripts" / "python.exe"
    if win_venv.is_file():
        return win_venv
    nix_venv = repo_root / ".venv" / "bin" / "python"
    if nix_venv.is_file():
        return nix_venv
    return Path(sys.executable)


def read_ghidra_server_base_port(ghidra_install_dir: Path) -> int:
    conf = ghidra_install_dir / "server" / "server.conf"
    if not conf.is_file():
        raise FileNotFoundError(f"Ghidra server.conf not found: {conf}")
    text = conf.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(
        r"wrapper\.app\.parameter\.\d+\s*=\s*-p\s*(\d+)",
        text,
        flags=re.IGNORECASE,
    ):
        return int(m.group(1))
    m2 = re.search(r"-p\s*(\d{4,6})\b", text)
    if m2:
        return int(m2.group(1))
    raise ValueError(f"Could not find -p#### base port in {conf}")


def ghidra_server_dir(ghidra_install_dir: Path) -> Path:
    return ghidra_install_dir / "server"


def effective_program_path(program_path: str, run_id: str, *, isolate_by_run_id: bool) -> str:
    """Stable in-project path for import-binary / tool steps.

    When ``isolate_by_run_id`` is true (default), each run uses ``/sort_<run_id>.exe`` (from the
    basename of ``program_path``) so a shared repo is not stuck with prior ``sh_*`` renames on a
    single ``/sort.exe`` program.
    """
    raw = (program_path or "/sort.exe").strip().replace("\\", "/")
    if not raw.startswith("/"):
        raw = "/" + raw
    if not isolate_by_run_id:
        return raw
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", run_id).strip("_") or "run"
    stem = Path(raw).stem or "sort"
    ext = Path(raw).suffix or ".exe"
    return f"/{stem}_{safe}{ext}"


# ---------------------------------------------------------------------------
# Windows port / process helpers
# ---------------------------------------------------------------------------


def _windows_pids_listening_tcp(port: int) -> list[int]:
    proc = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        LOG.warning("netstat -ano failed rc=%s stderr=%s", proc.returncode, proc.stderr[:500])
        return []
    pids: set[int] = set()
    needle = f":{port}"
    for line in proc.stdout.splitlines():
        if "LISTENING" not in line.upper():
            continue
        if needle not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            pids.add(int(parts[-1]))
        except ValueError:
            continue
    return sorted(pids)


def pids_listening_tcp(port: int) -> list[int]:
    if sys.platform == "win32":
        return _windows_pids_listening_tcp(port)
    proc = subprocess.run(
        ["ss", "-ltnp", f"sport = :{port}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        proc = subprocess.run(
            ["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return []
        return [int(x) for x in proc.stdout.split() if x.strip().isdigit()]
    # ss output parsing is distro-specific; keep minimal
    pids: set[int] = set()
    for m in re.finditer(r"pid=(\d+)", proc.stdout):
        pids.add(int(m.group(1)))
    return sorted(pids)


def kill_pid_tree(pid: int, *, logger: logging.Logger = LOG) -> None:
    if sys.platform == "win32":
        r = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            errors="replace",
        )
        logger.info("taskkill /PID %s /T /F -> rc=%s out=%s err=%s", pid, r.returncode, r.stdout, r.stderr)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            logger.debug("PID %s already gone (SIGTERM)", pid)
        else:
            logger.info("SIGTERM pid=%s", pid)


def kill_all_on_port(port: int, *, logger: logging.Logger = LOG) -> list[int]:
    pids = pids_listening_tcp(port)
    for pid in pids:
        kill_pid_tree(pid, logger=logger)
    return pids


def wait_tcp_port(
    host: str,
    port: int,
    *,
    timeout_s: float = 120.0,
    poll_s: float = 0.5,
    logger: logging.Logger = LOG,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((host, port))
            s.close()
            logger.info("TCP %s:%s is accepting connections", host, port)
            return True
        except OSError:
            time.sleep(poll_s)
    logger.error("Timeout waiting for TCP %s:%s", host, port)
    return False


def http_get_ok(url: str, *, timeout_s: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def wait_http_health(base_url: str, *, timeout_s: float = 240.0, logger: logging.Logger = LOG) -> bool:
    health = base_url.rstrip("/") + "/health"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if http_get_ok(health):
            logger.info("HTTP health OK: %s", health)
            return True
        time.sleep(0.5)
    logger.error("Timeout waiting for HTTP health: %s", health)
    return False


# ---------------------------------------------------------------------------
# Managed MCP subprocess
# ---------------------------------------------------------------------------


@dataclass
class ManagedMcpServer:
    repo_root: Path
    python_exe: Path
    host: str
    port: int
    project_path: Path
    ghidra_install_dir: Path
    log_dir: Path
    health_timeout_s: float = 240.0
    proc: subprocess.Popen[bytes] | None = None
    _out_fp: Any = None
    _err_fp: Any = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self, logger: logging.Logger = LOG, *, health_timeout_s: float | None = None) -> None:
        if self.proc and self.proc.poll() is None:
            logger.info("MCP already running (pid=%s)", self.proc.pid)
            return
        stale = kill_all_on_port(self.port, logger=logger)
        if stale:
            logger.info("Cleared stale listener(s) on port %s: %s", self.port, stale)
            time.sleep(1.0)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.log_dir / "mcp_server.stdout.log"
        err_path = self.log_dir / "mcp_server.stderr.log"
        self._out_fp = open(out_path, "ab", buffering=0)  # noqa: SIM115
        self._err_fp = open(err_path, "ab", buffering=0)  # noqa: SIM115
        env = os.environ.copy()
        env["GHIDRA_INSTALL_DIR"] = str(self.ghidra_install_dir)
        _ensure_src_on_pythonpath(self.repo_root, env)
        cmd = [
            str(self.python_exe),
            "-m",
            "agentdecompile_cli.server",
            "-t",
            "streamable-http",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--project-path",
            str(self.project_path),
        ]
        logger.info("Starting MCP: %s", " ".join(cmd))
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(self.repo_root),
            env=env,
            stdout=self._out_fp,
            stderr=self._err_fp,
            creationflags=creationflags,
            text=False,
        )
        logger.info("MCP subprocess pid=%s", self.proc.pid)
        hto = self.health_timeout_s if health_timeout_s is None else health_timeout_s
        if not wait_http_health(self.base_url, timeout_s=hto, logger=logger):
            self.stop(logger=logger)
            raise RuntimeError("MCP server failed to become healthy")
        logger.info("MCP listening at %s/mcp/message", self.base_url)

    def stop(self, logger: logging.Logger = LOG) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is not None:
            logger.debug("MCP already exited rc=%s", self.proc.returncode)
        else:
            logger.info("Stopping MCP pid=%s", self.proc.pid)
            if sys.platform == "win32":
                kill_pid_tree(self.proc.pid, logger=logger)
            else:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        self.proc = None
        for fp in (self._out_fp, self._err_fp):
            if fp is not None:
                try:
                    fp.close()
                except OSError:
                    pass
        self._out_fp = self._err_fp = None


# ---------------------------------------------------------------------------
# tool-seq runner
# ---------------------------------------------------------------------------


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _safe_console_text(text: str) -> str:
    """Avoid UnicodeEncodeError when logging tails on Windows (cp1252 StreamHandler)."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(enc, errors="replace").decode(enc, errors="replace")


def _tail(text: str, max_chars: int) -> str:
    if not text or max_chars <= 0:
        return ""
    return text if len(text) <= max_chars else text[-max_chars:]


def _log_tool_seq_streams(
    logger: logging.Logger,
    *,
    phase_name: str,
    stdout: str,
    stderr: str,
    verbose: bool,
    failed: bool,
) -> None:
    """Keep driver console noise low: 1000 chars at WARNING/ERROR; optional 700-char gap at DEBUG when verbose."""
    if stderr.strip():
        chunk = _safe_console_text(_tail(stderr, _LFG_LOG_INFO_CHARS))
        if failed:
            logger.error("%s stderr (last <=%d chars): %s", phase_name, _LFG_LOG_INFO_CHARS, chunk)
        else:
            logger.warning("%s stderr (last <=%d chars): %s", phase_name, _LFG_LOG_INFO_CHARS, chunk)
    if failed and stdout.strip() and not stderr.strip():
        logger.error(
            "%s stdout (last <=%d chars): %s",
            phase_name,
            _LFG_LOG_INFO_CHARS,
            _safe_console_text(_tail(stdout, _LFG_LOG_INFO_CHARS)),
        )
    if not verbose:
        return
    if stdout:
        logger.debug(
            "%s stdout tail (<=%d chars): %s",
            phase_name,
            _LFG_LOG_INFO_CHARS,
            _safe_console_text(_tail(stdout, _LFG_LOG_INFO_CHARS)),
        )
        if len(stdout) > _LFG_LOG_INFO_CHARS + _LFG_LOG_VERBOSE_GAP_CHARS:
            gap = stdout[-(_LFG_LOG_INFO_CHARS + _LFG_LOG_VERBOSE_GAP_CHARS) : -_LFG_LOG_INFO_CHARS]
            logger.debug(
                "%s stdout verbose-only (%d chars before info tail): %s",
                phase_name,
                _LFG_LOG_VERBOSE_GAP_CHARS,
                _safe_console_text(gap),
            )


def _ensure_src_on_pythonpath(repo_root: Path, env: dict[str, str]) -> None:
    """So ``python -m agentdecompile_cli.*`` works when the package is not installed."""
    src = str((repo_root / "src").resolve())
    cur = env.get("PYTHONPATH", "").strip()
    parts = [p for p in cur.split(os.pathsep) if p]
    if src not in parts:
        env["PYTHONPATH"] = src if not parts else src + os.pathsep + os.pathsep.join(parts)


def run_tool_seq(
    *,
    repo_root: Path,
    python_exe: Path,
    server_url: str,
    steps: list[dict[str, Any]],
    log_dir: Path,
    phase_name: str,
    logger: logging.Logger = LOG,
    extra_env: dict[str, str] | None = None,
    timeout_s: float = _DEFAULT_TOOL_SEQ_TIMEOUT,
    verbose: bool = False,
    tool_seq_json_output: bool = True,
    lfg_strict_verify: Literal["track_a", "track_b", "none"] = "none",
    lfg_run_id: str | None = None,
) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    json_path = log_dir / f"{phase_name}.steps.json"
    write_json(json_path, steps)
    out_path = log_dir / f"{phase_name}.cli.stdout.log"
    err_path = log_dir / f"{phase_name}.cli.stderr.log"
    cmd = [
        str(python_exe),
        "-m",
        "agentdecompile_cli.cli",
        "--server-url",
        server_url,
    ]
    if tool_seq_json_output:
        cmd.extend(["-f", "json"])
    cmd.extend(
        [
            "tool-seq",
            f"@{json_path}",
        ]
    )
    logger.info("PHASE %s: %s", phase_name, " ".join(cmd))
    env = os.environ.copy()
    _ensure_src_on_pythonpath(repo_root, env)
    if extra_env:
        env.update(extra_env)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        dt = time.perf_counter() - t0
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        out_path.write_text(out, encoding="utf-8")
        err_path.write_text(err, encoding="utf-8")
        logger.error(
            "PHASE %s timed out after %.1fs (timeout_s=%.1fs) exit=%s",
            phase_name,
            dt,
            timeout_s,
            getattr(exc, "returncode", None),
        )
        _log_tool_seq_streams(
            logger,
            phase_name=phase_name,
            stdout=out,
            stderr=err,
            verbose=verbose,
            failed=True,
        )
        raise RuntimeError(
            f"tool-seq phase {phase_name!r} timed out after {timeout_s:.1f}s; see {out_path}"
        ) from exc
    dt = time.perf_counter() - t0
    out_path.write_text(proc.stdout or "", encoding="utf-8")
    err_path.write_text(proc.stderr or "", encoding="utf-8")
    logger.info(
        "PHASE %s finished in %.2fs exit=%s (stdout %s bytes stderr %s bytes)",
        phase_name,
        dt,
        proc.returncode,
        len(proc.stdout or ""),
        len(proc.stderr or ""),
    )
    _log_tool_seq_streams(
        logger,
        phase_name=phase_name,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        verbose=verbose,
        failed=proc.returncode != 0,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"tool-seq phase {phase_name!r} failed with exit {proc.returncode}; see {out_path}")

    if lfg_strict_verify != "none":
        rid = (lfg_run_id or "").strip()
        if not rid:
            raise RuntimeError("lfg_strict_verify requires lfg_run_id")
        raw = out_path.read_text(encoding="utf-8", errors="replace")
        try:
            if lfg_strict_verify == "track_a":
                verify_lfg_track_a_tool_seq_json(raw, rid)
            elif lfg_strict_verify == "track_b":
                verify_lfg_track_b_tool_seq_json(raw, rid)
        except (AssertionError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"LFG strict verification failed for {phase_name!r} (run_id={rid}): {exc}",
            ) from exc
        logger.info("LFG strict verification passed for %s (run_id=%s)", phase_name, rid)


def run_pytest(
    *,
    repo_root: Path,
    python_exe: Path,
    log_dir: Path,
    logger: logging.Logger = LOG,
    timeout_s: float = _DEFAULT_NESTED_PYTEST_TIMEOUT,
    inner_test_timeout_s: float = 30.0,
    verbose: bool = False,
) -> None:
    tests = [
        "tests/test_mcp_transport_sdk.py",
        "tests/test_session_context.py",
    ]
    out_path = log_dir / "pytest.stdout.log"
    err_path = log_dir / "pytest.stderr.log"
    inner_to = max(5.0, min(inner_test_timeout_s, timeout_s / 3.0))
    cmd = [
        str(python_exe),
        "-m",
        "pytest",
        *tests,
        "-v",
        "-m",
        "not lfg",
        "--timeout",
        str(int(inner_to)),
        "-q",
    ]
    logger.info("PYTEST: %s (subprocess timeout %.1fs)", " ".join(cmd), timeout_s)
    env = os.environ.copy()
    _ensure_src_on_pythonpath(repo_root, env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        out_path.write_text(out, encoding="utf-8")
        err_path.write_text(err, encoding="utf-8")
        logger.error("pytest subprocess timed out after %.1fs", timeout_s)
        raise RuntimeError(f"nested pytest timed out after {timeout_s:.1f}s; see {out_path}") from exc
    out_path.write_text(proc.stdout or "", encoding="utf-8")
    err_path.write_text(proc.stderr or "", encoding="utf-8")
    logger.info("pytest exit=%s", proc.returncode)
    out = proc.stdout or ""
    if out:
        logger.info("pytest stdout (last <=%d chars): %s", _LFG_LOG_INFO_CHARS, _safe_console_text(_tail(out, _LFG_LOG_INFO_CHARS)))
        if verbose and len(out) > _LFG_LOG_INFO_CHARS + _LFG_LOG_VERBOSE_GAP_CHARS:
            gap = out[-(_LFG_LOG_INFO_CHARS + _LFG_LOG_VERBOSE_GAP_CHARS) : -_LFG_LOG_INFO_CHARS]
            logger.debug(
                "pytest stdout verbose-only (%d chars before info tail): %s",
                _LFG_LOG_VERBOSE_GAP_CHARS,
                _safe_console_text(gap),
            )
    err = proc.stderr or ""
    if proc.returncode != 0 and err.strip():
        logger.error("pytest stderr (last <=%d chars): %s", _LFG_LOG_INFO_CHARS, _safe_console_text(_tail(err, _LFG_LOG_INFO_CHARS)))
    if proc.returncode != 0:
        raise RuntimeError(f"pytest failed exit={proc.returncode}; see {out_path}")


# ---------------------------------------------------------------------------
# Post-run strict verification (JSON tool-seq envelope)
# ---------------------------------------------------------------------------


def _lfg_tool_result_text(step: dict[str, Any]) -> str:
    r = step.get("result")
    if not isinstance(r, dict):
        return ""
    content = r.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        return ""
    t = content[0].get("text")
    return t if isinstance(t, str) else ""


def _lfg_parse_tool_markdown_kv(text: str) -> dict[str, Any]:
    """Parse ``**key:** value`` lines from CLI markdown tool output (used even when ``-f json``)."""
    kv: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m = re.match(r"^\*\*([^*]+):\*\*\s*(.+?)\s*$", line)
        if not m:
            continue
        key = m.group(1).strip().lower().replace(" ", "_")
        val = m.group(2).strip()
        if val == "None":
            kv[key] = None
        elif val in ("True", "False"):
            kv[key] = val == "True"
        elif val == "[]":
            kv[key] = []
        elif re.fullmatch(r"-?\d+", val):
            kv[key] = int(val)
        else:
            kv[key] = val
    return kv


def _lfg_inner_tool_payload(step: dict[str, Any]) -> dict[str, Any] | None:
    """Parse tool body from MCP ``content[0].text`` (JSON or markdown **key:** lines)."""
    t = _lfg_tool_result_text(step)
    if not t.strip():
        return None
    try:
        if t.lstrip().startswith("{"):
            return json.loads(t)
    except json.JSONDecodeError:
        pass
    if "##" in t and "**" in t:
        parsed = _lfg_parse_tool_markdown_kv(t)
        return parsed if parsed else None
    return None


def verify_lfg_track_a_tool_seq_json(stdout: str, run_id: str) -> None:
    """Assert check-ins completed, ``sync-project`` real pull/push have ``errors: []``, symbols survive pull/push.

    Parses the **outer** tool-seq JSON envelope; nested tool bodies may be markdown (**checkout-status** is
    unreliable for ``latest_version`` on shared imports in the current resolver, so we do not assert VC numbers).
    """
    sh = f"sh_{run_id}"
    data = json.loads(stdout.strip())
    if not data.get("success"):
        raise AssertionError("tool-seq envelope success is false")
    steps = data.get("steps")
    if not isinstance(steps, list):
        raise AssertionError("tool-seq envelope missing steps list")

    checkins = 0
    sh_symbol_totals: list[int] = []
    saw_pull_real = False
    saw_push_real = False

    for step in steps:
        if not isinstance(step, dict) or not step.get("success"):
            continue
        name = step.get("name")
        text = _lfg_tool_result_text(step)
        inner = _lfg_inner_tool_payload(step)

        if name == "checkin-program":
            checkins += 1

        elif name == "sync-project" and inner is not None:
            errs = inner.get("errors")
            if errs not in (None, []):
                raise AssertionError(f"sync-project reported errors: {errs}")
            dry = inner.get("dryrun")
            if dry is False:
                direction = inner.get("direction")
                if direction == "pull":
                    saw_pull_real = True
                elif direction == "push":
                    saw_push_real = True

        elif name == "search-symbols" and sh in text:
            m = re.search(r"Showing \*\*(\d+)\*\* of \*\*(\d+)\*\*", text)
            if not m:
                raise AssertionError(f"search-symbols step missing result counts for {sh!r}")
            sh_symbol_totals.append(int(m.group(2)))

    if checkins < 3:
        raise AssertionError(f"expected 3 successful checkin-program steps, got {checkins}")

    if not saw_pull_real or not saw_push_real:
        raise AssertionError(f"missing real pull or push sync step (pull={saw_pull_real} push={saw_push_real})")

    if len(sh_symbol_totals) < 3:
        raise AssertionError(
            f"expected search-symbols for {sh!r} after read-back, post-pull, post-push (3+), got {sh_symbol_totals!r}",
        )
    for t in sh_symbol_totals:
        if t < 3:
            raise AssertionError(
                f"search-symbols for {sh!r} expected total>=3 (three mutations), got {sh_symbol_totals!r} — "
                "local project view lost symbols after sync?",
            )


def verify_lfg_track_b_tool_seq_json(stdout: str, run_id: str) -> None:
    """Assert local (non-versioned) check-ins: checkout-status must not report shared version control."""
    loc = f"loc_{run_id}"
    data = json.loads(stdout.strip())
    if not data.get("success"):
        raise AssertionError("tool-seq envelope success is false")
    steps = data.get("steps")
    if not isinstance(steps, list):
        raise AssertionError("tool-seq envelope missing steps list")

    loc_totals: list[int] = []
    post_checkin_local_status = 0

    for step in steps:
        if not isinstance(step, dict) or not step.get("success"):
            continue
        name = step.get("name")
        text = _lfg_tool_result_text(step)
        inner = _lfg_inner_tool_payload(step)

        if name == "checkout-status" and inner is not None and inner.get("action") == "checkout_status":
            post_checkin_local_status += 1
            if inner.get("is_versioned") is True:
                raise AssertionError(
                    "local .gpr track: checkout-status reported is_versioned=True (expected local-only / no Ghidra Server VC)",
                )
            if inner.get("success") is False and inner.get("error"):
                raise AssertionError(f"checkout-status error: {inner.get('error')}")

        elif name == "search-symbols" and loc in text:
            m = re.search(r"Showing \*\*(\d+)\*\* of \*\*(\d+)\*\*", text)
            if not m:
                raise AssertionError(f"search-symbols step missing result counts for {loc!r}")
            loc_totals.append(int(m.group(2)))

    if post_checkin_local_status < 3:
        raise AssertionError(
            f"expected checkout-status after each of 3 local check-ins, got {post_checkin_local_status} successful reads",
        )
    if not loc_totals or any(t < 3 for t in loc_totals):
        raise AssertionError(
            f"search-symbols for {loc!r} expected total>=3 each time, got totals={loc_totals!r}",
        )


# ---------------------------------------------------------------------------
# Step builders (strict /lfg semantics)
# ---------------------------------------------------------------------------


def _import_program_basename(program_path: str) -> str:
    p = (program_path or "").strip().replace("\\", "/").lstrip("/")
    return p.split("/")[-1] if p else "sort.exe"


def build_track_a_steps(
    *,
    run_id: str,
    repo: str,
    ghidra_host: str,
    ghidra_port: int,
    ghidra_user: str,
    ghidra_password: str,
    import_source: str,
    program_path: str,
    shared_fun_cycle1: str,
    shared_label_address: str,
    shared_fun_cycle3: str,
    exclusive_checkout: bool,
) -> list[dict[str, Any]]:
    sh = f"sh_{run_id}"
    steps: list[dict[str, Any]] = [
        {
            "name": "open",
            "arguments": {
                "shared": True,
                "path": repo,
                "serverHost": ghidra_host,
                "serverPort": ghidra_port,
                "serverUsername": ghidra_user,
                "serverPassword": ghidra_password,
            },
        },
        {"name": "list-project-files", "arguments": {}},
        {
            "name": "import-binary",
            "arguments": {
                "filePath": import_source.replace("\\", "/"),
                "programPath": _import_program_basename(program_path),
                "programName": _import_program_basename(program_path),
                "enableVersionControl": True,
                "analyzeAfterImport": True,
            },
        },
        {"name": "list-project-files", "arguments": {}},
        {
            "name": "checkout-program",
            "arguments": {"programPath": program_path, "exclusive": exclusive_checkout},
        },
        {
            "name": "manage-function",
            "arguments": {
                "mode": "rename",
                "programPath": program_path,
                "functionIdentifier": shared_fun_cycle1,
                "newName": f"{sh}_cycle1_fn",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{sh}_checkin_1"},
        },
        {
            "name": "checkout-program",
            "arguments": {"programPath": program_path, "exclusive": exclusive_checkout},
        },
        {
            "name": "create-label",
            "arguments": {
                "programPath": program_path,
                "address": shared_label_address,
                "labelName": f"{sh}_cycle2_lbl",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{sh}_checkin_2"},
        },
        {
            "name": "checkout-program",
            "arguments": {"programPath": program_path, "exclusive": exclusive_checkout},
        },
        {
            "name": "manage-function",
            "arguments": {
                "mode": "rename",
                "programPath": program_path,
                "functionIdentifier": shared_fun_cycle3,
                "newName": f"{sh}_cycle3_fn",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{sh}_checkin_3"},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": sh},
        },
        {"name": "sync-project", "arguments": {"mode": "pull", "dryRun": True}},
        {"name": "sync-project", "arguments": {"mode": "pull", "dryRun": False}},
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": sh},
        },
        {"name": "sync-project", "arguments": {"mode": "push", "dryRun": True}},
        {"name": "sync-project", "arguments": {"mode": "push", "dryRun": False}},
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": sh},
        },
    ]
    return steps


def build_track_b_steps(
    *,
    run_id: str,
    local_project_dir: str,
    import_source: str,
    program_path: str,
    local_fun_cycle1: str,
    local_label_address: str,
    local_fun_cycle3: str,
    analyze_after_import: bool,
) -> list[dict[str, Any]]:
    loc = f"loc_{run_id}"
    dir_json = local_project_dir.replace("\\", "/")
    steps: list[dict[str, Any]] = [
        {"name": "open", "arguments": {"path": dir_json}},
        {"name": "list-project-files", "arguments": {}},
        {
            "name": "import-binary",
            "arguments": {
                "filePath": import_source.replace("\\", "/"),
                "programPath": _import_program_basename(program_path),
                "programName": _import_program_basename(program_path),
                "enableVersionControl": False,
                "analyzeAfterImport": analyze_after_import,
            },
        },
        {"name": "list-project-files", "arguments": {}},
        {"name": "checkout-program", "arguments": {"programPath": program_path, "exclusive": False}},
        {
            "name": "manage-function",
            "arguments": {
                "mode": "rename",
                "programPath": program_path,
                "functionIdentifier": local_fun_cycle1,
                "newName": f"{loc}_cycle1_fn",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{loc}_checkin_1"},
        },
        {"name": "checkout-status", "arguments": {"programPath": program_path}},
        {"name": "checkout-program", "arguments": {"programPath": program_path, "exclusive": False}},
        {
            "name": "create-label",
            "arguments": {
                "programPath": program_path,
                "address": local_label_address,
                "labelName": f"{loc}_cycle2_lbl",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{loc}_checkin_2"},
        },
        {"name": "checkout-status", "arguments": {"programPath": program_path}},
        {"name": "checkout-program", "arguments": {"programPath": program_path, "exclusive": False}},
        {
            "name": "manage-function",
            "arguments": {
                "mode": "rename",
                "programPath": program_path,
                "functionIdentifier": local_fun_cycle3,
                "newName": f"{loc}_cycle3_fn",
            },
        },
        {
            "name": "checkin-program",
            "arguments": {"programPath": program_path, "comment": f"{loc}_checkin_3"},
        },
        {"name": "checkout-status", "arguments": {"programPath": program_path}},
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": loc},
        },
    ]
    return steps


def _shared_symbol_names(run_id: str) -> tuple[str, str, str]:
    sh = f"sh_{run_id}"
    return (f"{sh}_cycle1_fn", f"{sh}_cycle2_lbl", f"{sh}_cycle3_fn")


def _local_symbol_names(run_id: str) -> tuple[str, str, str]:
    loc = f"loc_{run_id}"
    return (f"{loc}_cycle1_fn", f"{loc}_cycle2_lbl", f"{loc}_cycle3_fn")


def build_persist_shared_steps(
    *,
    repo: str,
    ghidra_host: str,
    ghidra_port: int,
    ghidra_user: str,
    ghidra_password: str,
    program_path: str,
    run_id: str,
    exclusive_checkout: bool,
) -> list[dict[str, Any]]:
    """§7a proof only — run after §5 (Ghidra restart) and §6 (MCP restart).

    Three ``search-symbols`` steps (one query per check-in artifact). Prefer this over
    ``get-function`` for shared/versioned programs where ``get-function`` may be flaky.
    """
    c1, c2_lbl, c3 = _shared_symbol_names(run_id)
    return [
        {
            "name": "open",
            "arguments": {
                "shared": True,
                "path": repo,
                "serverHost": ghidra_host,
                "serverPort": ghidra_port,
                "serverUsername": ghidra_user,
                "serverPassword": ghidra_password,
            },
        },
        {
            "name": "checkout-program",
            "arguments": {"programPath": program_path, "exclusive": exclusive_checkout},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c1},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c2_lbl},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c3},
        },
    ]


def build_persist_local_steps(
    *,
    local_project_dir: str,
    program_path: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """§7b proof only — run in a **fresh** MCP session after another restart (not after §7a)."""
    c1, c2_lbl, c3 = _local_symbol_names(run_id)
    dir_json = local_project_dir.replace("\\", "/")
    return [
        {"name": "open", "arguments": {"path": dir_json}},
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c1},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c2_lbl},
        },
        {
            "name": "search-symbols",
            "arguments": {"programPath": program_path, "query": c3},
        },
    ]


def write_p6_proof_bundle(cfg: "LfgConfig", *, logger: logging.Logger = LOG) -> None:
    """Emit exact §7 tool-seq JSON for chat paste (P1/P6) plus symbol checklist."""
    log_dir = cfg.log_dir
    steps_7a = build_persist_shared_steps(
        repo=cfg.shared_repo,
        ghidra_host=cfg.ghidra_host,
        ghidra_port=cfg.ghidra_port,
        ghidra_user=cfg.ghidra_user,
        ghidra_password=cfg.ghidra_password,
        program_path=cfg.program_path,
        run_id=cfg.run_id,
        exclusive_checkout=cfg.exclusive_shared_checkout,
    )
    steps_7b = build_persist_local_steps(
        local_project_dir=str(cfg.local_project_dir),
        program_path=cfg.program_path,
        run_id=cfg.run_id,
    )
    c1s, c2s, c3s = _shared_symbol_names(cfg.run_id)
    c1l, c2l, c3l = _local_symbol_names(cfg.run_id)
    write_json(log_dir / "P6_exact_tool_seq_7a_shared_post_restart.json", steps_7a)
    write_json(log_dir / "P6_exact_tool_seq_7b_local_post_restart.json", steps_7b)
    combined = {
        "order": [
            "After §5 Ghidra restart and §6 MCP restart, run 7a:",
            "steps_7a_shared",
            "Restart MCP again (§0.2: no local open after shared open in same MCP process).",
            "Run 7b:",
            "steps_7b_local",
        ],
        "steps_7a_shared": steps_7a,
        "steps_7b_local": steps_7b,
        "symbols_track_a_checkins": {"cycle1_function": c1s, "cycle2_label": c2s, "cycle3_function": c3s},
        "symbols_track_b_checkins": {"cycle1_function": c1l, "cycle2_label": c2l, "cycle3_function": c3l},
    }
    write_json(log_dir / "P6_exact_post_restart_tool_seq_COMBINED.json", combined)
    logger.info(
        "Wrote P6 proof JSON: %s, %s, %s",
        log_dir / "P6_exact_tool_seq_7a_shared_post_restart.json",
        log_dir / "P6_exact_tool_seq_7b_local_post_restart.json",
        log_dir / "P6_exact_post_restart_tool_seq_COMBINED.json",
    )


# ---------------------------------------------------------------------------
# Ghidra Server lifecycle (optional, Windows-oriented)
# ---------------------------------------------------------------------------


def start_ghidra_server_console(
    ghidra_install_dir: Path, log_dir: Path, logger: logging.Logger = LOG
) -> subprocess.Popen[bytes]:
    """Spawn Ghidra Server; returns immediately (never use subprocess.run/wait on this console path).

    Stdout/stderr are piped to log files so the parent process is not blocked by ghidraSvr's
    interactive "Use Ctrl-C" console behavior.
    """
    sdir = ghidra_server_dir(ghidra_install_dir)
    bat = sdir / "ghidraSvr.bat"
    if not bat.is_file():
        raise FileNotFoundError(f"Missing {bat}")
    out = open(log_dir / "ghidra_server.stdout.log", "ab", buffering=0)  # noqa: SIM115
    err = open(log_dir / "ghidra_server.stderr.log", "ab", buffering=0)  # noqa: SIM115
    if sys.platform == "win32":
        cmd = ["cmd.exe", "/c", "ghidraSvr.bat", "console"]
    else:
        cmd = [str(sdir / "ghidraSvr"), "console"]
    logger.info("Starting Ghidra Server: cwd=%s cmd=%s", sdir, cmd)
    flags = 0
    if sys.platform == "win32":
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        # Avoid attaching a visible console to the pytest/orchestrator terminal (logs go to files).
        flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        cmd,
        cwd=str(sdir),
        stdout=out,
        stderr=err,
        creationflags=flags,
    )
    logger.info("Ghidra Server subprocess pid=%s", proc.pid)
    return proc


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


@dataclass
class LfgConfig:
    run_id: str
    repo_root: Path
    python_exe: Path
    ghidra_install_dir: Path
    ghidra_port: int
    ghidra_host: str
    ghidra_user: str
    ghidra_password: str
    shared_repo: str
    server_url: str
    mcp_host: str
    mcp_port: int
    mcp_project_path: Path
    import_source: Path
    program_path: str
    local_project_dir: Path
    shared_fun_cycle1: str
    shared_label_address: str
    shared_fun_cycle3: str
    local_fun_cycle1: str
    local_label_address: str
    local_fun_cycle3: str
    local_analyze_after_import: bool
    exclusive_shared_checkout: bool
    manage_mcp: bool
    manage_ghidra_server: bool
    skip_pytest: bool
    insecure_same_mcp_session_7b_after_7a: bool
    log_dir: Path
    # 1..8 = named phases in order; 9 = nested transport/session pytest subprocess.
    phase_from: int = 1
    phase_to: int = 9
    tool_seq_timeout_s: float = _DEFAULT_TOOL_SEQ_TIMEOUT
    mcp_health_timeout_s: float = _DEFAULT_MCP_HEALTH_TIMEOUT
    ghidra_tcp_timeout_s: float = _DEFAULT_GHIDRA_TCP_TIMEOUT
    nested_pytest_timeout_s: float = _DEFAULT_NESTED_PYTEST_TIMEOUT
    nested_pytest_inner_timeout_s: float = 30.0
    max_wall_seconds: float = 0.0
    wall_deadline_mono: float | None = None
    verbose: bool = False


def _checkpoint_wall(cfg: LfgConfig, where: str) -> None:
    if cfg.max_wall_seconds <= 0 or cfg.wall_deadline_mono is None:
        return
    if time.monotonic() >= cfg.wall_deadline_mono:
        raise RuntimeError(f"LFG wall-clock budget ({cfg.max_wall_seconds:.0f}s) exhausted at {where}")


def _capped_timeout(cfg: LfgConfig, limit: float, *, slack_s: float = 1.0) -> float:
    """``min(limit, wall_remaining - slack)`` when a wall deadline is active."""
    _checkpoint_wall(cfg, "before timed operation")
    if cfg.max_wall_seconds <= 0 or cfg.wall_deadline_mono is None:
        return limit
    rem = cfg.wall_deadline_mono - time.monotonic()
    if rem <= slack_s:
        raise RuntimeError(f"LFG wall-clock budget ({cfg.max_wall_seconds:.0f}s) exhausted")
    return min(limit, max(5.0, rem - slack_s))


def _phase_range_covers_tool_steps(a: int, b: int) -> bool:
    """True if [a,b] intersects phases 1..8 (everything before nested pytest)."""
    return a <= 8 and b >= 1 and a <= b


def _phase_slice_needs_listening_ghidra_server(a: int, b: int) -> bool:
    """Shared ``open`` runs in phase 1 (Track A) and phase 6 (§7a); repo server must accept TCP."""
    if a > b:
        return False
    return (a <= 1 <= b) or (a <= 6 <= b)


def _ghidra_kill_start_and_wait(cfg: LfgConfig, logger: logging.Logger, *, log_label: str) -> None:
    killed = kill_all_on_port(cfg.ghidra_port, logger=logger)
    logger.info("%s: cleared listeners on port %s: %s", log_label, cfg.ghidra_port, killed)
    time.sleep(4.0)
    ghidra_proc = start_ghidra_server_console(cfg.ghidra_install_dir, cfg.log_dir, logger=logger)
    write_json(cfg.log_dir / "ghidra_server_subprocess.json", {"pid": ghidra_proc.pid})
    tcp_to = _capped_timeout(cfg, cfg.ghidra_tcp_timeout_s)
    if not wait_tcp_port(cfg.ghidra_host, cfg.ghidra_port, timeout_s=tcp_to, logger=logger):
        raise RuntimeError(f"Ghidra Server did not accept TCP after {log_label}")
    logger.info("%s: Ghidra Server accepting TCP (child pid=%s)", log_label, ghidra_proc.pid)


def _ensure_ghidra_server_for_shared_slice(cfg: LfgConfig, logger: logging.Logger) -> None:
    """When the slice includes shared ``open``, guarantee repo TCP is up (shard 01 used to assume a manual server)."""
    if not cfg.manage_ghidra_server:
        return
    if not _phase_slice_needs_listening_ghidra_server(cfg.phase_from, cfg.phase_to):
        return
    probe_s = min(8.0, _capped_timeout(cfg, cfg.ghidra_tcp_timeout_s))
    if wait_tcp_port(cfg.ghidra_host, cfg.ghidra_port, timeout_s=probe_s, logger=logger):
        logger.info(
            "Ghidra Server already listening on %s:%s (shared phase in slice)",
            cfg.ghidra_host,
            cfg.ghidra_port,
        )
        return
    logger.info(
        "Ghidra Server not accepting TCP on %s:%s within %.1fs; starting (manage-ghidra-server)",
        cfg.ghidra_host,
        cfg.ghidra_port,
        probe_s,
    )
    _ghidra_kill_start_and_wait(cfg, logger, log_label="Ghidra bootstrap (pre shared tool-seq)")


def run_phases(cfg: LfgConfig, logger: logging.Logger) -> None:
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "run_id": cfg.run_id,
        "phase_from": cfg.phase_from,
        "phase_to": cfg.phase_to,
        "ghidra_port": cfg.ghidra_port,
        "server_url": cfg.server_url,
        "shared_repo": cfg.shared_repo,
        "program_path": cfg.program_path,
        "local_project_dir": str(cfg.local_project_dir),
        "manage_mcp": cfg.manage_mcp,
        "manage_ghidra_server": cfg.manage_ghidra_server,
        "insecure_same_mcp_session_7b_after_7a": cfg.insecure_same_mcp_session_7b_after_7a,
        "p6_proof_json": {
            "7a_file": "P6_exact_tool_seq_7a_shared_post_restart.json",
            "7b_file": "P6_exact_tool_seq_7b_local_post_restart.json",
            "combined_file": "P6_exact_post_restart_tool_seq_COMBINED.json",
        },
    }
    write_json(cfg.log_dir / "run_meta.json", meta)
    logger.info("Run metadata written to %s", cfg.log_dir / "run_meta.json")

    write_p6_proof_bundle(cfg, logger=logger)

    if cfg.max_wall_seconds > 0:
        cfg.wall_deadline_mono = time.monotonic() + cfg.max_wall_seconds
        logger.info("LFG wall-clock budget: %.0fs (deadline active)", cfg.max_wall_seconds)

    _checkpoint_wall(cfg, "before Ghidra bootstrap")
    _ensure_ghidra_server_for_shared_slice(cfg, logger)

    mcp: ManagedMcpServer | None = None
    need_managed_mcp = cfg.manage_mcp and _phase_range_covers_tool_steps(cfg.phase_from, cfg.phase_to)
    if cfg.manage_mcp:
        cfg.server_url = f"http://{cfg.mcp_host}:{cfg.mcp_port}"
    if need_managed_mcp:
        mcp = ManagedMcpServer(
            repo_root=cfg.repo_root,
            python_exe=cfg.python_exe,
            host=cfg.mcp_host,
            port=cfg.mcp_port,
            project_path=cfg.mcp_project_path,
            ghidra_install_dir=cfg.ghidra_install_dir,
            log_dir=cfg.log_dir,
            health_timeout_s=cfg.mcp_health_timeout_s,
        )
        _checkpoint_wall(cfg, "before MCP start")
        mcp.start(logger=logger, health_timeout_s=_capped_timeout(cfg, cfg.mcp_health_timeout_s))
    elif cfg.manage_mcp and cfg.phase_from <= 9 <= cfg.phase_to and not cfg.skip_pytest:
        logger.info(
            "Phase slice is pytest-only (includes phase 9): no MCP start; clearing port %s if occupied.",
            cfg.mcp_port,
        )
        kill_all_on_port(cfg.mcp_port, logger=logger)
        time.sleep(1.0)
    elif not cfg.manage_mcp:
        logger.info("Using existing MCP at %s (not started by this script)", cfg.server_url)
        if not wait_http_health(cfg.server_url, timeout_s=30.0, logger=logger):
            logger.warning("Health check failed for %s — tool-seq may still work if path differs", cfg.server_url)

    def tsurl() -> str:
        return cfg.server_url

    phases: list[tuple[str, Callable[[], None]]] = []

    phases.append(
        (
            "01_track_a_shared",
            lambda: run_tool_seq(
                repo_root=cfg.repo_root,
                python_exe=cfg.python_exe,
                server_url=tsurl(),
                steps=build_track_a_steps(
                    run_id=cfg.run_id,
                    repo=cfg.shared_repo,
                    ghidra_host=cfg.ghidra_host,
                    ghidra_port=cfg.ghidra_port,
                    ghidra_user=cfg.ghidra_user,
                    ghidra_password=cfg.ghidra_password,
                    import_source=str(cfg.import_source),
                    program_path=cfg.program_path,
                    shared_fun_cycle1=cfg.shared_fun_cycle1,
                    shared_label_address=cfg.shared_label_address,
                    shared_fun_cycle3=cfg.shared_fun_cycle3,
                    exclusive_checkout=cfg.exclusive_shared_checkout,
                ),
                log_dir=cfg.log_dir,
                phase_name="01_track_a_shared",
                logger=logger,
                timeout_s=_capped_timeout(cfg, cfg.tool_seq_timeout_s),
                verbose=cfg.verbose,
                lfg_strict_verify="track_a",
                lfg_run_id=cfg.run_id,
            ),
        ),
    )

    def restart_mcp() -> None:
        nonlocal mcp
        if not cfg.manage_mcp:
            logger.info("SKIP MCP restart (--manage-mcp not set); you must restart MCP manually before Track B.")
            return
        assert mcp is not None
        mcp.stop(logger=logger)
        time.sleep(2.0)
        _checkpoint_wall(cfg, "before MCP restart (track B)")
        mcp.start(logger=logger, health_timeout_s=_capped_timeout(cfg, cfg.mcp_health_timeout_s))

    phases.append(("02_mcp_restart_before_track_b", restart_mcp))

    phases.append(
        (
            "03_track_b_local",
            lambda: run_tool_seq(
                repo_root=cfg.repo_root,
                python_exe=cfg.python_exe,
                server_url=tsurl(),
                steps=build_track_b_steps(
                    run_id=cfg.run_id,
                    local_project_dir=str(cfg.local_project_dir),
                    import_source=str(cfg.import_source),
                    program_path=cfg.program_path,
                    local_fun_cycle1=cfg.local_fun_cycle1,
                    local_label_address=cfg.local_label_address,
                    local_fun_cycle3=cfg.local_fun_cycle3,
                    analyze_after_import=cfg.local_analyze_after_import,
                ),
                log_dir=cfg.log_dir,
                phase_name="03_track_b_local",
                logger=logger,
                timeout_s=_capped_timeout(cfg, cfg.tool_seq_timeout_s),
                verbose=cfg.verbose,
                lfg_strict_verify="track_b",
                lfg_run_id=cfg.run_id,
            ),
        ),
    )

    def restart_ghidra() -> None:
        if not cfg.manage_ghidra_server:
            logger.info("SKIP Ghidra Server restart (--manage-ghidra-server not set).")
            return
        logger.info("Restarting Ghidra Server on base port %s", cfg.ghidra_port)
        _ghidra_kill_start_and_wait(cfg, logger, log_label="Ghidra restart (phase 4)")

    phases.append(("04_restart_ghidra_server", restart_ghidra))

    def restart_mcp_after_ghidra() -> None:
        if not cfg.manage_mcp:
            logger.info("SKIP MCP restart after Ghidra (--manage-mcp not set).")
            return
        assert mcp is not None
        mcp.stop(logger=logger)
        time.sleep(2.0)
        _checkpoint_wall(cfg, "before MCP restart (after Ghidra)")
        mcp.start(logger=logger, health_timeout_s=_capped_timeout(cfg, cfg.mcp_health_timeout_s))

    phases.append(("05_mcp_restart_after_ghidra", restart_mcp_after_ghidra))

    def restart_mcp_before_p6_7b_local() -> None:
        """§0.2: local ``open`` must not follow shared ``open`` in the same MCP process."""
        if cfg.manage_mcp:
            assert mcp is not None
            logger.info(
                "MCP restart before §7b (required): shared proof 7a used shared open; "
                "fresh process before local open for 7b."
            )
            mcp.stop(logger=logger)
            time.sleep(2.0)
            _checkpoint_wall(cfg, "before MCP restart (§7b)")
            mcp.start(logger=logger, health_timeout_s=_capped_timeout(cfg, cfg.mcp_health_timeout_s))
            return
        if cfg.insecure_same_mcp_session_7b_after_7a:
            logger.warning(
                "SKIPPING MCP restart before §7b — %s",
                "strict P6 proof is INVALID per /lfg §0.2 (same session after shared open).",
            )
            return
        raise RuntimeError(
            "Strict /lfg: after §7a (shared open), you must restart agentdecompile-server before §7b "
            "(local open). Re-run with --manage-mcp, or pass "
            "--insecure-same-mcp-session-7b-after-7a only for non-proof debugging."
        )

    phases.append(
        (
            "06_P6_7a_shared_post_ghidra_and_mcp_restart",
            lambda: run_tool_seq(
                repo_root=cfg.repo_root,
                python_exe=cfg.python_exe,
                server_url=tsurl(),
                steps=build_persist_shared_steps(
                    repo=cfg.shared_repo,
                    ghidra_host=cfg.ghidra_host,
                    ghidra_port=cfg.ghidra_port,
                    ghidra_user=cfg.ghidra_user,
                    ghidra_password=cfg.ghidra_password,
                    program_path=cfg.program_path,
                    run_id=cfg.run_id,
                    exclusive_checkout=cfg.exclusive_shared_checkout,
                ),
                log_dir=cfg.log_dir,
                phase_name="06_P6_7a_shared_post_ghidra_and_mcp_restart",
                logger=logger,
                timeout_s=_capped_timeout(cfg, cfg.tool_seq_timeout_s),
                verbose=cfg.verbose,
            ),
        ),
    )

    phases.append(("07_mcp_restart_before_P6_7b_local_proof", restart_mcp_before_p6_7b_local))

    phases.append(
        (
            "08_P6_7b_local_after_fresh_mcp",
            lambda: run_tool_seq(
                repo_root=cfg.repo_root,
                python_exe=cfg.python_exe,
                server_url=tsurl(),
                steps=build_persist_local_steps(
                    local_project_dir=str(cfg.local_project_dir),
                    program_path=cfg.program_path,
                    run_id=cfg.run_id,
                ),
                log_dir=cfg.log_dir,
                phase_name="08_P6_7b_local_after_fresh_mcp",
                logger=logger,
                timeout_s=_capped_timeout(cfg, cfg.tool_seq_timeout_s),
                verbose=cfg.verbose,
            ),
        ),
    )

    for idx, (name, fn) in enumerate(phases, start=1):
        if idx < cfg.phase_from or idx > cfg.phase_to:
            continue
        logger.info("======== BEGIN %s (phase %d) ========", name, idx)
        _checkpoint_wall(cfg, f"phase {name}")
        try:
            fn()
        except Exception:
            logger.exception("Phase %s failed", name)
            raise
        logger.info("======== END %s ========", name)

    ran_nested = False
    if cfg.phase_from <= 9 <= cfg.phase_to:
        if cfg.skip_pytest:
            logger.info("Skipping nested pytest (--skip-pytest)")
        else:
            if cfg.manage_mcp and mcp is not None:
                mcp.stop(logger=logger)
                time.sleep(1.0)
            if pids_listening_tcp(cfg.mcp_port):
                if cfg.manage_mcp:
                    logger.warning(
                        "Port %s still in use after managed MCP stop — force-killing listeners (stale process).",
                        cfg.mcp_port,
                    )
                    kill_all_on_port(cfg.mcp_port, logger=logger)
                    time.sleep(2.0)
                else:
                    logger.warning(
                        "Port %s is in use before pytest; transport tests use random ports but stop any local MCP on %s if pytest fails.",
                        cfg.mcp_port,
                        cfg.mcp_port,
                    )
            _checkpoint_wall(cfg, "before nested pytest")
            run_pytest(
                repo_root=cfg.repo_root,
                python_exe=cfg.python_exe,
                log_dir=cfg.log_dir,
                logger=logger,
                timeout_s=_capped_timeout(cfg, cfg.nested_pytest_timeout_s),
                inner_test_timeout_s=cfg.nested_pytest_inner_timeout_s,
            )
            ran_nested = True

    if cfg.manage_mcp and mcp is not None and not ran_nested:
        mcp.stop(logger=logger)

    logger.info("All phases complete. Artifacts: %s", cfg.log_dir)


def setup_logging(log_dir: Path, verbose: bool) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "lfg_validation.driver.log"
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)
    root.handlers.clear()
    root.addHandler(fh)
    root.addHandler(ch)
    LOG.info("Driver log file: %s", log_file)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    root = repo_root_from_script()
    default_ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-id", required=True, help="Unique id embedded in sh_<id>_ and loc_<id>_ symbols (e.g. lfg20260321d).")
    p.add_argument("--repo-root", type=Path, default=root, help="Repository root (default: auto).")
    p.add_argument("--python-exe", type=Path, default=None, help="Python for CLI/server/pytest (default: .venv or sys.executable).")
    p.add_argument(
        "--ghidra-install-dir",
        type=Path,
        default=Path(default_ghidra) if default_ghidra else None,
        help="Ghidra install (default: GHIDRA_INSTALL_DIR).",
    )
    p.add_argument("--ghidra-host", default="127.0.0.1")
    p.add_argument("--ghidra-user", default=os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "ghidra"))
    p.add_argument("--ghidra-password", default=os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "admin"))
    p.add_argument("--shared-repo", default="agentrepo", help="Shared repository name for open(shared).")
    p.add_argument("--server-url", default="http://127.0.0.1:8080", help="MCP URL when not using --manage-mcp.")
    p.add_argument("--mcp-host", default="127.0.0.1")
    p.add_argument("--mcp-port", type=int, default=8080)
    p.add_argument(
        "--mcp-project-path",
        type=Path,
        default=Path(os.environ.get("AGENTDECOMPILE_TEMP_PROJECT", str(root / ".lfg_mcp_project"))),
        help="Ignored when --manage-mcp is set (run uses .lfg_run/<run>_<ts>/mcp_project_workspace). Otherwise: server --project-path.",
    )
    p.add_argument(
        "--import-source",
        type=Path,
        default=Path(r"C:\Windows\System32\sort.exe") if sys.platform == "win32" else Path("/bin/true"),
        help="Binary to import (default: Windows sort.exe).",
    )
    p.add_argument("--program-path", default="/sort.exe", help="Program path in project (e.g. /sort.exe).")
    p.add_argument(
        "--isolate-program-by-run-id",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Use /sort_<run_id>.exe (derived from --program-path basename) in the project so "
            "repeated LFG runs do not hit renamed symbols on an existing shared /sort.exe (default: true)."
        ),
    )
    p.add_argument(
        "--local-project-dir",
        type=Path,
        default=root / ".lfg_local_gpr_default",
        help="Directory for local .gpr (created if missing).",
    )
    p.add_argument("--shared-fun-cycle1", default="FUN_140001010", help="Source symbol for shared cycle 1 rename.")
    p.add_argument("--shared-label-address", default="140001640", help="Hex address (no 0x) for shared cycle 2 label.")
    p.add_argument("--shared-fun-cycle3", default="FUN_140001680", help="Source symbol for shared cycle 3 rename.")
    p.add_argument("--local-fun-cycle1", default="FUN_1400010f0")
    p.add_argument("--local-label-address", default="140001514")
    p.add_argument("--local-fun-cycle3", default="FUN_140001328")
    p.add_argument(
        "--local-analyze-after-import",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pass analyzeAfterImport to local import-binary (default: true).",
    )
    p.add_argument(
        "--exclusive-shared-checkout",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="exclusive flag for shared checkout-program (default: true).",
    )
    p.add_argument("--manage-mcp", action="store_true", help="Start/stop agentdecompile-server on --mcp-port.")
    p.add_argument(
        "--insecure-same-mcp-session-7b-after-7a",
        action="store_true",
        help=(
            "Allow §7b local proof in the same MCP process as §7a (violates strict /lfg §0.2; "
            "invalid for P6 — use only for debugging)."
        ),
    )
    p.add_argument(
        "--manage-ghidra-server",
        action="store_true",
        help="Kill listener on Ghidra base port and start ghidraSvr.bat console (Windows-oriented).",
    )
    p.add_argument("--skip-pytest", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument(
        "--prepare-local-dir",
        action="store_true",
        help="Delete and recreate --local-project-dir before Track B (fresh .gpr).",
    )
    p.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Fixed log/artifact directory (no timestamp suffix). Use for sharded --from-phase/--to-phase runs.",
    )
    p.add_argument(
        "--from-phase",
        type=int,
        default=1,
        metavar="N",
        help="First phase to run: 1..8 are tool-seq blocks in order; 9 = nested pytest (default 1).",
    )
    p.add_argument(
        "--to-phase",
        type=int,
        default=9,
        metavar="N",
        help="Last phase inclusive (default 9 = full stack including nested pytest).",
    )
    p.add_argument(
        "--max-wall-seconds",
        type=float,
        default=_DEFAULT_MAX_WALL,
        help=(
            "Hard wall-clock cap for the whole driver (0 disables). "
            "Env LFG_MAX_WALL_SECONDS (default 0 for CLI unless set)."
        ),
    )
    p.add_argument(
        "--tool-seq-timeout",
        type=float,
        default=_DEFAULT_TOOL_SEQ_TIMEOUT,
        help="Per tool-seq subprocess cap in seconds (default 180). Env LFG_TOOL_SEQ_TIMEOUT.",
    )
    p.add_argument(
        "--mcp-health-timeout",
        type=float,
        default=_DEFAULT_MCP_HEALTH_TIMEOUT,
        help="MCP /health wait cap in seconds. Env LFG_MCP_HEALTH_TIMEOUT.",
    )
    p.add_argument(
        "--ghidra-tcp-timeout",
        type=float,
        default=_DEFAULT_GHIDRA_TCP_TIMEOUT,
        help="Ghidra Server TCP listen wait after restart. Env LFG_GHIDRA_TCP_TIMEOUT.",
    )
    p.add_argument(
        "--nested-pytest-timeout",
        type=float,
        default=_DEFAULT_NESTED_PYTEST_TIMEOUT,
        help="Nested pytest subprocess cap in seconds. Env LFG_NESTED_PYTEST_TIMEOUT.",
    )
    p.add_argument(
        "--nested-pytest-inner-timeout",
        type=float,
        default=30.0,
        help="Per-test --timeout forwarded to nested pytest (default 30).",
    )
    return p.parse_args(list(argv) if argv is not None else None)


def run_lfg_cli(argv: Sequence[str] | None = None) -> int:
    """Run the full /lfg pipeline (optionally managing MCP and Ghidra Server).

    This is the single programmatic entry point used by ``python scripts/lfg_validation.py``
    and by ``tests/test_lfg_e2e.py``.

    Returns:
        ``0`` on success, ``1`` on validation failure, ``2`` on bad args / environment.
    """
    args = parse_args(argv)
    if args.ghidra_install_dir is None:
        LOG.error("Set GHIDRA_INSTALL_DIR or pass --ghidra-install-dir")
        return 2
    if args.from_phase < 1 or args.to_phase > 9 or args.from_phase > args.to_phase:
        LOG.error("Invalid phase range: need 1 <= --from-phase <= --to-phase <= 9")
        return 2
    ghidra_install = args.ghidra_install_dir.resolve()
    repo_root = args.repo_root.resolve()
    python_exe = (args.python_exe or resolve_python_exe(repo_root)).resolve()

    try:
        ghidra_port = read_ghidra_server_base_port(ghidra_install)
    except (OSError, ValueError) as exc:
        LOG.error("Failed to read Ghidra server port: %s", exc)
        return 2

    run_tag = args.run_id
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.artifacts_dir is not None:
        log_dir = args.artifacts_dir.resolve()
    else:
        log_dir = repo_root / ".lfg_run" / f"{run_tag}_{ts}"
    setup_logging(log_dir, args.verbose)

    if args.manage_mcp:
        # Default .lfg_mcp_project is often left locked after a crashed server; use a fresh tree per run.
        args.mcp_project_path = log_dir / "mcp_project_workspace"
        LOG.info("Managed MCP project path (isolated): %s", args.mcp_project_path)

    if args.prepare_local_dir:
        lp = args.local_project_dir.resolve()
        LOG.info("Removing local project dir for clean Track B: %s", lp)
        shutil.rmtree(lp, ignore_errors=True)
        lp.mkdir(parents=True, exist_ok=True)

    args.mcp_project_path.mkdir(parents=True, exist_ok=True)
    args.local_project_dir.mkdir(parents=True, exist_ok=True)

    eff_program = effective_program_path(
        args.program_path,
        args.run_id,
        isolate_by_run_id=args.isolate_program_by_run_id,
    )
    LOG.info("Program path in Ghidra project: %s", eff_program)

    cfg = LfgConfig(
        run_id=args.run_id,
        repo_root=repo_root,
        python_exe=python_exe,
        ghidra_install_dir=ghidra_install,
        ghidra_port=ghidra_port,
        ghidra_host=args.ghidra_host,
        ghidra_user=args.ghidra_user,
        ghidra_password=args.ghidra_password,
        shared_repo=args.shared_repo,
        server_url=args.server_url.rstrip("/"),
        mcp_host=args.mcp_host,
        mcp_port=args.mcp_port,
        mcp_project_path=args.mcp_project_path.resolve(),
        import_source=args.import_source.resolve(),
        program_path=eff_program,
        local_project_dir=args.local_project_dir.resolve(),
        shared_fun_cycle1=args.shared_fun_cycle1,
        shared_label_address=args.shared_label_address,
        shared_fun_cycle3=args.shared_fun_cycle3,
        local_fun_cycle1=args.local_fun_cycle1,
        local_label_address=args.local_label_address,
        local_fun_cycle3=args.local_fun_cycle3,
        local_analyze_after_import=args.local_analyze_after_import,
        exclusive_shared_checkout=args.exclusive_shared_checkout,
        manage_mcp=args.manage_mcp,
        manage_ghidra_server=args.manage_ghidra_server,
        skip_pytest=args.skip_pytest,
        insecure_same_mcp_session_7b_after_7a=args.insecure_same_mcp_session_7b_after_7a,
        log_dir=log_dir,
        phase_from=args.from_phase,
        phase_to=args.to_phase,
        tool_seq_timeout_s=args.tool_seq_timeout,
        mcp_health_timeout_s=args.mcp_health_timeout,
        ghidra_tcp_timeout_s=args.ghidra_tcp_timeout,
        nested_pytest_timeout_s=args.nested_pytest_timeout,
        nested_pytest_inner_timeout_s=args.nested_pytest_inner_timeout,
        max_wall_seconds=args.max_wall_seconds,
        verbose=args.verbose,
    )
    LOG.info("Ghidra base port from server.conf: %s", ghidra_port)
    LOG.info("Python: %s", python_exe)
    LOG.info("Artifacts directory: %s", cfg.log_dir)

    try:
        run_phases(cfg, LOG)
    except Exception as exc:
        LOG.error("LFG validation failed: %s", exc)
        return 1
    LOG.info("SUCCESS")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry (``python scripts/lfg_validation.py``). Delegates to :func:`run_lfg_cli`."""
    return run_lfg_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
