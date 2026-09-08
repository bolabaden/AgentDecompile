"""Build provenance-bearing evidence packets for recovery prompts.

Prompts must describe the function actually being recovered. Collection stays
separate from prose rendering so a missing tool or field is represented as
missing evidence instead of generic text.

The high-throughput source is an operator-supplied Ghidra knowledge SQLite.
AgentDecompile's CLI is preferred when a local project is configured because
it can collect function, reference, and call-graph views in one stateful
sequence. CLI failure is recorded in the packet and never aborts generation.
"""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

SCHEMA = "agentdecompile.recovery-prompt-evidence.v1"
AGENT_SCHEMA = "agentdecompile.agentdecompile-evidence.v7"
AGENTDECOMPILE_ROOT = pathlib.Path(__file__).resolve().parents[3]
KNOWLEDGE_DB = pathlib.Path(
    os.environ.get("AGENT_DECOMPILE_GHIDRA_KNOWLEDGE_DB")
    or "ghidra_knowledge.sqlite"
)
AGENT_CACHE = pathlib.Path("prompt_evidence") / "agentdecompile"
AGENT_LOCK = AGENT_CACHE / ".collect.lock"
AGENT_LOCAL_PROJECT = pathlib.Path("agentdecompile_projects")
AGENT_LOCAL_NAME = "agentdecompile"
_AGENT_REVISION: str | None = None


class _GhidraCliEnv:
    SSH_KEY = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_KEYFILE", "")
    SERVER_HOST = os.environ.get("AGENT_DECOMPILE_GHIDRA_HOST", "")
    SERVER_PORT = int(os.environ.get("AGENT_DECOMPILE_GHIDRA_PORT") or "0")
    REPO_NAME = os.environ.get("AGENT_DECOMPILE_GHIDRA_REPOSITORY", "")
    USER_ID = os.environ.get("AGENT_DECOMPILE_GHIDRA_USER", "")
    GHIDRA_INSTALL = os.environ.get("GHIDRA_INSTALL_DIR", "")
    JAVA_HOME = os.environ.get("JAVA_HOME", "")


ge = _GhidraCliEnv()


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def _decode_jsonish(value: Any) -> Any:
    if not isinstance(value, str) or not value.strip():
        return []
    try:
        return json.loads(value)
    except ValueError:
        return [part.strip() for part in value.split("|") if part.strip()]


def _function_row(con: sqlite3.Connection, binary_id: int, addr: int) -> dict[str, Any]:
    row = con.execute(
        """SELECT name, namespace, source, size, calling_convention, return_type,
                  param_count, param_types, stack_frame_size, stack_param_size,
                  stack_local_size, signature, n_instr, n_blocks, n_edges,
                  back_edges, cyclomatic, n_callees, indirect_calls, data_refs,
                  strings, consts, ext_calls, name_origin, source_file,
                  object_file, stabs_name, stabs_type
             FROM func WHERE binary_id=? AND addr=?""",
        (binary_id, addr),
    ).fetchone()
    return {key: _json_value(row[key]) for key in row.keys()} if row else {}


def _neighbors(con: sqlite3.Connection, binary_id: int, addr: int, limit: int = 12) -> dict[str, list[dict[str, Any]]]:
    def rows(direction: str) -> list[dict[str, Any]]:
        if direction == "callees":
            sql = """SELECT e.callee_addr AS addr, f.name, f.signature, f.source_file
                       FROM calledge e LEFT JOIN func f
                         ON f.binary_id=e.binary_id AND f.addr=e.callee_addr
                      WHERE e.binary_id=? AND e.caller_addr=?
                      ORDER BY e.callee_addr LIMIT ?"""
        else:
            sql = """SELECT e.caller_addr AS addr, f.name, f.signature, f.source_file
                       FROM calledge e LEFT JOIN func f
                         ON f.binary_id=e.binary_id AND f.addr=e.caller_addr
                      WHERE e.binary_id=? AND e.callee_addr=?
                      ORDER BY e.caller_addr LIMIT ?"""
        return [
            {
                "address": f"0x{int(row['addr']):08x}",
                "name": row["name"],
                "signature": row["signature"],
                "sourceFile": row["source_file"],
            }
            for row in con.execute(sql, (binary_id, addr, limit))
        ]
    return {"callers": rows("callers"), "callees": rows("callees")}


def _identities(con: sqlite3.Connection, logical_id: int | None, limit: int = 24) -> list[dict[str, Any]]:
    if logical_id is None:
        return []
    return [
        {
            "program": row["repo_path"],
            "address": f"0x{int(row['addr']):08x}",
            "name": row["name"],
            "signature": row["signature"],
            "confidence": round(float(row["confidence"]), 6),
            "method": row["method"],
        }
        for row in con.execute(
            """SELECT b.repo_path, i.addr, i.confidence, i.method,
                      f.name, f.signature
                 FROM identity i JOIN binary b ON b.id=i.binary_id
                 LEFT JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                WHERE i.logical_id=? ORDER BY i.confidence DESC, b.repo_path
                LIMIT ?""",
            (logical_id, limit),
        )
    ]


def _pyghidra_export(program: str, addr: int) -> dict[str, Any]:
    if not pathlib.Path(KNOWLEDGE_DB).exists():
        return {"status": "unavailable", "reason": "knowledge database missing"}
    try:
        con = sqlite3.connect(f"file:{KNOWLEDGE_DB}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        row = con.execute(
            """SELECT name, size, file_offset, calling_convention, signature,
                      length(decompiled) AS decompiled_bytes,
                      length(asm) AS asm_bytes, n_instructions, n_refs
                 FROM func_knowledge
                WHERE program=? AND entry_hex IN (?, ?)""",
            (program, f"{addr:08x}", f"{addr:016x}"),
        ).fetchone()
        con.close()
    except sqlite3.Error as exc:
        return {"status": "error", "reason": str(exc)}
    if row is None:
        return {"status": "not-found"}
    return {
        "status": "complete",
        "provider": "indexed-pyghidra-export",
        "source": str(KNOWLEDGE_DB),
        **{key: _json_value(row[key]) for key in row.keys()},
    }


def _cache_path(repo_path: str, addr: int) -> pathlib.Path:
    return AGENT_CACHE / repo_path.strip("/").replace("/", "__") / f"{addr:08x}.json"


def _agent_revision() -> str:
    global _AGENT_REVISION
    if _AGENT_REVISION is None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=AGENTDECOMPILE_ROOT,
                text=True, capture_output=True, timeout=10, check=False,
            )
            _AGENT_REVISION = result.stdout.strip() if result.returncode == 0 else "unknown"
        except (OSError, subprocess.TimeoutExpired):
            _AGENT_REVISION = "unknown"
    return _AGENT_REVISION


def _analysis_epoch() -> str:
    try:
        stat = pathlib.Path(KNOWLEDGE_DB).stat()
        return f"{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        return "knowledge-db-unavailable"


def _cached_agent_context(repo_path: str, addr: int,
                          binding: dict[str, Any]) -> dict[str, Any] | None:
    cache_path = _cache_path(repo_path, addr)
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            if cached.get("schema") != AGENT_SCHEMA:
                return None
            if cached.get("agentdecompileRevision") != _agent_revision():
                return None
            if cached.get("binding") != binding:
                return None
            collected = datetime.fromisoformat(cached.get("collectedAt", ""))
            ttl = os.environ.get("AGENT_DECOMPILE_CACHE_TTL") or os.environ.get(
                "KX_AGENTDECOMPILE_CACHE_TTL", "21600"
            )
            age = (datetime.now(timezone.utc) - collected).total_seconds()
            if age > float(ttl):
                return None
            cached["collection"] = "cached"
            cached["cache"] = str(cache_path)
            return cached
        except (OSError, ValueError, TypeError):
            pass
    return None


def _cache_agent_packet(repo_path: str, addr: int,
                        packet: dict[str, Any]) -> pathlib.Path | None:
    if packet.get("status") != "complete":
        return None
    cache_path = _cache_path(repo_path, addr)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            "w", dir=cache_path.parent, prefix=f".{cache_path.name}.",
            suffix=".tmp", delete=False) as fh:
        json.dump(packet, fh, indent=2, sort_keys=True)
        temp_path = pathlib.Path(fh.name)
    temp_path.replace(cache_path)
    return cache_path


def _cli_json(stdout: str) -> dict[str, Any] | None:
    """Extract JSON after AgentDecompile's PyGhidra startup messages."""
    decoder = json.JSONDecoder()
    for offset, char in enumerate(stdout):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(stdout[offset:])
        except ValueError:
            continue
        if isinstance(value, dict) and "steps" in value:
            return value
    return None


def _step_payload(step: dict[str, Any]) -> dict[str, Any]:
    if not step.get("success") or (step.get("result") or {}).get("isError"):
        return {}
    result = step.get("result") or {}
    for item in result.get("content") or []:
        if item.get("type") != "text":
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        try:
            payload = json.loads(text)
        except ValueError:
            continue
        if isinstance(payload, dict):
            payload.pop("projectContext", None)
            return payload
    return {}


def _compact_agent_packet(repo_path: str, addr: int,
                          outputs: dict[str, dict[str, Any]], mode: str,
                          binding: dict[str, Any] | None = None) -> dict[str, Any]:
    info = outputs.get("info") or {}
    calls = outputs.get("calls") or {}
    refs = outputs.get("references") or {}
    missing_views = [name for name in
                     ("info", "calls", "references")
                     if not outputs.get(name)]
    try:
        returned_addr = int(str(info.get("address", "")), 16)
    except ValueError:
        returned_addr = None
    address_matches = returned_addr == addr
    status = "complete" if not missing_views and address_matches else "partial"
    return {
        "schema": AGENT_SCHEMA,
        "status": status,
        "provider": "agentdecompile-cli",
        "mode": mode,
        "binding": binding or {},
        "programPath": repo_path,
        "address": f"0x{addr:08x}",
        "addressVerified": address_matches,
        "missingViews": missing_views,
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "collection": "live",
        "agentdecompileRevision": _agent_revision(),
        "command": "agentdecompile-cli --local ... tool-seq-file <generated>",
        "tools": ["get-functions:info", "get-functions:calls",
                  "get-references:both"],
        "function": info,
        "calls": {
            "callers": calls.get("callers", [])[:24],
            "callees": calls.get("callees", [])[:24],
            "callerCount": calls.get("callerCount", len(calls.get("callers", []))),
            "calleeCount": calls.get("calleeCount", len(calls.get("callees", []))),
        },
        "references": {
            "incomingRowsReturned": len(refs.get("referencesTo", [])),
            "outgoingRowsReturned": len(refs.get("referencesFrom", [])),
            "countsAreLowerBounds": True,
            "to": refs.get("referencesTo", [])[:24],
            "from": refs.get("referencesFrom", [])[:24],
        },
    }


def _agent_steps(program_path: str, addresses: list[int],
                 shared: bool) -> tuple[list[dict[str, Any]], list[tuple[int, str]]]:
    steps: list[dict[str, Any]] = []
    labels: list[tuple[int, str]] = []
    if shared:
        steps.append({"name": "open", "arguments": {
            "path": ge.REPO_NAME, "shared": True,
            "serverHost": ge.SERVER_HOST, "serverPort": ge.SERVER_PORT,
            "serverUsername": ge.USER_ID, "repositoryName": ge.REPO_NAME,
            "format": "json",
        }})
    for addr in addresses:
        ident = f"0x{addr:08x}"
        query_steps = [
            ("info", "get-functions", {"programPath": program_path, "identifier": ident, "view": "info", "format": "json"}),
            ("calls", "get-functions", {"programPath": program_path, "identifier": ident, "view": "calls", "format": "json"}),
            ("references", "get-references", {"programPath": program_path, "target": ident, "mode": "both", "includeRefContext": True, "includeDataRefs": True, "format": "json"}),
        ]
        for label, name, arguments in query_steps:
            steps.append({"name": name, "arguments": arguments})
            labels.append((addr, label))
    return steps, labels


def _agentdecompile_cli_argv() -> list[str] | None:
    """Resolve agentdecompile-cli without requiring ``uv`` on PATH.

    Watchdog and shardloop environments often lack ``~/.local/bin``. The
    workspace venv script is the same interpreter the dashboard already uses.
    """
    venv_cli = AGENTDECOMPILE_ROOT / ".venv" / "bin" / "agentdecompile-cli"
    if venv_cli.is_file() and os.access(venv_cli, os.X_OK):
        return [str(venv_cli)]
    found = shutil.which("agentdecompile-cli")
    if found:
        return [found]
    uv = shutil.which("uv")
    if uv:
        return [uv, "run", "--project", str(AGENTDECOMPILE_ROOT),
                "agentdecompile-cli"]
    return None


def collect_agentdecompile_batch(repo_path: str, addresses: list[int]) -> dict[int, dict[str, Any]]:
    """Collect live CLI evidence once for a whole generated prompt batch."""
    unique = list(dict.fromkeys(int(addr) for addr in addresses))
    raw_map = os.environ.get("AGENT_DECOMPILE_PROJECTS") or os.environ.get(
        "KX_AGENTDECOMPILE_PROJECTS", ""
    )
    shared_setting = os.environ.get("AGENT_DECOMPILE_SHARED") or os.environ.get(
        "KX_AGENTDECOMPILE_SHARED"
    )
    shared = (shared_setting not in (None, "", "0") and pathlib.Path(ge.SSH_KEY).is_file())
    if not raw_map and not shared:
        unavailable = {"status": "not-configured", "provider": "agentdecompile-cli"}
        return {addr: unavailable.copy() for addr in unique}
    binding: dict[str, Any] = {}
    if raw_map:
        try:
            binding = json.loads(raw_map).get(repo_path) or {}
        except (ValueError, AttributeError):
            invalid = {"status": "invalid-config", "provider": "agentdecompile-cli"}
            return {addr: invalid.copy() for addr in unique}
    project_path = pathlib.Path(str(binding.get("projectPath") or AGENT_LOCAL_PROJECT))
    project_name = str(binding.get("projectName") or AGENT_LOCAL_NAME)
    program_path = str(binding.get("programPath") or repo_path)
    if not project_path.exists() or not project_name or not program_path:
        invalid = {"status": "invalid-binding", "provider": "agentdecompile-cli"}
        return {addr: invalid.copy() for addr in unique}
    binding_fingerprint = {
        "mode": "shared-repository" if shared else "local-project",
        "programPath": program_path,
        "projectPath": (f"ghidra://{ge.SERVER_HOST}:{ge.SERVER_PORT}/{ge.REPO_NAME}"
                        if shared else str(project_path.resolve())),
        "projectName": ge.REPO_NAME if shared else project_name,
        "analysisEpoch": _analysis_epoch(),
    }
    found = {addr: cached for addr in unique
             if (cached := _cached_agent_context(
                 repo_path, addr, binding_fingerprint)) is not None}
    missing = [addr for addr in unique if addr not in found]
    if not missing:
        return found

    steps, labels = _agent_steps(program_path, missing, shared)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(steps, fh)
        sequence_path = pathlib.Path(fh.name)
    cli = _agentdecompile_cli_argv()
    if cli is None:
        missing_cli = {
            "status": "error",
            "provider": "agentdecompile-cli",
            "reason": "agentdecompile-cli not found (venv missing and uv not on PATH)",
        }
        sequence_path.unlink(missing_ok=True)
        found.update({addr: missing_cli.copy() for addr in missing})
        return found
    command = [
        *cli, "--local", "--local-project-path", str(project_path),
        "--local-project-name", project_name, "-f", "json",
        "tool-seq-file", str(sequence_path), "--continue-on-error",
    ]
    env = os.environ.copy()
    if ge.GHIDRA_INSTALL:
        env.setdefault("GHIDRA_INSTALL_DIR", ge.GHIDRA_INSTALL)
    if ge.JAVA_HOME:
        env.setdefault("JAVA_HOME", ge.JAVA_HOME)
    if shared and ge.SSH_KEY:
        env.setdefault("AGENT_DECOMPILE_GHIDRA_SERVER_KEYFILE", ge.SSH_KEY)
    AGENT_CACHE.mkdir(parents=True, exist_ok=True)
    lock_fh = AGENT_LOCK.open("a+")
    wait_limit = float(os.environ.get("AGENT_DECOMPILE_LOCK_WAIT") or
                       os.environ.get("KX_AGENTDECOMPILE_LOCK_WAIT", "900"))
    deadline = time.monotonic() + wait_limit
    while True:
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                busy = {"status": "busy", "provider": "agentdecompile-cli",
                        "reason": "another prompt batch is collecting live evidence"}
                found.update({addr: busy.copy() for addr in missing})
                sequence_path.unlink(missing_ok=True)
                lock_fh.close()
                return found
            time.sleep(0.5)
    refreshed = {addr: cached for addr in missing
                 if (cached := _cached_agent_context(
                     repo_path, addr, binding_fingerprint)) is not None}
    found.update(refreshed)
    if len(refreshed) == len(missing):
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()
        sequence_path.unlink(missing_ok=True)
        return found
    if refreshed:
        missing = [addr for addr in missing if addr not in refreshed]
        steps, labels = _agent_steps(program_path, missing, shared)
        sequence_path.unlink(missing_ok=True)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(steps, fh)
            sequence_path = pathlib.Path(fh.name)
        command[-2] = str(sequence_path)
    try:
        try:
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=300, env=env, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            error = {"status": "error", "provider": "agentdecompile-cli",
                     "reason": str(exc)}
            found.update({addr: error.copy() for addr in missing})
            return found
        payload = _cli_json(result.stdout)
        if payload is None:
            error = {"status": "error", "provider": "agentdecompile-cli",
                     "reason": (result.stderr or result.stdout)[-2000:]}
            found.update({addr: error.copy() for addr in missing})
            return found
        result_steps = list(payload.get("steps") or [])
        if shared and result_steps:
            open_step = result_steps.pop(0)
            if (not open_step.get("success")
                    or (open_step.get("result") or {}).get("isError")):
                error = {"status": "error", "provider": "agentdecompile-cli",
                         "reason": "failed to open shared Ghidra repository"}
                found.update({addr: error.copy() for addr in missing})
                return found
        grouped: dict[int, dict[str, dict[str, Any]]] = {addr: {} for addr in missing}
        for (addr, label), step in zip(labels, result_steps):
            grouped[addr][label] = _step_payload(step)
        for addr in missing:
            packet = _compact_agent_packet(
                repo_path, addr, grouped[addr],
                "shared-repository" if shared else "local-project",
                binding_fingerprint,
            )
            if cache_path := _cache_agent_packet(repo_path, addr, packet):
                packet["cache"] = str(cache_path)
            found[addr] = packet
        return found
    finally:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()
        sequence_path.unlink(missing_ok=True)


def collect(con: sqlite3.Connection, *, binary_id: int, repo_path: str,
            fn: dict[str, Any], agent_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a JSON-serializable, exact-target evidence packet."""
    addr = int(fn["addr"])
    program = repo_path.rsplit("/", 1)[-1]
    row = _function_row(con, binary_id, addr)
    packet = {
        "schema": SCHEMA,
        "target": {
            "repositoryPath": repo_path,
            "program": program,
            "address": f"0x{addr:08x}",
            "logicalId": fn.get("logical_id"),
            "canonicalName": fn.get("canonical_name"),
        },
        "function": row,
        "relationships": _neighbors(con, binary_id, addr),
        "crossBuildIdentity": _identities(con, fn.get("logical_id")),
        "pyghidra": _pyghidra_export(program, addr),
        "agentdecompile": (agent_context if agent_context is not None else
                           {"status": "not-prefetched",
                            "provider": "agentdecompile-cli"}),
        "claimBoundary": (
            "All facts above are evidence, not proof of recovered source. "
            "Only readable high-level C/C++ that independently compiles and "
            "matches the target may pass recovery. Assembly wrappers, emitted "
            "bytes, naked functions, and inline assembly are forbidden."
        ),
    }
    for key in ("strings", "consts", "ext_calls", "data_refs", "param_types"):
        if key in packet["function"]:
            packet["function"][key] = _decode_jsonish(packet["function"][key])
    return packet
