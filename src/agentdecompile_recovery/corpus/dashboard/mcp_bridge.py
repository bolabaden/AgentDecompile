"""Talk to the live AgentDecompile MCP HTTP server from the dashboard process.

The catalog used to spawn ``agentdecompile-cli`` for every MCP verb. That path
imports the USB tree and wedges. Listing functions and opening a program must
stay in-process over HTTP.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

CONTEXT_LOCK = threading.RLock()
_LOCK = threading.RLock()
_SESSION_ID = ""
_INITIALIZED = False
_REQ_ID = 0
_OPENED: dict[str, str] = {}
_ACTIVE_LOCATOR = ""


def mcp_url() -> str:
    from agentdecompile_recovery.corpus.dashboard.actions.catalog import env_defaults

    raw = env_defaults()["mcp_url"].strip()
    if raw.endswith("/"):
        raw = raw[:-1]
    return raw


def _resolve_open_program(wanted: str) -> tuple[str, list[str]]:
    """Map a UI program name to a path that is actually open in this MCP session."""
    hit = call_tool("list-project-files", {"responseFormat": "json"}, timeout=15.0)
    files: list[dict[str, Any]] = []
    parsed = hit.get("parsed")
    if isinstance(parsed, dict):
        raw = parsed.get("files") or parsed.get("results") or []
        if isinstance(raw, list):
            files = [row for row in raw if isinstance(row, dict)]
        ctx = parsed.get("projectContext") if isinstance(parsed.get("projectContext"), dict) else {}
        for extra in ctx.get("openPrograms") or []:
            if isinstance(extra, str) and extra:
                normalized = extra.replace("\\", "/").strip("/")
                covered = any(str(row.get("path") or "").replace("\\", "/").strip("/") == normalized for row in files)
                # Session caches may expose both a folder path and its short
                # alias. An alias is not another root-level program.
                if "/" not in extra.replace("\\", "/"):
                    covered = covered or any(str(row.get("name") or row.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1] == normalized for row in files)
                if not covered:
                    files.append({"name": normalized.rsplit("/", 1)[-1], "path": extra})
    names: list[str] = []
    seen: set[str] = set()
    for row in files:
        path = str(row.get("path") or "")
        name = str(row.get("name") or path.rsplit("/", 1)[-1] or "")
        for token in (path, name, path.lstrip("/"), name.lstrip("/")):
            if token and token not in seen:
                seen.add(token)
                names.append(token)
    needle = (wanted or "").strip().replace("\\", "/").strip("/")
    if not needle:
        return "", names
    qualified = "/" in (wanted or "").strip().replace("\\", "/")
    matches = {}
    for row in files:
        path = str(row.get("path") or row.get("name") or "").replace("\\", "/")
        name = str(row.get("name") or path.rsplit("/", 1)[-1])
        canonical = path.strip("/")
        if not canonical:
            continue
        matched = canonical.casefold() == needle.casefold()
        if not qualified:
            matched = matched or name.casefold() == needle.casefold() or canonical.rsplit("/", 1)[-1].casefold() == needle.casefold()
        if matched:
            matches[canonical] = path
    if len(matches) == 1:
        return next(iter(matches.values())), names
    return "", names



def reset_session() -> None:
    global _SESSION_ID, _INITIALIZED, _ACTIVE_LOCATOR
    with _LOCK:
        _SESSION_ID = ""
        _INITIALIZED = False
        _OPENED.clear()
        _ACTIVE_LOCATOR = ""


def call_tool(name: str, arguments: dict[str, Any] | None = None, *, timeout: float = 90.0) -> dict[str, Any]:
    global _ACTIVE_LOCATOR
    with CONTEXT_LOCK:
        result = _call_tool(name, arguments, timeout=timeout)
        if name == "import-binary" and result.get("ok") and isinstance(result.get("parsed"), dict):
            from .workbench import record_import_bindings
            try:
                record_import_bindings(result["parsed"])
            except Exception as exc:
                # The import already succeeded. Do not invite duplicate imports
                # merely because its navigation metadata could not be saved.
                result["parsed"]["workbenchBindingError"] = str(exc)
        if name in {"open", "import-binary", "connect-shared-project", "close"}:
            _ACTIVE_LOCATOR = str((arguments or {}).get("path") or "") if result.get("ok") and name == "open" else ""
        return result


def ensure_project(locator: str) -> dict[str, Any]:
    """Reuse the project opened by this session instead of reacquiring its file lock."""
    with CONTEXT_LOCK:
        if locator and locator == _ACTIVE_LOCATOR:
            return {"ok": True, "reused": True}
        return call_tool("open", {"path": locator, "analyzeAfterImport": False, "openAllPrograms": False}, timeout=180.0)


def _call_tool(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    timeout: float = 90.0,
) -> dict[str, Any]:
    """JSON-RPC ``tools/call``. Returns ``{ok, isError, text, parsed, raw}``."""
    try:
        _ensure_initialized(timeout=min(20.0, timeout))
        result = _rpc(
            "tools/call",
            {"name": name, "arguments": dict(arguments or {})},
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 — surface MCP errors to the UI
        return {"ok": False, "isError": True, "error": str(exc), "text": "", "parsed": None}
    content = result.get("content") if isinstance(result, dict) else None
    text = _content_text(content if isinstance(content, list) else [])
    parsed = _maybe_json(text)
    payload_fail = isinstance(parsed, dict) and parsed.get("success") is False
    is_error = bool(isinstance(result, dict) and result.get("isError")) or payload_fail
    err = ""
    if payload_fail:
        err = str(parsed.get("error") or text)
    elif is_error:
        err = text
    return {
        "ok": not is_error,
        "isError": is_error,
        "text": text,
        "parsed": parsed,
        "raw": result,
        "error": err,
    }


def list_functions(
    program: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int | str = "all",
    program_path: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.dashboard.common import page_window

    wanted = (program_path or program or "").strip()
    path, available = _resolve_open_program(wanted)
    start, cap = page_window(offset, limit)
    chunk = cap if cap is not None else 200
    args: dict[str, Any] = {
        "offset": start,
        "limit": chunk,
        "responseFormat": "json",
    }
    if path:
        args["program_path"] = path
    elif wanted:
        avail = ", ".join(available[:12]) if available else "none"
        return {
            "ok": True,
            "program": program,
            "program_path": wanted,
            "q": q,
            "offset": start,
            "limit": "all" if cap is None else cap,
            "total": 0,
            "results": [],
            "hasMore": False,
            "source": "ghidra-mcp",
            "next": "open-program",
            "openPrograms": available,
            "error": (
                f"{wanted} is not open in this Ghidra session "
                f"(open: {avail}). File → Open the project that contains it, "
                "or start the Ghidra server if this is a shared repository."
            ),
        }
    if q:
        args["query"] = q
        args["search_string"] = q
    collected: list[dict[str, Any]] = []
    cursor = start
    last_error = ""
    while True:
        args["offset"] = cursor
        args["limit"] = chunk
        hit = call_tool("list-functions", args, timeout=15.0)
        page = _functions_from_payload(hit.get("parsed"), hit.get("text") or "")
        if page:
            collected.extend(page)
            cursor += len(page)
            if cap is not None or len(page) < chunk:
                break
            continue
        last_error = hit.get("error") or hit.get("text") or "Ghidra has no functions for this program yet."
        break
    if collected:
        return {
            "ok": True,
            "program": program,
            "program_path": path,
            "q": q,
            "offset": start,
            "limit": "all" if cap is None else cap,
            "total": start + len(collected),
            "results": collected,
            "hasMore": cap is not None and len(collected) >= cap,
            "source": "ghidra-mcp",
        }
    next_step = "open-program" if _needs_open(last_error) else "analyze-program"
    return {
        "ok": True,
        "program": program,
        "program_path": path,
        "q": q,
        "offset": start,
        "limit": "all" if cap is None else cap,
        "total": 0,
        "results": [],
        "hasMore": False,
        "source": "ghidra-mcp",
        "next": next_step,
        "error": (last_error or "Ghidra has no functions for this program yet.")[:800],
    }


def ensure_program(locator: str, program: str = "", inspected: dict[str, Any] | None = None) -> dict[str, Any]:
    """Open the Ghidra project (once) and make ``program`` the current program."""
    from agentdecompile_recovery.corpus.ghidra_project import (
        classify_locator,
        ghidra_connect_args,
        ghidra_program_path,
        inspect_locator,
        shared_defaults,
    )

    loc = (locator or "").strip()
    name = (program or "").strip()
    info = dict(inspected or {})
    if not info.get("ok") and loc:
        info = inspect_locator(loc) if loc else classify_locator(loc)
    kind = str(info.get("kind") or "")
    if loc and name:
        from agentdecompile_recovery.corpus.dashboard.workbench import _list_functions_from_store

        stored = _list_functions_from_store(loc, name)
        if stored.get("results") or stored.get("opened"):
            stored["ensured"] = True
            stored["steps"] = [{"tool": "ghidra-store", "ok": True, "error": stored.get("error")}]
            if stored.get("results"):
                key = f"{loc}\0{stored.get('program_path') or name}"
                with _LOCK:
                    _OPENED[key] = "ready"
            return stored
        if kind == "shared-fs":
            return {
                "ok": True,
                "ensured": True,
                "program": name,
                "locator": loc,
                "results": [],
                "total": 0,
                "source": "ghidra-store",
                "next": "",
                "steps": [{"tool": "ghidra-store", "ok": False, "error": f"{name} is not in {loc}"}],
                "error": (
                    f"{name} is not a program in the filesystem store at {loc}. "
                    "No Ghidra server is required; pick a name from Explorer."
                ),
            }
    path = ghidra_program_path(info, name) if name else ""
    resolved, _available = _resolve_open_program(name)
    if resolved:
        path = resolved
    key = f"{loc}\0{path or name}"
    with _LOCK:
        cached = _OPENED.get(key)
    if cached == "ready":
        listed = list_functions(name, program_path=path or name)
        listed["ensured"] = True
        listed["cached"] = True
        return listed

    steps: list[dict[str, Any]] = []
    open_args = ghidra_connect_args(info)
    if not open_args and loc and kind not in {"shared-fs", ""}:
        open_args = {"path": loc, "analyze_after_import": False, "open_all_programs": False}
    _apply_server_auth(open_args)
    if kind == "binary" and loc:
        opened = call_tool(
            "import-binary",
            {
                "path": loc,
                "program_name": name or "",
                "analyze_after_import": False,
            },
            timeout=180.0,
        )
        steps.append({"tool": "import-binary", "ok": opened.get("ok"), "error": opened.get("error")})
    elif open_args:
        opened = call_tool("open", open_args, timeout=180.0)
        steps.append({"tool": "open", "ok": opened.get("ok"), "error": opened.get("error")})
        if not opened.get("ok") and open_args.get("shared"):
            defaults = shared_defaults()
            url = (
                f"ghidra://{defaults.get('host') or '127.0.0.1'}:"
                f"{int(defaults.get('port') or 13100)}/"
                f"{open_args.get('repository_name') or defaults.get('repository') or ''}"
            )
            retry = call_tool(
                "open",
                {"path": url, "analyze_after_import": False, "open_all_programs": False},
                timeout=180.0,
            )
            steps.append({"tool": "open-url", "ok": retry.get("ok"), "error": retry.get("error")})
            opened = retry

    if path or name:
        checked = call_tool(
            "checkout-program",
            {"program_path": path or name, "exclusive": False, "responseFormat": "json"},
            timeout=90.0,
        )
        steps.append({"tool": "checkout-program", "ok": checked.get("ok"), "error": checked.get("error")})

    listed = list_functions(name, program_path=path or name)
    listed["ensured"] = True
    listed["steps"] = steps
    listed["program_path"] = path or name
    if listed.get("results"):
        with _LOCK:
            _OPENED[key] = "ready"
    return listed


def _apply_server_auth(args: dict[str, Any]) -> None:
    user = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or "").strip()
    password = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or "").strip()
    if user:
        args.setdefault("server_username", user)
    if password:
        args.setdefault("server_password", password)


def _ensure_initialized(*, timeout: float) -> None:
    global _INITIALIZED
    with _LOCK:
        if _INITIALIZED:
            return
        _rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "agentdecompile-workbench", "version": "1.0.0"},
            },
            timeout=timeout,
            notification_after="notifications/initialized",
        )
        _INITIALIZED = True


def _rpc(
    method: str,
    params: dict[str, Any],
    *,
    timeout: float,
    notification_after: str = "",
) -> dict[str, Any]:
    global _REQ_ID, _SESSION_ID
    _REQ_ID += 1
    payload = {"jsonrpc": "2.0", "id": _REQ_ID, "method": method, "params": params}
    body, headers = _post(payload, timeout=timeout)
    if notification_after:
        note = {"jsonrpc": "2.0", "method": notification_after}
        try:
            _post(note, timeout=min(10.0, timeout))
        except Exception:
            pass
    if body.get("error"):
        raise RuntimeError(str(body["error"]))
    result = body.get("result")
    return result if isinstance(result, dict) else {"value": result}


def _post(payload: dict[str, Any], *, timeout: float) -> tuple[dict[str, Any], dict[str, str]]:
    global _SESSION_ID
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    if _SESSION_ID:
        headers["mcp-session-id"] = _SESSION_ID
    req = urllib.request.Request(mcp_url(), data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            sid = (resp.headers.get("mcp-session-id") or "").strip()
            if sid:
                _SESSION_ID = sid
            parsed = _decode_rpc(raw, hdrs.get("content-type") or "")
            return parsed, hdrs
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp else b""
        sid = (exc.headers.get("mcp-session-id") if exc.headers else "") or ""
        if sid:
            _SESSION_ID = sid
        text = raw.decode("utf-8", errors="replace")
        if exc.code in {400, 404} and "session" in text.lower():
            reset_session()
        raise RuntimeError(f"MCP HTTP {exc.code}: {text[:400]}") from exc


def _decode_rpc(raw: bytes, content_type: str) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    if "event-stream" in content_type or text.startswith(("event:", "data:")):
        last: dict[str, Any] | None = None
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            chunk = line[5:].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                last = json.loads(chunk)
            except json.JSONDecodeError:
                continue
        if last is None:
            raise RuntimeError("MCP event stream had no JSON payload")
        return last
    if not text.strip():
        return {}
    return json.loads(text)


def _content_text(content: list[Any]) -> str:
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("text"):
            parts.append(str(item["text"]))
        elif isinstance(item, str):
            parts.append(item)
    return "\n".join(parts).strip()


def _maybe_json(text: str) -> Any:
    blob = (text or "").strip()
    if not blob:
        return None
    if blob.startswith("{") or blob.startswith("["):
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            return None
    start = blob.find("{")
    end = blob.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(blob[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _functions_from_payload(parsed: Any, text: str) -> list[dict[str, Any]]:
    rows: list[Any] = []
    if isinstance(parsed, list):
        rows = parsed
    elif isinstance(parsed, dict):
        for key in ("results", "functions", "items", "data"):
            val = parsed.get(key)
            if isinstance(val, list):
                rows = val
                break
        if not rows and isinstance(parsed.get("function"), dict):
            rows = [parsed["function"]]
    out: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        addr = (
            item.get("addr")
            or item.get("address")
            or item.get("entry")
            or item.get("entryPoint")
            or ""
        )
        name = item.get("name") or item.get("function") or item.get("symbol") or ""
        if not addr and not name:
            continue
        size = item.get("size") or item.get("bodySize") or 0
        try:
            size_i = int(size or 0)
        except (TypeError, ValueError):
            size_i = 0
        out.append(
            {
                "addr": str(addr),
                "address": _int_addr(addr),
                "name": str(name or addr),
                "size": size_i,
                "logicalId": item.get("logicalId") or item.get("logical_id"),
                "decomp": item.get("decomp") or "none",
                "validate": item.get("validate") or "none",
                "source": "ghidra-mcp",
            }
        )
    if out:
        return out
    return _functions_from_markdown(text)


def _functions_from_markdown(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "Address" in stripped or set(stripped) <= set("|-: "):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 2:
            continue
        addr = ""
        name = ""
        for cell in cells:
            if cell.lower().startswith("0x") or (len(cell) >= 6 and all(ch in "0123456789abcdefABCDEFx" for ch in cell)):
                addr = cell
            elif cell and cell not in {"FUN", "ext", "thunk"} and not name:
                name = cell
        if addr or name:
            rows.append(
                {
                    "addr": addr or name,
                    "address": _int_addr(addr),
                    "name": name or addr,
                    "size": 0,
                    "logicalId": None,
                    "decomp": "none",
                    "validate": "none",
                    "source": "ghidra-mcp",
                }
            )
    return rows


def _int_addr(raw: Any) -> int | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def _needs_open(err: str) -> bool:
    low = (err or "").lower()
    return any(
        token in low
        for token in (
            "no program",
            "not loaded",
            "not open",
            "open a",
            "import-binary",
            "checkout",
            "no project",
        )
    )


def mcp_host_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or "127.0.0.1"
