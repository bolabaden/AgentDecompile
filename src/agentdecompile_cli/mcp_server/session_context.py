"""Session-scoped runtime state for MCP requests.

This module provides a lightweight in-memory SessionContext map keyed by MCP
session ID. It is intentionally process-local and suitable for a single MCP
server instance.

Session lifecycle:
    - Active sessions are tracked in ``SessionContextStore._sessions``.
    - When the SDK evicts a session (crash/client disconnect), the middleware
      moves it to a **grace period** holding area instead of destroying it.
    - During the grace period (configurable via ``AGENTDECOMPILE_SESSION_GRACE_PERIOD``
      env var, default 300 s), a reconnecting client with the same fingerprint
      can reclaim the session state.
    - A background reaper thread periodically purges expired grace-period entries
      and idle sessions to bound memory usage.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agentdecompile_cli.app_logger import basename_hint, redact_session_id

if TYPE_CHECKING:
    from ghidra.framework.remote import RepositoryItem as GhidraRepositoryItem  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

    from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)

CURRENT_MCP_SESSION_ID: ContextVar[str] = ContextVar("current_mcp_session_id", default="default")

# Per-request project path override (e.g. from proxy X-AgentDecompile-Project-Path header).
# When set, debug_info and open flows use this path instead of runtime_context.
CURRENT_REQUEST_PROJECT_PATH_OVERRIDE: ContextVar[str | None] = ContextVar("current_request_project_path_override", default=None)

# Per-request auto match-function propagation (X-AgentDecompile-Auto-Match-Propagate header).
# When set, overrides AGENTDECOMPILE_AUTO_MATCH_PROPAGATE for this request (value: 1, true, yes).
CURRENT_REQUEST_AUTO_MATCH_PROPAGATE: ContextVar[str | None] = ContextVar("current_request_auto_match_propagate", default=None)

# Per-request auto match target paths (X-AgentDecompile-Auto-Match-Target-Paths header).
# Comma-separated program paths; when set, overrides AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS for this request.
CURRENT_REQUEST_AUTO_MATCH_TARGET_PATHS: ContextVar[str | None] = ContextVar("current_request_auto_match_target_paths", default=None)

# Default grace period in seconds.  Overridden by AGENTDECOMPILE_SESSION_GRACE_PERIOD
_DEFAULT_GRACE_PERIOD: int = 300
# How frequently the reaper thread checks for expired entries (seconds)
_REAPER_INTERVAL: int = 30
# Maximum number of sessions to keep in the grace-period store
_MAX_GRACE_ENTRIES: int = 100


def _get_grace_period() -> int:
    """Return the configured session grace period in seconds."""
    logger.debug("diag.enter %s", "mcp_server/session_context.py:_get_grace_period")
    raw = os.environ.get("AGENTDECOMPILE_SESSION_GRACE_PERIOD", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            logger.warning(
                "mcp_session_grace_env_invalid raw_len=%s using_default_seconds=%s",
                len(raw),
                _DEFAULT_GRACE_PERIOD,
            )
    return _DEFAULT_GRACE_PERIOD


def get_current_request_project_path_override() -> str | None:
    """Return the current request's project path override (from proxy header), if any."""
    logger.debug("diag.enter %s", "mcp_server/session_context.py:get_current_request_project_path_override")
    return CURRENT_REQUEST_PROJECT_PATH_OVERRIDE.get()


def get_current_request_auto_match_propagate() -> str | None:
    """Return the current request's auto-match-propagate value (X-AgentDecompile-Auto-Match-Propagate), if any."""
    logger.debug("diag.enter %s", "mcp_server/session_context.py:get_current_request_auto_match_propagate")
    return CURRENT_REQUEST_AUTO_MATCH_PROPAGATE.get()


def get_current_request_auto_match_target_paths() -> str | None:
    """Return the current request's auto-match target paths (X-AgentDecompile-Auto-Match-Target-Paths), if any."""
    logger.debug("diag.enter %s", "mcp_server/session_context.py:get_current_request_auto_match_target_paths")
    return CURRENT_REQUEST_AUTO_MATCH_TARGET_PATHS.get()


def get_current_mcp_session_id() -> str:
    """Return the current MCP session ID for this request (used by tools to find SessionContext)."""
    logger.debug("diag.enter %s", "mcp_server/session_context.py:get_current_mcp_session_id")
    session_id: str | None = CURRENT_MCP_SESSION_ID.get()
    # Middleware sets "default" when the client omits mcp-session-id (AGENTS.md stable session).
    # Do not replace with sdk-session:object-id — that key diverges from the CLI-persisted header
    # (SDK UUID), so open/checkout state lands in one bucket and follow-up tools in another
    # (check-in then sees an unmodified versioned DomainFile).
    if session_id == "default":
        return "default"
    if session_id:
        return session_id

    # Fallback: derive from MCP SDK request context when transport wrappers do
    # not propagate CURRENT_MCP_SESSION_ID (e.g. some streamable-HTTP paths).
    try:
        from mcp.server.lowlevel.server import request_ctx

        ctx = request_ctx.get()
        session = getattr(ctx, "session", None)
        if session is not None:
            for attr in ("session_id", "id", "_session_id", "client_id"):
                value = getattr(session, attr, None)
                if value:
                    return str(value)
            return f"sdk-session:{id(session)}"
    except Exception as e:
        logger.debug(
            "mcp_session_id_sdk_probe_failed exc_type=%s fallback=default",
            type(e).__name__,
        )

    return session_id or "default"


@dataclass
class SessionContext:
    """Per-MCP-session state: open programs, active program, project handle, tool history.

    Keys in open_programs are program paths (as used by tools). active_program_key
    is the path of the "current" program when the client does not pass programPath.
    """

    session_id: str
    project_handle: dict[str, Any] | None = None
    open_programs: dict[str, ProgramInfo] = field(default_factory=dict)
    active_program_key: str | None = None
    preferences: dict[str, Any] = field(default_factory=dict)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    project_binaries: list[dict[str, Any]] = field(default_factory=list)
    # Lifecycle metadata
    client_fingerprint: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    # create-label (addr, name) pairs per canonical program path — merged into versioned check-in reopen
    # snapshots when Ghidra/JPype omits USER_DEFINED labels from the symbol table (LFG shared search 0 hits).
    pending_versioned_labels: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def touch(self) -> None:
        """Update last-activity timestamp."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContext.touch")
        self.last_activity = time.monotonic()

    def get_active_program_info(self) -> ProgramInfo | None:
        """Return the ProgramInfo for the session's active program key, or None if none set."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContext.get_active_program_info")
        if not self.active_program_key:
            return None
        return self.open_programs.get(self.active_program_key)


@dataclass
class _GraceEntry:
    """A session evicted from the SDK that is kept alive for reconnection."""

    context: SessionContext
    evicted_at: float = field(default_factory=time.monotonic)
    grace_seconds: float = _DEFAULT_GRACE_PERIOD


class SessionContextStore:
    """In-memory store of MCP sessions: active sessions, grace-period evictees, and client fingerprints.

    Single process-wide instance (SESSION_CONTEXTS). Thread-safe via _lock.
    Reaper thread purges expired grace entries and optionally idle sessions.
    """

    def __init__(self) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.__init__")
        self._lock: threading.RLock = threading.RLock()
        self._sessions: dict[str, SessionContext] = {}
        # Grace-period: evicted sessions kept for reconnection
        self._grace: dict[str, _GraceEntry] = {}
        # Client fingerprint → most recent session ID (for reconnect matching)
        self._fingerprint_map: dict[str, str] = {}
        # Background reaper
        self._reaper: threading.Thread | None = None
        self._reaper_stop: threading.Event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def start_reaper(self) -> None:
        """Start the background thread that purges expired grace-period entries."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.start_reaper")
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._reaper_stop.clear()
        self._reaper = threading.Thread(target=self._reaper_loop, daemon=True, name="session-reaper")
        self._reaper.start()

    def stop_reaper(self) -> None:
        """Signal the reaper thread to stop."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.stop_reaper")
        self._reaper_stop.set()

    def _reaper_loop(self) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore._reaper_loop")
        while not self._reaper_stop.wait(timeout=_REAPER_INTERVAL):
            self._purge_expired_grace_entries()

    def _purge_expired_grace_entries(self) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore._purge_expired_grace_entries")
        now = time.monotonic()
        with self._lock:
            expired = [sid for sid, entry in self._grace.items() if (now - entry.evicted_at) > entry.grace_seconds]
            for sid in expired:
                entry = self._grace.pop(sid, None)
                if entry:
                    logger.debug("Session %s grace period expired, purging state", sid[:12])
                    # Also clean fingerprint map
                    fp = entry.context.client_fingerprint
                    if fp and self._fingerprint_map.get(fp) == sid:
                        del self._fingerprint_map[fp]
            if expired:
                remaining = len(self._grace)
                logger.info(
                    "grace_period_purged expired_count=%s remaining_grace_count=%s",
                    len(expired),
                    remaining,
                )

    # ------------------------------------------------------------------
    # Client fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def compute_client_fingerprint(
        user_agent: str = "",
        remote_addr: str = "",
        extra: str = "",
    ) -> str:
        """Compute a stable fingerprint for a connecting client.

        Uses User-Agent + remote address + any extra identifying info.
        This is NOT a security mechanism — it's a best-effort session
        recovery hint for well-behaved clients.
        """
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.compute_client_fingerprint")
        raw = f"{user_agent}|{remote_addr}|{extra}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]

    def bind_fingerprint(self, session_id: str, fingerprint: str) -> None:
        """Associate a client fingerprint with a session."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.bind_fingerprint")
        with self._lock:
            old_sid = self._fingerprint_map.get(fingerprint)
            replaced_existing = old_sid is not None and old_sid != session_id
            ctx = self._sessions.get(session_id)
            if ctx:
                ctx.client_fingerprint = fingerprint
            self._fingerprint_map[fingerprint] = session_id
        fp_hint = (fingerprint[:8] + "…") if len(fingerprint) > 8 else fingerprint
        logger.info(
            "mcp_client_fingerprint_bound session_id=%s fingerprint_prefix=%s replaced_existing=%s",
            redact_session_id(session_id),
            fp_hint,
            replaced_existing,
        )

    def find_session_by_fingerprint(self, fingerprint: str) -> str | None:
        """Look up a session ID by client fingerprint.

        Checks grace-period entries first (reconnection scenario),
        then active sessions.
        """
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.find_session_by_fingerprint")
        with self._lock:
            sid = self._fingerprint_map.get(fingerprint)
            if sid and sid in self._grace:
                return sid
            if sid and sid in self._sessions:
                return sid
            fp_hint = (fingerprint[:8] + "…") if len(fingerprint) > 8 else fingerprint
            logger.debug(
                "fingerprint_session_miss fingerprint_prefix=%s had_map_entry=%s",
                fp_hint,
                sid is not None,
            )
            return None

    # ------------------------------------------------------------------
    # Grace-period management
    # ------------------------------------------------------------------

    def is_in_grace(self, session_id: str) -> bool:
        """True if ``session_id`` currently has preserved state in the grace-period store."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.is_in_grace")
        if not session_id:
            return False
        with self._lock:
            return session_id in self._grace

    def evict_to_grace(self, session_id: str) -> None:
        """Move an active session into the grace-period holding area."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.evict_to_grace")
        with self._lock:
            ctx = self._sessions.pop(session_id, None)
            if ctx is None:
                return
            grace_seconds = _get_grace_period()
            self._grace[session_id] = _GraceEntry(context=ctx, grace_seconds=grace_seconds)
            # Cap grace entries to prevent unbounded growth
            if len(self._grace) > _MAX_GRACE_ENTRIES:
                oldest_sid = min(self._grace, key=lambda s: self._grace[s].evicted_at)
                removed = self._grace.pop(oldest_sid, None)
                _fp_adjusted = False
                if removed:
                    fp = removed.context.client_fingerprint
                    if fp and self._fingerprint_map.get(fp) == oldest_sid:
                        del self._fingerprint_map[fp]
                        _fp_adjusted = True
                    logger.warning(
                        "mcp_grace_capacity_eviction dropped_session_id=%s grace_count_after=%s fingerprint_map_adjusted=%s",
                        redact_session_id(oldest_sid),
                        len(self._grace),
                        _fp_adjusted,
                    )
            logger.info(
                "Session %s moved to grace period (%ds), state preserved for reconnect",
                session_id[:12],
                grace_seconds,
            )

    def reclaim_from_grace(self, session_id: str, new_session_id: str) -> SessionContext | None:
        """Reclaim a grace-period session under a new SDK session ID.

        The SDK always creates a new session ID on reconnect, so we migrate
        the old context to the new ID.
        """
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.reclaim_from_grace")
        with self._lock:
            entry = self._grace.pop(session_id, None)
            if entry is None:
                return None
            ctx = entry.context
            ctx.session_id = new_session_id
            ctx.touch()
            self._sessions[new_session_id] = ctx
            # Update fingerprint map
            fp = ctx.client_fingerprint
            if fp:
                self._fingerprint_map[fp] = new_session_id
            logger.info(
                "Reclaimed grace-period session %s → new session %s",
                session_id[:12],
                new_session_id[:12],
            )
            return ctx

    # ------------------------------------------------------------------
    # Session statistics (for /health, monitoring)
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return summary statistics for monitoring."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.stats")
        with self._lock:
            return {
                "active_sessions": len(self._sessions),
                "grace_period_sessions": len(self._grace),
                "fingerprints_tracked": len(self._fingerprint_map),
            }

    # ------------------------------------------------------------------
    # Original CRUD operations
    # ------------------------------------------------------------------

    def get_or_create(self, session_id: str) -> SessionContext:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_or_create")
        normalized = session_id or "default"
        with self._lock:
            session = self._sessions.get(normalized)
            if session is not None:
                session.touch()
                return session
            # Check grace-period (client might be resuming with same ID)
            grace_entry = self._grace.pop(normalized, None)
            if grace_entry is not None:
                ctx = grace_entry.context
                ctx.session_id = normalized
                ctx.touch()
                self._sessions[normalized] = ctx
                logger.info(
                    "session_rehydrate source=grace session_id=%s",
                    redact_session_id(normalized),
                )
                return ctx
            # Sequential CLI / streamable HTTP: first invocation omits mcp-session-id → middleware uses
            # "default" and tools store Ghidra state under that key (get_current_mcp_session_id). The client
            # persists the SDK's mcp-session-id (UUID) from the response; the next subprocess sends that UUID.
            # Without rebinding, open/checkout state stays under "default" while follow-up tools use the UUID.
            if normalized != "default":
                default_ctx = self._sessions.get("default")
                if default_ctx is not None and (default_ctx.project_handle or default_ctx.open_programs or default_ctx.project_binaries):
                    default_ctx.session_id = normalized
                    self._sessions[normalized] = default_ctx
                    del self._sessions["default"]
                    default_ctx.touch()
                    logger.info(
                        "session_rebind_default_to_sdk_id session_id=%s",
                        redact_session_id(normalized),
                    )
                    return default_ctx
            session = SessionContext(session_id=normalized)
            self._sessions[normalized] = session
            logger.info("mcp_session_created session_id=%s", redact_session_id(normalized))
            return session

    def add_tool_history(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> None:
        """Append one tool invocation to session history; keep only the last 250 entries to bound memory."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.add_tool_history")
        session = self.get_or_create(session_id)
        with self._lock:
            session.tool_history.append({"tool": tool_name, "arguments": dict(arguments or {})})
            if len(session.tool_history) > 250:
                session.tool_history = session.tool_history[-250:]

    def set_project_handle(self, session_id: str, handle: dict[str, Any] | None) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.set_project_handle")
        session = self.get_or_create(session_id)
        with self._lock:
            session.project_handle = handle

    def get_project_handle(self, session_id: str) -> dict[str, Any] | None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_project_handle")
        session = self.get_or_create(session_id)
        with self._lock:
            return session.project_handle

    def set_project_binaries(self, session_id: str, binaries: list[dict[str, GhidraRepositoryItem]]) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.set_project_binaries")
        session = self.get_or_create(session_id)
        with self._lock:
            session.project_binaries = list(binaries)

    def get_project_binaries(self, session_id: str, fallback_to_latest: bool = False) -> list[dict[str, Any]]:
        """Return this session's project binaries only. Sessions are fully isolated; fallback_to_latest is ignored."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_project_binaries")
        session = self.get_or_create(session_id)
        with self._lock:
            if session.project_binaries:
                return list(session.project_binaries)
            return []

    def record_pending_versioned_label(self, session_id: str, program_path: str, addr: str, name: str) -> None:
        """Remember a user create-label for versioned check-in reopen when symbol snapshots are unreliable."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.record_pending_versioned_label")
        raw = (program_path or "").strip()
        if not raw:
            return
        key = self.canonicalize_program_path(session_id, raw)
        if not key:
            return
        session = self.get_or_create(session_id)
        t = (str(addr).strip(), str(name).strip())
        if not t[0] or not t[1]:
            return
        with self._lock:
            lst = session.pending_versioned_labels.setdefault(key, [])
            if t not in lst:
                lst.append(t)
            session.touch()

    def copy_pending_versioned_labels(self, session_id: str, program_path: str) -> list[tuple[str, str]]:
        """Return a copy of pending labels for this program path (do not clear)."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.copy_pending_versioned_labels")
        raw = (program_path or "").strip()
        if not raw:
            return []
        key = self.canonicalize_program_path(session_id, raw)
        session = self.get_or_create(session_id)
        with self._lock:
            return list(session.pending_versioned_labels.get(key, []))

    def copy_pending_versioned_labels_resolved(self, session_id: str, program_path: str) -> list[tuple[str, str]]:
        """Pending labels for the canonical path plus any bucket sharing the same basename.

        create-label and checkin-program can disagree on the stored session path key (canonicalize drift,
        adapter vs. tool path); a strict key lookup then misses rows and versioned reopen check-in uploads
        empty symbol trees (flaky LFG 02d / step 5).
        """
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.copy_pending_versioned_labels_resolved")
        merged: list[tuple[str, str]] = list(self.copy_pending_versioned_labels(session_id, program_path))
        seen: set[tuple[str, str]] = set(merged)
        raw = (program_path or "").strip().replace("\\", "/")
        if not raw:
            return merged
        want_base = raw.split("/")[-1].lower()
        if not want_base:
            return merged
        session = self.get_or_create(session_id)
        with self._lock:
            for k, lst in session.pending_versioned_labels.items():
                k_norm = str(k).strip().replace("\\", "/")
                kb = k_norm.split("/")[-1].lower()
                if kb != want_base:
                    continue
                for t in lst:
                    if t not in seen:
                        seen.add(t)
                        merged.append(t)
        return merged

    def clear_pending_versioned_labels(self, session_id: str, program_path: str) -> None:
        """Drop pending labels after a successful versioned check-in for this program."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.clear_pending_versioned_labels")
        raw = (program_path or "").strip()
        if not raw:
            return
        key = self.canonicalize_program_path(session_id, raw)
        session = self.get_or_create(session_id)
        with self._lock:
            session.pending_versioned_labels.pop(key, None)
            session.touch()

    def canonicalize_program_path(self, session_id: str, program_path: str) -> str:
        """Return the session listing's canonical path when ``program_path`` matches case-insensitively.

        Ghidra on Windows often stores ``HOSTNAME.EXE`` while tools pass ``/hostname.exe``; repository
        APIs are case-sensitive, so we align to the path from ``list-project-files`` / project_binaries.
        """
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.canonicalize_program_path")
        raw = (program_path or "").strip()
        if not raw:
            return raw
        want = raw.replace("\\", "/")
        want_l = want.lower()
        want_base = want_l.split("/")[-1]
        session = self.get_or_create(session_id)
        resolved: str | None = None
        with self._lock:
            for item in session.project_binaries:
                p = str(item.get("path") or "").strip().replace("\\", "/")
                name = str(item.get("name") or "").strip()
                if not p and not name:
                    continue
                p_l = p.lower()
                n_l = name.lower()
                if p_l == want_l or p_l.endswith("/" + want_base) or n_l == want_base:
                    resolved = p if p.startswith("/") else (f"/{p}" if p else f"/{name}")
                    break
                if want_l == f"/{n_l}" or want_l.lstrip("/") == n_l:
                    resolved = p if p.startswith("/") else f"/{name}"
                    break
        out = resolved if resolved is not None else want
        if resolved is not None and out != want:
            logger.info(
                "path_canonicalized session_id=%s before_tail=%s after_tail=%s",
                redact_session_id(session_id),
                basename_hint(want),
                basename_hint(out),
            )
        return out

    def get_tool_history(self, session_id: str, limit: int = 25) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_tool_history")
        session = self.get_or_create(session_id)
        with self._lock:
            if limit <= 0:
                return []
            return [dict(entry) for entry in session.tool_history[-limit:]]

    def get_session_snapshot(
        self,
        session_id: str,
        *,
        project_binary_limit: int = 50,
        tool_history_limit: int = 25,
    ) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_session_snapshot")
        session = self.get_or_create(session_id)
        with self._lock:
            return {
                "sessionId": session.session_id,
                "activeProgramKey": session.active_program_key,
                "openProgramKeys": list(session.open_programs.keys()),
                "openProgramCount": len(session.open_programs),
                "projectHandle": session.project_handle,
                "projectBinaryCount": len(session.project_binaries),
                "projectBinaries": [dict(item) for item in session.project_binaries[:project_binary_limit]],
                "toolHistoryCount": len(session.tool_history),
                "recentToolHistory": [dict(entry) for entry in session.tool_history[-tool_history_limit:]],
                "preferences": dict(session.preferences),
                "createdAt": session.created_at,
                "lastActivity": session.last_activity,
                "clientFingerprint": session.client_fingerprint,
            }

    def set_active_program_info(self, session_id: str, key: str, program_info: ProgramInfo) -> None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.set_active_program_info")
        session = self.get_or_create(session_id)
        with self._lock:
            session.open_programs[key] = program_info
            session.active_program_key = key

    def get_active_program_info(self, session_id: str) -> ProgramInfo | None:
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_active_program_info")
        session = self.get_or_create(session_id)
        with self._lock:
            return session.get_active_program_info()

    def get_active_program_key(self, session_id: str) -> str | None:
        """Return the session's active program path key (for restoring after opening another program)."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_active_program_key")
        session = self.get_or_create(session_id)
        with self._lock:
            return session.active_program_key

    def get_program_info(self, session_id: str, key: str) -> ProgramInfo | None:
        """Return ProgramInfo for a program key; tries exact key, then case-insensitive and path-normalized matches, then program name."""
        logger.debug("diag.enter %s", "mcp_server/session_context.py:SessionContextStore.get_program_info")
        session = self.get_or_create(session_id)
        with self._lock:
            direct = session.open_programs.get(key)
            if direct is not None:
                return direct

            # Fallback: case-insensitive key match, then path without leading slashes, then Ghidra program name
            key_l = key.strip().lower()
            for existing_key, info in session.open_programs.items():
                if existing_key.strip().lower() == key_l:
                    return info
                if existing_key.strip().lower().lstrip("/") == key_l.lstrip("/"):
                    return info

                try:
                    program: GhidraProgram = getattr(info, "program", None)
                    if program is not None:
                        # Match by last path component (e.g. "binary.exe") vs program.getName()
                        if str(program.getName()).strip().lower() == key_l.split("/")[-1]:
                            return info
                except Exception:
                    continue

            return None


def is_shared_server_handle(handle: dict[str, Any] | None) -> bool:
    """Return True if the session project handle represents a shared Ghidra server connection.

    Accepts both "shared-server" and "sharedserver" so all code paths recognize
    the session as shared regardless of which string is stored.
    """
    logger.debug("diag.enter %s", "mcp_server/session_context.py:is_shared_server_handle")
    if not handle:
        return False
    mode = (str(handle.get("mode", "") or "").strip().lower()).replace("-", "")
    return mode == "sharedserver"


SESSION_CONTEXTS = SessionContextStore()
