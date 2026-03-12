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

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)

CURRENT_MCP_SESSION_ID: ContextVar[str] = ContextVar("current_mcp_session_id", default="default")

# Default grace period in seconds.  Overridden by AGENTDECOMPILE_SESSION_GRACE_PERIOD
_DEFAULT_GRACE_PERIOD: int = 300
# How frequently the reaper thread checks for expired entries (seconds)
_REAPER_INTERVAL: int = 30
# Maximum number of sessions to keep in the grace-period store
_MAX_GRACE_ENTRIES: int = 100


def _get_grace_period() -> int:
    """Return the configured session grace period in seconds."""
    raw = os.environ.get("AGENTDECOMPILE_SESSION_GRACE_PERIOD", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_GRACE_PERIOD


def get_current_mcp_session_id() -> str:
    """Return the current MCP session ID for this request (used by tools to find SessionContext)."""
    session_id = CURRENT_MCP_SESSION_ID.get()
    if session_id and session_id != "default":
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
    except Exception:
        pass

    return session_id or "default"


@dataclass
class SessionContext:
    """Per-MCP-session state: open programs, active program, project handle, tool history.

    Keys in open_programs are program paths (as used by tools). active_program_key
    is the path of the "current" program when the client does not pass programPath.
    """
    session_id: str
    project_handle: Any | None = None
    open_programs: dict[str, ProgramInfo] = field(default_factory=dict)
    active_program_key: str | None = None
    preferences: dict[str, Any] = field(default_factory=dict)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    project_binaries: list[dict[str, Any]] = field(default_factory=list)
    # Lifecycle metadata
    client_fingerprint: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        """Update last-activity timestamp."""
        self.last_activity = time.monotonic()

    def get_active_program_info(self) -> ProgramInfo | None:
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
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionContext] = {}
        self._last_session_with_binaries: str | None = None
        # Grace-period: evicted sessions kept for reconnection
        self._grace: dict[str, _GraceEntry] = {}
        # Client fingerprint → most recent session ID (for reconnect matching)
        self._fingerprint_map: dict[str, str] = {}
        # Background reaper
        self._reaper: threading.Thread | None = None
        self._reaper_stop = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def start_reaper(self) -> None:
        """Start the background thread that purges expired grace-period entries."""
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._reaper_stop.clear()
        self._reaper = threading.Thread(target=self._reaper_loop, daemon=True, name="session-reaper")
        self._reaper.start()

    def stop_reaper(self) -> None:
        """Signal the reaper thread to stop."""
        self._reaper_stop.set()

    def _reaper_loop(self) -> None:
        while not self._reaper_stop.wait(timeout=_REAPER_INTERVAL):
            self._purge_expired_grace_entries()

    def _purge_expired_grace_entries(self) -> None:
        now = time.monotonic()
        with self._lock:
            expired = [
                sid for sid, entry in self._grace.items()
                if (now - entry.evicted_at) > entry.grace_seconds
            ]
            for sid in expired:
                entry = self._grace.pop(sid, None)
                if entry:
                    logger.debug("Session %s grace period expired, purging state", sid[:12])
                    # Also clean fingerprint map
                    fp = entry.context.client_fingerprint
                    if fp and self._fingerprint_map.get(fp) == sid:
                        del self._fingerprint_map[fp]

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
        raw = f"{user_agent}|{remote_addr}|{extra}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]

    def bind_fingerprint(self, session_id: str, fingerprint: str) -> None:
        """Associate a client fingerprint with a session."""
        with self._lock:
            ctx = self._sessions.get(session_id)
            if ctx:
                ctx.client_fingerprint = fingerprint
            self._fingerprint_map[fingerprint] = session_id

    def find_session_by_fingerprint(self, fingerprint: str) -> str | None:
        """Look up a session ID by client fingerprint.

        Checks grace-period entries first (reconnection scenario),
        then active sessions.
        """
        with self._lock:
            sid = self._fingerprint_map.get(fingerprint)
            if sid and sid in self._grace:
                return sid
            if sid and sid in self._sessions:
                return sid
            return None

    # ------------------------------------------------------------------
    # Grace-period management
    # ------------------------------------------------------------------

    def evict_to_grace(self, session_id: str) -> None:
        """Move an active session into the grace-period holding area."""
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
                if removed:
                    fp = removed.context.client_fingerprint
                    if fp and self._fingerprint_map.get(fp) == oldest_sid:
                        del self._fingerprint_map[fp]
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
                logger.debug("Restored session %s from grace period", normalized[:12])
                return ctx
            session = SessionContext(session_id=normalized)
            self._sessions[normalized] = session
            return session

    def add_tool_history(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> None:
        session = self.get_or_create(session_id)
        with self._lock:
            session.tool_history.append({"tool": tool_name, "arguments": dict(arguments or {})})
            if len(session.tool_history) > 250:
                session.tool_history = session.tool_history[-250:]

    def set_project_handle(self, session_id: str, handle: Any) -> None:
        session = self.get_or_create(session_id)
        with self._lock:
            session.project_handle = handle

    def get_project_handle(self, session_id: str) -> Any | None:
        session = self.get_or_create(session_id)
        with self._lock:
            return session.project_handle

    def set_project_binaries(self, session_id: str, binaries: list[dict[str, Any]]) -> None:
        session = self.get_or_create(session_id)
        with self._lock:
            session.project_binaries = list(binaries)
            if session.project_binaries:
                self._last_session_with_binaries = session.session_id

    def get_project_binaries(self, session_id: str, fallback_to_latest: bool = False) -> list[dict[str, Any]]:
        session = self.get_or_create(session_id)
        with self._lock:
            if session.project_binaries:
                return list(session.project_binaries)

            # Never leak binary catalogs across explicit MCP client sessions.
            # Fallback is retained only for legacy/default session behavior.
            if fallback_to_latest and session.session_id == "default" and self._last_session_with_binaries:
                latest = self._sessions.get(self._last_session_with_binaries)
                if latest and latest.project_binaries:
                    return list(latest.project_binaries)

            return []

    def get_tool_history(self, session_id: str, limit: int = 25) -> list[dict[str, Any]]:
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
        session = self.get_or_create(session_id)
        with self._lock:
            session.open_programs[key] = program_info
            session.active_program_key = key

    def get_active_program_info(self, session_id: str) -> ProgramInfo | None:
        session = self.get_or_create(session_id)
        with self._lock:
            return session.get_active_program_info()

    def get_active_program_key(self, session_id: str) -> str | None:
        """Return the session's active program path key (for restoring after opening another program)."""
        session = self.get_or_create(session_id)
        with self._lock:
            return session.active_program_key

    def get_program_info(self, session_id: str, key: str) -> ProgramInfo | None:
        session = self.get_or_create(session_id)
        with self._lock:
            direct = session.open_programs.get(key)
            if direct is not None:
                return direct

            key_l = key.strip().lower()
            for existing_key, info in session.open_programs.items():
                if existing_key.strip().lower() == key_l:
                    return info
                if existing_key.strip().lower().lstrip("/") == key_l.lstrip("/"):
                    return info

                try:
                    program = getattr(info, "program", None)
                    if program is not None and hasattr(program, "getName"):
                        if str(program.getName()).strip().lower() == key_l.split("/")[-1]:
                            return info
                except Exception:
                    continue

            return None


SESSION_CONTEXTS = SessionContextStore()
