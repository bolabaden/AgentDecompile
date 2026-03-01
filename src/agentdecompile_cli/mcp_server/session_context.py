"""Session-scoped runtime state for MCP requests.

This module provides a lightweight in-memory SessionContext map keyed by MCP
session ID. It is intentionally process-local and suitable for a single MCP
server instance.
"""

from __future__ import annotations

import threading

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo


CURRENT_MCP_SESSION_ID: ContextVar[str] = ContextVar("current_mcp_session_id", default="default")


def get_current_mcp_session_id() -> str:
    session_id = CURRENT_MCP_SESSION_ID.get()
    if session_id and session_id != "default":
        return session_id

    # Fallback: derive from MCP SDK request context when transport wrappers do
    # not propagate CURRENT_MCP_SESSION_ID.
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
    session_id: str
    project_handle: Any | None = None
    open_programs: dict[str, ProgramInfo] = field(default_factory=dict)
    active_program_key: str | None = None
    preferences: dict[str, Any] = field(default_factory=dict)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    project_binaries: list[dict[str, Any]] = field(default_factory=list)

    def get_active_program_info(self) -> ProgramInfo | None:
        if not self.active_program_key:
            return None
        return self.open_programs.get(self.active_program_key)


class SessionContextStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionContext] = {}
        self._last_session_with_binaries: str | None = None

    def get_or_create(self, session_id: str) -> SessionContext:
        normalized = session_id or "default"
        with self._lock:
            session = self._sessions.get(normalized)
            if session is None:
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

    def set_active_program_info(self, session_id: str, key: str, program_info: ProgramInfo) -> None:
        session = self.get_or_create(session_id)
        with self._lock:
            session.open_programs[key] = program_info
            session.active_program_key = key

    def get_active_program_info(self, session_id: str) -> ProgramInfo | None:
        session = self.get_or_create(session_id)
        with self._lock:
            return session.get_active_program_info()

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
