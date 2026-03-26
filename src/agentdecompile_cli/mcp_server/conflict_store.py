"""Session-scoped store for pending modification conflicts.

When a modifying tool would overwrite custom data, it stores the pending
modification here keyed by (session_id, conflictId). resolve-modification-conflict
looks up by conflictId and either applies (re-invoke tool with force flag) or discards.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from agentdecompile_cli.app_logger import basename_hint, redact_session_id

logger = logging.getLogger(__name__)

# Max pending conflicts per session; oldest dropped when exceeded
_MAX_PENDING_PER_SESSION = 100
# TTL seconds for a pending entry (optional cleanup)
_PENDING_TTL_SECONDS = 3600


@dataclass
class PendingModification:
    """Stored pending modification to apply when user calls resolve-modification-conflict with overwrite."""

    conflict_id: str
    tool: str
    arguments: dict[str, Any]
    program_path: str | None
    summary: str | None
    created_at: float = field(default_factory=time.monotonic)

    def is_expired(self, ttl_seconds: float = _PENDING_TTL_SECONDS) -> bool:
        logger.debug("diag.enter %s", "mcp_server/conflict_store.py:PendingModification.is_expired")
        return (time.monotonic() - self.created_at) > ttl_seconds


# session_id -> { conflict_id -> PendingModification }
_store: dict[str, dict[str, PendingModification]] = {}
_lock = threading.RLock()


def _get_session_store(session_id: str) -> dict[str, PendingModification]:
    logger.debug("diag.enter %s", "mcp_server/conflict_store.py:_get_session_store")
    with _lock:
        if session_id not in _store:
            _store[session_id] = {}
        return _store[session_id]


def store(
    session_id: str,
    conflict_id: str,
    tool: str,
    arguments: dict[str, Any],
    program_path: str | None = None,
    summary: str | None = None,
) -> None:
    """Store a pending modification for the given session and conflictId."""
    logger.debug("diag.enter %s", "mcp_server/conflict_store.py:store")
    with _lock:
        sess = _get_session_store(session_id)
        # Cap size: drop oldest by created_at if over limit
        if len(sess) >= _MAX_PENDING_PER_SESSION:
            oldest_id = min(sess, key=lambda cid: sess[cid].created_at)
            del sess[oldest_id]
            logger.debug("Dropped oldest pending conflict %s for session", oldest_id[:8])
        sess[conflict_id] = PendingModification(
            conflict_id=conflict_id,
            tool=tool,
            arguments=dict(arguments) if arguments else {},
            program_path=program_path,
            summary=summary,
        )
        logger.info(
            "modification conflict pending conflict_id=%s tool=%s session_id=%s program=%s pending_count=%d",
            conflict_id[:8],
            tool,
            redact_session_id(session_id),
            basename_hint(program_path),
            len(sess),
        )


def get(session_id: str, conflict_id: str) -> PendingModification | None:
    """Return the pending modification for this session and conflictId, or None if not found or expired."""
    logger.debug("diag.enter %s", "mcp_server/conflict_store.py:get")
    with _lock:
        sess = _get_session_store(session_id)
        pending = sess.get(conflict_id)
        if pending is None:
            return None
        if pending.is_expired():
            del sess[conflict_id]
            logger.warning(
                "pending_conflict_expired conflict_id_prefix=%s session_id=%s source_tool=%s",
                conflict_id[:8],
                redact_session_id(session_id),
                pending.tool,
            )
            return None
        return pending


def remove(session_id: str, conflict_id: str) -> bool:
    """Remove the pending modification; return True if it existed."""
    logger.debug("diag.enter %s", "mcp_server/conflict_store.py:remove")
    with _lock:
        sess = _get_session_store(session_id)
        if conflict_id in sess:
            del sess[conflict_id]
            return True
        return False
