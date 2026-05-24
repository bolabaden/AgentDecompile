"""Shared package :class:`logging.Logger` and small helpers for safe diagnostic fields.

Prefer ``logging.getLogger(__name__)`` per module for normal development; use
``APP_LOGGER`` or :func:`get_app_logger` when a single stable logger name is
required. Use :func:`redact_session_id` and :func:`norm_arg_keys` so logs stay
useful without leaking full session tokens or large argument payloads.
"""

from __future__ import annotations

import logging
from typing import Any

_APP_LOG_NAME = "agentdecompile_cli"

APP_LOGGER: logging.Logger = logging.getLogger(_APP_LOG_NAME)


def get_app_logger() -> logging.Logger:
    """Return the package-wide :class:`logging.Logger` (same object as ``APP_LOGGER``)."""
    return APP_LOGGER


def redact_session_id(session_id: str | None, prefix: int = 12) -> str:
    """Return a log-safe session hint (never the full id)."""
    if not session_id:
        return "—"
    s = session_id.strip()
    if len(s) > prefix:
        return s[:prefix] + "…"
    return s


def norm_arg_keys(arguments: dict[str, Any] | None, *, limit: int = 48) -> str:
    """Sorted parameter names for DEBUG logs (no values)."""
    if not arguments:
        return "()"
    keys = sorted({str(k) for k in arguments.keys() if k is not None})
    if len(keys) > limit:
        return "(" + ", ".join(keys[:limit]) + f", …+{len(keys) - limit})"
    return "(" + ", ".join(keys) + ")"


def basename_hint(path: str | None, *, max_len: int = 120) -> str:
    """Basename or tail of a path for logs (avoid dumping huge absolute paths)."""
    if not path:
        return "—"
    p = str(path).strip().replace("\\", "/")
    base = p.rsplit("/", 1)[-1] if "/" in p else p
    if len(base) > max_len:
        return base[: max_len - 1] + "…"
    return base
