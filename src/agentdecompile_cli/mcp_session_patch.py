"""
Apply MCP SDK fix for RuntimeError: dictionary changed size during iteration.

The MCP Python SDK's BaseSession._receive_loop iterates over self._response_streams.items()
in its finally block. Concurrent coroutines can modify this dict (via send_request's
finally block calling .pop()), causing the error. Industry-standard fix: use
list(self._response_streams.items()) to iterate over a snapshot.

This patches the installed mcp package's source file on disk before import.
No monkeypatching - we edit the installed source once.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _apply_mcp_session_fix() -> None:
    """Patch installed MCP session.py to use list() for _response_streams iteration."""
    try:
        spec = importlib.util.find_spec("mcp")
        if not spec or not spec.origin:
            return
        session_path = Path(spec.origin).parent / "shared" / "session.py"
        if not session_path.exists():
            return
        content = session_path.read_text(encoding="utf-8")
        old = "for id, stream in self._response_streams.items():"
        new = "for id, stream in list(self._response_streams.items()):"
        if old in content and new not in content:
            session_path.write_text(content.replace(old, new), encoding="utf-8")
    except Exception:
        pass
