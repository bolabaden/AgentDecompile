"""Shared helpers for collecting program-level and project-level metadata.

Used by:
- ``providers/project.py`` to enrich ``open-project`` responses with per-program
  details (function count, tags, bookmarks, versioning/checkout info).
- ``tool_providers.py`` base ``call_tool()`` to inject a concise
  ``projectContext`` block into every data-returning tool response.
"""

from __future__ import annotations

import logging
import time

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentdecompile_cli.context import ProgramInfo

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    SessionContext,
    is_shared_server_handle,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-program summary (rich detail for open-project)
# ---------------------------------------------------------------------------


def collect_program_summary(program_info: ProgramInfo) -> dict[str, Any]:
    """Collect a rich metadata summary for a single loaded program.

    All Ghidra API calls are wrapped in try/except so the summary degrades
    gracefully when a program is partially loaded or an API is unavailable.
    """
    program = getattr(program_info, "program", None)
    if program is None:
        return {"name": getattr(program_info, "name", "unknown")}

    summary: dict[str, Any] = {"name": getattr(program_info, "name", "") or ""}

    # --- Function count ---
    try:
        fm = program.getFunctionManager()
        summary["functionCount"] = int(fm.getFunctionCount())
    except Exception:
        pass

    # --- Function tags ---
    try:
        fm = program.getFunctionManager()
        tag_mgr = fm.getFunctionTagManager()
        all_tags = tag_mgr.getAllFunctionTags()
        tags: list[dict[str, Any]] = []
        if all_tags:
            for tag in all_tags:
                tag_name = str(tag.getName())
                try:
                    use_count = int(tag_mgr.getUseCount(tag))
                except Exception:
                    use_count = 0
                tags.append({"name": tag_name, "useCount": use_count})
        summary["functionTags"] = tags
    except Exception:
        pass

    # --- Bookmarks ---
    try:
        bm = program.getBookmarkManager()
        summary["bookmarkCount"] = int(bm.getBookmarkCount())
        bm_types = bm.getBookmarkTypes()
        if bm_types:
            type_counts: dict[str, int] = {}
            for bt in bm_types:
                type_str = str(bt.getTypeString()) if hasattr(bt, "getTypeString") else str(bt)
                try:
                    type_counts[type_str] = int(bm.getBookmarkCount(type_str))
                except Exception:
                    type_counts[type_str] = 0
            summary["bookmarksByType"] = type_counts
    except Exception:
        pass

    # --- Listing stats ---
    try:
        listing = program.getListing()
        summary["instructionCount"] = int(listing.getNumInstructions())
    except Exception:
        pass

    try:
        listing = program.getListing()
        # getCommentAddressCount can vary by Ghidra version
        if hasattr(listing, "getCommentAddressIterator"):
            # Count PRE comments as a proxy if getCommentAddressCount is absent
            pass
    except Exception:
        pass

    # --- Language / Compiler ---
    try:
        summary["languageId"] = str(program.getLanguageID())
    except Exception:
        pass

    try:
        summary["compilerSpec"] = str(program.getCompilerSpec().getCompilerSpecID())
    except Exception:
        pass

    # --- Program metadata (selective) ---
    _METADATA_KEYS = (
        "Executable Format",
        "Compiler",
        "Created With Ghidra Version",
        "Date Created",
        "Executable Location",
        "Executable MD5",
        "Executable SHA256",
    )
    try:
        raw_meta = program.getMetadata()
        if raw_meta:
            picked: dict[str, str] = {}
            for key in _METADATA_KEYS:
                val = raw_meta.get(key)
                if val is not None:
                    picked[key] = str(val)
            if picked:
                summary["metadata"] = picked
    except Exception:
        pass

    # --- DomainFile versioning/checkout ---
    try:
        df = program.getDomainFile()
        if df is not None:
            versioning: dict[str, Any] = {}
            try:
                versioning["isVersioned"] = bool(df.isVersioned())
            except Exception:
                pass
            try:
                versioning["isCheckedOut"] = bool(df.isCheckedOut())
            except Exception:
                pass
            try:
                versioning["isCheckedOutExclusive"] = bool(df.isCheckedOutExclusive())
            except Exception:
                pass
            try:
                versioning["modifiedSinceCheckout"] = bool(df.modifiedSinceCheckout())
            except Exception:
                pass
            try:
                versioning["canCheckout"] = bool(df.canCheckout())
            except Exception:
                pass
            try:
                versioning["canCheckin"] = bool(df.canCheckin())
            except Exception:
                pass
            try:
                versioning["currentVersion"] = int(df.getVersion())
            except Exception:
                pass
            try:
                versioning["latestVersion"] = int(df.getLatestVersion())
            except Exception:
                pass
            try:
                last_mod_ms = df.getLastModifiedTime()
                if last_mod_ms:
                    versioning["lastModified"] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_mod_ms / 1000.0)
                    )
            except Exception:
                pass
            try:
                versioning["fileSize"] = int(df.length())
            except Exception:
                pass

            # Checkout status detail
            if versioning.get("isCheckedOut"):
                try:
                    status = df.getCheckoutStatus()
                    if status is not None:
                        versioning["checkoutUser"] = str(status.getUser()) if hasattr(status, "getUser") else None
                        try:
                            versioning["checkoutVersion"] = int(status.getCheckoutVersion())
                        except Exception:
                            pass
                except Exception:
                    pass

            if versioning:
                summary["versioning"] = versioning
    except Exception:
        pass

    return summary


# ---------------------------------------------------------------------------
# Compact project context (injected into every tool response)
# ---------------------------------------------------------------------------


def collect_project_context(session_id: str) -> dict[str, Any] | None:
    """Build a compact project-context dict for the given session.

    Returns ``None`` if no project/programs are loaded (so the caller can
    skip injection).
    """
    session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
    handle = session.project_handle
    open_programs = session.open_programs or {}
    active_key = session.active_program_key

    # Nothing loaded → skip
    if not handle and not open_programs:
        return None

    ctx: dict[str, Any] = {}

    # --- Mode and path ---
    is_shared = is_shared_server_handle(handle)
    if handle:
        mode = str(handle.get("mode", "unknown"))
        ctx["mode"] = mode
        if is_shared:
            ctx["serverHost"] = handle.get("server_host") or handle.get("serverHost")
            ctx["serverPort"] = handle.get("server_port") or handle.get("serverPort")
            ctx["repository"] = handle.get("repository") or handle.get("repository_name")
        path = handle.get("path") or handle.get("gpr_path")
        if path:
            ctx["projectPath"] = str(path)
        project_name = handle.get("projectName") or handle.get("project_name")
        if project_name:
            ctx["projectName"] = str(project_name)

    # --- Programs ---
    program_names = list(open_programs.keys())
    ctx["programCount"] = len(program_names)
    if program_names:
        ctx["programs"] = program_names
    if active_key:
        ctx["activeProgram"] = active_key

    return ctx


# ---------------------------------------------------------------------------
# Injection helper (for call_tool post-processing)
# ---------------------------------------------------------------------------

# Tools that should NOT receive the projectContext injection
# (their response is meta/administrative, not program data).
_SKIP_CONTEXT_TOOLS: frozenset[str] = frozenset({
    "debuginfo",
    "listtools",
})


def inject_project_context(
    response_text: str,
    session_id: str,
    *,
    tool_name_normalized: str = "",
) -> str:
    """Parse a JSON tool response, inject ``projectContext``, re-serialize.

    Returns the original ``response_text`` unchanged if:
    - The response is not valid JSON.
    - The response already has a ``projectContext`` key.
    - No project/programs are loaded.
    - The tool is in the skip-list.
    """
    if tool_name_normalized in _SKIP_CONTEXT_TOOLS:
        return response_text

    import json as _json

    try:
        data = _json.loads(response_text)
    except Exception:
        return response_text

    if not isinstance(data, dict):
        return response_text

    if "projectContext" in data:
        return response_text

    ctx = collect_project_context(session_id)
    if ctx is None:
        return response_text

    data["projectContext"] = ctx
    return _json.dumps(data)
