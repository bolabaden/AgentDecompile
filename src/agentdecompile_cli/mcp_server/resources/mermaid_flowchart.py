"""Mermaid flowchart resource: agentdecompile://mermaid-flowchart.

Generates a Mermaid flowchart from all open programs: one subgraph per program,
nodes = functions (bold title from name, body from comments), edges = calls.
Entry point is clearly positioned (stadium shape, distinct style). Bookmark
types at function entry determine node border color (deterministic palette).
Includes function tags, bookmarks, and comments with no omissions.
"""

from __future__ import annotations

import hashlib
import logging
import re

from typing import TYPE_CHECKING, Any

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_function_comments,
    collect_function_tags,
    iter_items,
)
from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    SessionContext,
    get_current_mcp_session_id,
)

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)

_URI = "agentdecompile://mermaid-flowchart"

# Mermaid-safe: node ids alphanumeric + underscore; labels: escape ] " # and avoid bare "end"
_ID_RE = re.compile(r"[^a-zA-Z0-9_]")
_LABEL_ESCAPE = str.maketrans({'"': "#quot;", "]": "]", "#": "#35;", "&": "&amp;", "<": "&lt;", ">": "&gt;"})

# Deterministic border colors by bookmark type (hash → palette index). Accessible, distinct strokes.
_BORDER_PALETTE = [
    ("#00695c", "#004d40"),   # dark teal
    ("#00838f", "#006064"),   # teal
    ("#1976d2", "#0d47a1"),   # blue
    ("#388e3c", "#1b5e20"),   # green
    ("#455a64", "#263238"),   # blue grey
    ("#5d4037", "#3e2723"),   # brown
    ("#6a1b9a", "#4a148c"),   # deep purple
    ("#7b1fa2", "#4a148c"),   # purple
    ("#c62828", "#b71c1c"),   # red
    ("#f57c00", "#e65100"),   # orange
]


def _sanitize_node_id(s: str, max_len: int = 60) -> str:
    """Return a Mermaid-safe node id (alphanumeric + underscore)."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_sanitize_node_id")
    out = _ID_RE.sub("_", s)[:max_len].strip("_") or "n"
    if out.lower() == "end":
        out = "n_end"
    return out or "n"


def _escape_label(text: str) -> str:
    """Escape special chars for use inside Mermaid quoted labels."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_escape_label")
    if not text:
        return ""
    return text.translate(_LABEL_ESCAPE).replace("\n", "<br>").strip()


def _border_class_for_bookmarks(bookmark_types: set[str]) -> str:
    """Deterministic class name from bookmark types (hash → palette index)."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_border_class_for_bookmarks")
    if not bookmark_types:
        return "default"
    key = "|".join(sorted(bookmark_types))
    h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    idx = h % len(_BORDER_PALETTE)
    return f"tag{idx}"


def _get_program_entry_point(program: Any) -> Any:
    """Return the Function at program entry, or None. Uses GhidraProgramUtilities or first function by address."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_get_program_entry_point")
    fm = program.getFunctionManager()
    try:
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

        if hasattr(GhidraProgramUtilities, "getProgramEntryPoint"):
            entry_addr = GhidraProgramUtilities.getProgramEntryPoint(program)
            if entry_addr is not None:
                return fm.getFunctionAt(entry_addr)
    except Exception:
        pass
    try:
        min_addr = program.getMinAddress()
        if min_addr is not None:
            return fm.getFunctionAt(min_addr)
    except Exception:
        pass
    try:
        for func in iter_items(fm.getFunctions(True)):
            return func
    except Exception:
        pass
    return None


def _function_body_text(program: Any, func: Any) -> str:
    """Single body string from function comment, repeatable comment, and entry-point code unit comments."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_function_body_text")
    parts: list[str] = []
    try:
        c = func.getComment()
        if c and str(c).strip():
            parts.append(str(c).strip())
        rc = func.getRepeatableComment()
        if rc and str(rc).strip():
            parts.append(str(rc).strip())
    except Exception:
        pass
    try:
        entry_comments = collect_function_comments(program, func)
        for _label, txt in entry_comments.items():
            if txt and str(txt).strip():
                parts.append(str(txt).strip())
    except Exception:
        pass
    return " | ".join(parts) if parts else ""


def _bookmarks_at_address(program: Any, addr: Any) -> list[tuple[str, str, str]]:
    """Return list of (type, category, comment) for bookmarks at address."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_bookmarks_at_address")
    out: list[tuple[str, str, str]] = []
    try:
        bm_mgr = program.getBookmarkManager()
        bookmarks = bm_mgr.getBookmarks(addr) if hasattr(bm_mgr, "getBookmarks") else []
        if bookmarks is None:
            return out
        for bm in list(bookmarks):
            t = str(bm.getTypeString() or "")
            c = str(bm.getCategory() or "")
            m = str(bm.getComment() or "")
            out.append((t, c, m))
    except Exception:
        pass
    return out


def _build_mermaid_for_program(
    program: Any, program_label: str, program_id: str
) -> tuple[list[str], list[str], dict[str, str], list[str]]:
    """Build Mermaid lines for one program: node defs, edge lines, classDef lines, and entry node ids."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_build_mermaid_for_program")
    from agentdecompile_cli.mcp_server.providers._collectors import _get_function_list

    node_lines: list[str] = []
    edge_lines: list[str] = []
    class_defs: dict[str, str] = {}
    entry_node_ids: list[str] = []
    entry_func = _get_program_entry_point(program)
    entry_addr_str = str(entry_func.getEntryPoint()) if entry_func is not None else None

    fm = program.getFunctionManager()
    func_list = _get_function_list(fm)
    if not func_list:
        return node_lines, edge_lines, class_defs, entry_node_ids

    # Map function (name, entryAddr) -> unique node id for this program
    func_to_id: dict[tuple[str, str], str] = {}
    used_ids: set[str] = set()

    for idx, func in enumerate(func_list):
        try:
            name = str(func.getName() or "unknown")
            entry_addr = str(func.getEntryPoint())
            body = _function_body_text(program, func)
            bookmarks = _bookmarks_at_address(program, func.getEntryPoint())
            tags = collect_function_tags(func)
        except Exception as e:
            logger.debug("mermaid_flowchart: skip function %s: %s", idx, e)
            continue

        # Unique id: program_id + sanitized name + short addr
        base_id = f"{program_id}_{_sanitize_node_id(name)}_{entry_addr.replace(':', '_')[-12:]}"
        nid = base_id
        c = 0
        while nid in used_ids:
            c += 1
            nid = f"{base_id}_{c}"
        used_ids.add(nid)
        func_to_id[(name, entry_addr)] = nid

        # Title (bold) + body; append bookmark/tag hints
        title = f"**{_escape_label(name)}**"
        if body:
            title += f"<br>{_escape_label(body[:500])}"
        if tags:
            title += f"<br>tags: {_escape_label(', '.join(tags))}"
        if bookmarks:
            bm_parts = [f"{t}: {_escape_label(m or c)}" for t, c, m in bookmarks[:3]]
            title += f"<br>bookmarks: {_escape_label('; '.join(bm_parts))}"

        label = f'"{title}"'
        is_entry = entry_addr_str is not None and entry_addr == entry_addr_str

        if is_entry:
            node_lines.append(f"        {nid}([{_escape_label(name)}])")
        else:
            node_lines.append(f"        {nid}[{label}]")

        # Bookmark-based border class
        bm_types = {t for t, _c, _m in bookmarks}
        border_class = _border_class_for_bookmarks(bm_types)
        if border_class != "default" and border_class not in class_defs:
            idx_palette = int(border_class.replace("tag", "")) % len(_BORDER_PALETTE)
            fill, stroke = _BORDER_PALETTE[idx_palette]
            class_defs[border_class] = f"fill:{fill},stroke:{stroke},stroke-width:2px"
        if border_class != "default":
            node_lines.append(f"        class {nid} {border_class}")

    # Edges: callees (TaskMonitor can be None in PyGhidra)
    for func in func_list:
        try:
            name = str(func.getName() or "unknown")
            entry_addr = str(func.getEntryPoint())
            src_id = func_to_id.get((name, entry_addr))
            if not src_id:
                continue
            try:
                callees = list(func.getCalledFunctions(None))
            except Exception:
                callees = []
            for callee in callees or []:
                try:
                    c_name = str(callee.getName() or "unknown")
                    c_addr = str(callee.getEntryPoint())
                    tgt_id = func_to_id.get((c_name, c_addr))
                    if tgt_id and tgt_id != src_id:
                        edge_lines.append(f"        {src_id} --> {tgt_id}")
                except Exception:
                    continue
        except Exception:
            continue

    return node_lines, edge_lines, class_defs, entry_node_ids


class MermaidFlowchartResource(ResourceProvider):
    """MCP resource that returns a Mermaid flowchart of all open programs: functions as nodes, calls as edges."""

    def list_resources(self) -> list[types.Resource]:
        logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:MermaidFlowchartResource.list_resources")
        return [
            types.Resource(
                uri=AnyUrl(url=_URI),
                name="Mermaid Flowchart",
                description="Mermaid flowchart from all open programs: functions (bold title, comments body), calls as edges, entry point highlighted, bookmark-based border colors.",
                mimeType="text/markdown",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:MermaidFlowchartResource.read_resource")
        if str(uri).strip() != _URI:
            raise NotImplementedError(f"Unknown resource: {uri}")

        session_id: str = get_current_mcp_session_id()
        session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
        open_programs: dict[str, ProgramInfo] = getattr(session, "open_programs", None) or {}

        if not open_programs:
            return _wrap_mermaid(
                "flowchart TB\n    subgraph empty[No open programs]\n        N[Open programs to generate flowchart]\n    end",
                note="No open programs in session. Open and analyze programs first.",
            )

        lines: list[str] = ["flowchart TB"]
        all_class_defs: dict[str, str] = {"entry": "fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px"}
        entry_ids: list[str] = []

        for path_key, program_info in open_programs.items():
            program = getattr(program_info, "program", None)
            if program is None:
                continue
            try:
                prog_name = getattr(program, "getName", lambda: path_key)()
                program_label = _escape_label(str(prog_name))
                program_id = _sanitize_node_id(path_key, 40)
                node_lines, edge_lines, class_defs, entry_node_ids = _build_mermaid_for_program(
                    program, program_label, program_id
                )
                if not node_lines:
                    continue
                all_class_defs.update(class_defs)
                entry_ids.extend(entry_node_ids)
                lines.append(f"    subgraph {program_id}[{program_label}]")
                lines.extend(node_lines)
                lines.extend(edge_lines)
                lines.append("    end")
            except Exception as e:
                logger.warning("mermaid_flowchart: skip program %s: %s", path_key, e, exc_info=True)
                continue

        for cname, cstyle in all_class_defs.items():
            lines.append(f"    classDef {cname} {cstyle}")
        if entry_ids:
            lines.append(f"    class {','.join(entry_ids)} entry")

        return _wrap_mermaid("\n".join(lines), note="Entry point = stadium shape. Border color = bookmark type at function entry.")


def _wrap_mermaid(diagram: str, note: str = "") -> str:
    """Wrap Mermaid code in optional note and code block."""
    logger.debug("diag.enter %s", "mcp_server/resources/mermaid_flowchart.py:_wrap_mermaid")
    out = []
    if note:
        out.append(f"<!-- {note} -->\n")
    out.append("```mermaid\n")
    out.append(diagram)
    out.append("\n```")
    return "".join(out)
