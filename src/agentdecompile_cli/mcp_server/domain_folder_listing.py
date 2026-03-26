"""List Ghidra DomainFolder trees for local projects.

Used by list-project-files and ghidra://programs when no program is loaded in
ProgramInfo but a GhidraProject exists (e.g. after server restart: binaries are
on disk but session-scoped caches are empty).

Some PyGhidra/Ghidra builds expose the domain tree from getRootFolder() on the
project handle; others only populate the tree under getProject().getProjectData().
We try both roots and merge unique entries by pathname.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.app.services.project import GhidraProject
    from ghidra.program.model.data import DomainFolder

logger = logging.getLogger(__name__)


def walk_domain_folder_tree(root_folder: DomainFolder, max_results: int) -> list[dict[str, Any]]:
    """Walk a DomainFolder recursively; return dicts compatible with list-project-files."""
    logger.debug("diag.enter %s", "mcp_server/domain_folder_listing.py:walk_domain_folder_tree")
    items: list[dict[str, Any]] = []

    def walk(folder: DomainFolder) -> None:
        nonlocal items
        if len(items) >= max_results:
            return

        try:
            for child in folder.getFolders():
                if len(items) >= max_results:
                    return
                items.append({"name": child.getName(), "path": str(child.getPathname()), "type": "Folder"})
                walk(child)
        except Exception as e:
            logger.debug("walk_domain_folder_tree: getFolders failed: %s", e)

        try:
            for domain_file in folder.getFiles():
                if len(items) >= max_results:
                    return
                content_type = str(domain_file.getContentType()) if hasattr(domain_file, "getContentType") else "unknown"
                items.append({"name": domain_file.getName(), "path": str(domain_file.getPathname()), "type": content_type})
        except Exception as e:
            logger.debug("walk_domain_folder_tree: getFiles failed: %s", e)

    walk(root_folder)
    return items


def _domain_root_folders(ghidra_project: GhidraProject) -> list[DomainFolder]:
    """Return distinct DomainFolder roots that may contain project files."""
    logger.debug("diag.enter %s", "mcp_server/domain_folder_listing.py:_domain_root_folders")
    roots: list[DomainFolder] = []
    seen: set[int] = set()

    def add(root: DomainFolder) -> None:
        if root is None:
            return
        rid = id(root)
        if rid in seen:
            return
        seen.add(rid)
        roots.append(root)

    try:
        add(ghidra_project.getRootFolder())
    except Exception as e:
        logger.debug("domain roots: getRootFolder failed: %s", e)

    try:
        proj = ghidra_project.getProject()
        if proj is not None:
            pd = proj.getProjectData()
            if pd is not None:
                add(pd.getRootFolder())
    except Exception as e:
        logger.debug("domain roots: getProject().getProjectData().getRootFolder failed: %s", e)

    return roots


def _resolve_subfolder(root: DomainFolder, normalized_folder: str) -> DomainFolder | None:
    """Resolve a folder under root; normalized_folder must match ProjectToolProvider._normalize_repo_path()."""
    logger.debug("diag.enter %s", "mcp_server/domain_folder_listing.py:_resolve_subfolder")
    if normalized_folder.strip() in ("", "/"):
        return root
    if not hasattr(root, "getFolder"):
        return None
    try:
        return root.getFolder(normalized_folder.lstrip("/"))
    except Exception:
        return None


def list_project_tree_from_ghidra(
    ghidra_project: GhidraProject,
    *,
    normalized_folder: str,
    max_results: int,
) -> list[dict[str, str | int]]:
    """Enumerate domain folders/files under each known project root, merging unique paths."""
    logger.debug("diag.enter %s", "mcp_server/domain_folder_listing.py:list_project_tree_from_ghidra")
    roots = _domain_root_folders(ghidra_project)
    if not roots:
        return []

    norm = (normalized_folder or "/").strip()
    if not norm.startswith("/"):
        norm = "/" + norm
    if norm != "/":
        norm = "/" + norm.lstrip("/")

    merged: list[dict[str, str | int]] = []
    seen_paths: set[str] = set()

    for root in roots:
        target = _resolve_subfolder(root, norm)
        if target is None:
            continue
        try:
            chunk = walk_domain_folder_tree(target, max_results)
        except Exception as e:
            logger.warning("list_project_tree_from_ghidra: walk failed for one root: %s", e)
            continue
        for item in chunk:
            p = str(item.get("path", item.get("name", "")) or "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            merged.append(item)
            if len(merged) >= max_results:
                return merged

    return merged
