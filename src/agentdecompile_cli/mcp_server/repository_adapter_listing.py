"""Helpers for Ghidra ``RepositoryAdapter`` listing and folder-path quirks.

Some Ghidra Server / JPype combinations expose the repository root as ``""`` instead
of ``"/"``, so callers that only walk ``"/"`` or call ``getItem("/", name)`` see an
empty repository after a fresh JVM session even though check-ins succeeded.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


def repository_adapter_folder_candidates(folder_path: str) -> list[str]:
    """Folder strings to try for ``getItem`` / ``getItemList`` / ``checkout`` (root aliasing)."""
    fp = (folder_path or "/").strip() or "/"
    out: list[str] = []
    for c in (fp, "/", "", "."):
        if c not in out:
            out.append(c)
    return out


def canonical_repository_item_path(folder_path: str, name: str) -> str:
    """Normalize displayed path to a leading ``/`` form (session binaries)."""
    if not folder_path or folder_path in ("/", ".", ""):
        return f"/{name}"
    return f"{folder_path.rstrip('/')}/{name}"


def list_repository_adapter_items(
    repository_adapter: Any,
    *,
    log: logging.Logger | None = None,
    start_time: float | None = None,
) -> list[dict[str, Any]]:
    """Recursively list repository programs/folders, walking both ``/`` and ``""`` roots."""
    log = log or logger
    t0 = start_time if start_time is not None else time.time()
    items_by_key: dict[str, dict[str, Any]] = {}
    seen_list_calls: set[str] = set()

    def _walk(folder_path: str) -> None:
        if folder_path in seen_list_calls:
            return
        seen_list_calls.add(folder_path)
        log.info("shared-sync repository listing walking folder=%r", folder_path)
        try:
            subfolders: list[Any] = repository_adapter.getSubfolderList(folder_path) or []
        except Exception as exc:
            log.debug("getSubfolderList(%r) failed: %s", folder_path, exc)
            subfolders = []
        log.info("shared-sync repository listing folder=%r subfolders=%s", folder_path, len(subfolders))
        for subfolder in subfolders:
            subfolder_name = str(subfolder)
            if not folder_path or folder_path == "/" or folder_path == ".":
                next_path = f"/{subfolder_name}"
            else:
                next_path = f"{folder_path.rstrip('/')}/{subfolder_name}"
            _walk(next_path)

        try:
            repo_items: list[Any] = repository_adapter.getItemList(folder_path) or []
        except Exception as exc:
            log.debug("getItemList(%r) failed: %s", folder_path, exc)
            repo_items = []
        log.info("shared-sync repository listing folder=%r items=%s", folder_path, len(repo_items))
        for repo_item in repo_items:
            name = str(repo_item.getName()) if hasattr(repo_item, "getName") else str(repo_item)
            path = canonical_repository_item_path(folder_path, name)
            item_type = str(repo_item.getContentType()) if hasattr(repo_item, "getContentType") else "Program"
            lk = path.lower()
            if lk not in items_by_key:
                items_by_key[lk] = {"name": name, "path": path, "type": item_type}
            n = len(items_by_key)
            if n == 1 or n % 50 == 0:
                log.info(
                    "shared-sync repository listing progress discovered_items=%s elapsed_sec=%.2f",
                    n,
                    time.time() - t0,
                )

    # Ghidra Server / JPype sometimes uses "", ".", or "/" for the repository root; walk all.
    for root in ("/", "", "."):
        try:
            _walk(root)
        except Exception as exc:
            log.debug("repository walk from root=%r failed: %s", root, exc)

    out = sorted(items_by_key.values(), key=lambda d: (d.get("path") or "").lower())
    log.info("shared-sync repository listing complete total_items=%s elapsed_sec=%.2f", len(out), time.time() - t0)
    return out
