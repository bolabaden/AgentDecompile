"""Build the Ghidra URL for a binary: shared server or local project.

``extract.resolve_source`` maps a repo path through ``maps.json``
``local_sources`` (empty by default). Server host/port/repository come from
``corpus_config.load_ghidra_server``. Path segments are encoded separately so
spaces do not produce an "Invalid Ghidra URL".
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from .corpus_config import load_ghidra_server
from .extract import resolve_source


def ghidra_url(
    repo_path: str,
    *,
    workspace: Path | str | None = None,
    config_dir_path: Path | str | None = None,
) -> str:
    src = resolve_source(repo_path, workspace=workspace)
    if not src.startswith("local:"):
        encoded = "/".join(quote(seg, safe="") for seg in src.split("/"))
        cfg = load_ghidra_server(config_dir_path)
        host = str(cfg.get("host") or "localhost")
        port = int(cfg.get("port") or 0)
        repo = str(cfg.get("repository") or "")
        return f"ghidra://{host}:{port}/{repo}{encoded}"
    _tag, projdir, projname, inner = src.split(":", 3)
    return f"ghidra:{projdir}/{projname}?{inner}"


def is_local(repo_path: str, *, workspace: Path | str | None = None) -> bool:
    return resolve_source(repo_path, workspace=workspace).startswith("local:")
