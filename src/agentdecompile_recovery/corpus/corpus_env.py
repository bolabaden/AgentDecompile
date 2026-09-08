"""Required-path helpers for corpus writers.

No default database or product tree. Callers pass Path arguments, or set
the documented environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path


class MissingCorpusPath(ValueError):
    """Raised when a required corpus path was neither passed nor configured."""


def env_path(name: str) -> Path | None:
    value = (os.environ.get(name) or "").strip()
    return Path(value) if value else None


def require_env_path(name: str) -> Path:
    path = env_path(name)
    if path is None:
        raise MissingCorpusPath(f"{name} is required")
    return path


def corpus_db_path(*, path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    return require_env_path("AGENT_DECOMPILE_CORPUS_DB")


def corpus_work_dir(*, path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    return require_env_path("AGENT_DECOMPILE_CORPUS_WORK_DIR")


def external_recovery_root(*, path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    return require_env_path("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT")


def knowledge_db_path(*, path: Path | str | None = None) -> Path | None:
    if path is not None:
        return Path(path)
    return env_path("AGENT_DECOMPILE_GHIDRA_KNOWLEDGE_DB")


def recovered_source_root(*, path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    root = env_path("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT")
    if root is not None:
        return root / "recovered-source"
    return Path("/work") / "recovered-source"
