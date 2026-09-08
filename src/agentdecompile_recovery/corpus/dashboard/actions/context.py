"""Page defaults for dashboard actions: store binaries and corpus env."""

from __future__ import annotations

from typing import Any

from agentdecompile_recovery.corpus.dashboard.actions.catalog import env_defaults
from agentdecompile_recovery.corpus.dashboard.common import query_db


def workbench_context() -> dict[str, Any]:
    defaults = env_defaults()
    rows, err = query_db(
        "SELECT slug, repo_path, role, func_count, named_count FROM binary ORDER BY slug"
    )
    binaries: list[dict[str, Any]] = []
    if not err:
        for slug, repo_path, role, funcs, named in rows:
            binaries.append(
                {
                    "slug": slug,
                    "repo": repo_path,
                    "program": repo_path or slug,
                    "role": role or "",
                    "funcs": int(funcs or 0),
                    "named": int(named or 0),
                }
            )
    return {
        "defaults": defaults,
        "binaries": binaries,
        "storeError": err,
    }
