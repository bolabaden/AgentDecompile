"""Load per-corpus settings from JSON. Scripts stay product-agnostic.

Python defaults are empty. JSON lives under ``AGENT_DECOMPILE_CORPUS_CONFIG_DIR``
or a caller-supplied directory. There is no repo-root default and no product
checkout guess for ``ctx.h``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# Not a repository root. Callers that need a workspace pass a Path or set
# AGENT_DECOMPILE_PROJECT_PATH / AGENT_DECOMPILE_CORPUS_CONFIG_DIR.
ROOT: Path | None = None


@dataclass
class ProgramConfig:
    program: str
    repo_path: str = ""
    known_globals: dict[str, str] = field(default_factory=dict)
    known_int_globals: list[str] = field(default_factory=list)
    ctx_h: str = ""
    donor: str = ""
    permuter_ctx_project: str = ""
    knowledge_dir: str = ""


def config_dir(explicit: Path | str | None = None) -> Path | None:
    if explicit is not None:
        return Path(explicit)
    override = os.environ.get("AGENT_DECOMPILE_CORPUS_CONFIG_DIR", "").strip()
    return Path(override) if override else None


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def program_config_path(program: str, config_dir_path: Path | str | None = None) -> Path | None:
    override = os.environ.get("CORPUS_CONFIG", "").strip()
    if override:
        return Path(override)
    root = config_dir(config_dir_path)
    if root is None or not program:
        return None
    return root / "programs" / f"{program}.json"


def load_program_config(program: str | None, config_dir_path: Path | str | None = None) -> ProgramConfig:
    name = (program or os.environ.get("CORPUS_PROGRAM") or "").strip()
    path = program_config_path(name, config_dir_path) if name else None
    raw = _read_json(path) if path is not None else {}
    ctx = str(raw.get("ctx_h") or raw.get("ctxH") or "")
    return ProgramConfig(
        program=name,
        repo_path=str(raw.get("repo_path") or raw.get("repoPath") or ""),
        known_globals=dict(raw.get("known_globals") or raw.get("knownGlobals") or {}),
        known_int_globals=list(raw.get("known_int_globals") or raw.get("knownIntGlobals") or []),
        ctx_h=ctx,
        donor=str(raw.get("donor") or ""),
        permuter_ctx_project=str(raw.get("permuter_ctx_project") or ""),
        knowledge_dir=str(raw.get("knowledge_dir") or ""),
    )


def load_match_pairs(config_dir_path: Path | str | None = None) -> list[tuple[str, str, str]]:
    env = os.environ.get("CORPUS_PAIRS", "").strip()
    root = config_dir(config_dir_path)
    path = Path(env) if env else (root / "pairs.json" if root is not None else None)
    raw = _read_json(path) if path is not None else {}
    rows = raw.get("pairs") if isinstance(raw.get("pairs"), list) else []
    out: list[tuple[str, str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        src = str(row.get("source") or row.get("src") or "")
        dst = str(row.get("target") or row.get("dst") or "")
        if src and dst:
            out.append((src, dst, str(row.get("reason") or "")))
    return out


def load_ghidra_server(config_dir_path: Path | str | None = None) -> dict[str, str | int]:
    env_host = os.environ.get("GHIDRA_SERVER_HOST", "").strip()
    env_port = os.environ.get("GHIDRA_SERVER_PORT", "").strip()
    env_repo = os.environ.get("GHIDRA_SERVER_REPOSITORY", "").strip()
    env_user = os.environ.get("GHIDRA_SERVER_USERNAME", "").strip()
    env_key = os.environ.get("GHIDRA_SERVER_SSH_KEY", "").strip()
    root = config_dir(config_dir_path)
    file_cfg = _read_json(root / "ghidra_server.json") if root is not None else {}
    port_raw = env_port or file_cfg.get("port") or 0
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 0
    return {
        "host": env_host or str(file_cfg.get("host") or "localhost"),
        "port": port,
        "repository": env_repo or str(file_cfg.get("repository") or ""),
        "username": env_user or str(file_cfg.get("username") or ""),
        "ssh_key": env_key or str(file_cfg.get("ssh_key") or ""),
    }


def load_maps(config_dir_path: Path | str | None = None) -> dict:
    root = config_dir(config_dir_path)
    if root is None:
        return {}
    return _read_json(root / "maps.json")


def leaf_to_repo(leaf: str, config_dir_path: Path | str | None = None) -> str:
    aliases = dict(load_maps(config_dir_path).get("leaf_to_repo") or {})
    if leaf in aliases:
        return str(aliases[leaf])
    cfg = load_program_config(leaf, config_dir_path)
    return cfg.repo_path


def repo_to_ctx_project(repo_path: str, config_dir_path: Path | str | None = None) -> str:
    mapped = dict(load_maps(config_dir_path).get("repo_to_ctx_project") or {})
    if repo_path in mapped:
        return str(mapped[repo_path])
    leaf = repo_path.rstrip("/").split("/")[-1]
    cfg = load_program_config(leaf, config_dir_path)
    return cfg.permuter_ctx_project or leaf


def repo_to_program_dir(repo_path: str, config_dir_path: Path | str | None = None) -> str:
    mapped = dict(load_maps(config_dir_path).get("repo_to_program_dir") or {})
    if repo_path in mapped:
        return str(mapped[repo_path])
    return repo_path.rstrip("/").split("/")[-1]


def repo_to_knowledge_dir(repo_path: str, config_dir_path: Path | str | None = None) -> str:
    mapped = dict(load_maps(config_dir_path).get("repo_to_knowledge_dir") or {})
    if repo_path in mapped:
        return str(mapped[repo_path])
    return repo_path.rstrip("/").split("/")[-1]


def verification_project(program: str, config_dir_path: Path | str | None = None) -> dict:
    raw = load_maps(config_dir_path).get("verification_projects") or {}
    row = raw.get(program) if isinstance(raw, dict) else None
    return dict(row) if isinstance(row, dict) else {}


def require_program(program: str | None) -> str:
    name = (program or os.environ.get("CORPUS_PROGRAM") or "").strip()
    if not name:
        raise SystemExit("program id required (--program or CORPUS_PROGRAM). There is no default binary.")
    return name


def resolve_repo_path(con, program: str, repo_arg: str | None = None, config_dir_path: Path | str | None = None) -> str:
    if repo_arg:
        return repo_arg
    cfg = load_program_config(program, config_dir_path)
    if cfg.repo_path:
        return cfg.repo_path
    row = con.execute(
        "SELECT repo_path FROM binary WHERE repo_path LIKE ? OR repo_path=?",
        (f"%/{program}", program),
    ).fetchone()
    if row:
        return str(row["repo_path"] if not isinstance(row, tuple) else row[0])
    path = program_config_path(program, config_dir_path)
    raise SystemExit(f"no repo_path for {program!r}: pass repo_path or set it in {path}")
