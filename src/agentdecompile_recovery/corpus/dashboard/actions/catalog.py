"""Action catalog for the corpus dashboard and Swagger.

Every advertised MCP tool and every public corpus / recover / reconstruct
entrypoint is one cataloged action. The browser never sends a freeform argv.
Rows are generated from the live parsers — see introspect.py.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agentdecompile_recovery.corpus.dashboard.common import KNOWLEDGE_DB, live_db, live_root

PROGRAM_KEYS = frozenset({"programPath", "program", "binary", "path", "repo"})
ADDR_KEYS = frozenset({
    "address",
    "addressOrSymbol",
    "target",
    "function",
    "functionIdentifier",
    "identifier",
    "addr",
})
DB_KEYS = frozenset({"db"})
WORK_KEYS = frozenset({"work-dir", "work_dir", "out-dir", "out_dir", "outDir", "workspace"})
KB_KEYS = frozenset({"kb"})
REPO_KEYS = frozenset({"repo", "repo-path", "repo_path"})

DANGEROUS_CORPUS = frozenset({
    "force",
    "apply",
    "llm-cleanup",
    "watch",
})


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str = "str"
    required: bool = False
    flag: str | None = None
    choices: tuple[str, ...] = ()
    default: Any = None
    from_context: str | None = None
    help: str = ""
    positional: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        default = payload.get("default")
        if isinstance(default, Path):
            payload["default"] = str(default)
        elif default is not None and not isinstance(default, (str, int, float, bool, list, tuple, dict)):
            payload["default"] = str(default)
        return payload


@dataclass(frozen=True)
class ActionSpec:
    id: str
    title: str
    group: str
    backend: str
    command: str
    summary: str = ""
    fields: tuple[FieldSpec, ...] = ()
    pages: tuple[str, ...] = ("work",)
    danger: bool = False
    mutating: bool = False
    long_running: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["fields"] = [field.to_dict() for field in self.fields]
        return payload


_ACTIONS: list[ActionSpec] | None = None


def list_actions() -> list[ActionSpec]:
    global _ACTIONS
    if _ACTIONS is None:
        from agentdecompile_recovery.corpus.dashboard.actions.introspect import generate_actions

        _ACTIONS = generate_actions()
    return _ACTIONS


def action_by_id(action_id: str) -> ActionSpec | None:
    for action in list_actions():
        if action.id == action_id:
            return action
    return None


def env_defaults() -> dict[str, str]:
    db = live_db()
    root = live_root()
    kb = KNOWLEDGE_DB
    mcp = (
        os.environ.get("AGENT_DECOMPILE_MCP_SERVER_URL")
        or os.environ.get("AGENTDECOMPILE_MCP_SERVER_URL")
        or "http://127.0.0.1:8080/mcp"
    )
    return {
        "db": str(db) if db else "",
        "work_dir": str(root) if root else "",
        "kb": str(kb) if kb else "",
        "mcp_url": mcp,
    }


def apply_defaults(action: ActionSpec, params: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fill empty fields from page context and corpus environment."""
    merged = dict(params)
    ctx = {**(env_defaults()), **(context or {})}
    alias = {
        "program": ctx.get("program") or ctx.get("slug") or ctx.get("repo") or "",
        "slug": ctx.get("slug") or "",
        "addr": ctx.get("addr") or ctx.get("address") or "",
        "name": ctx.get("name") or "",
        "repo": ctx.get("repo") or ctx.get("program") or "",
        "db": ctx.get("db") or "",
        "work_dir": ctx.get("work_dir") or ctx.get("out_dir") or "",
        "kb": ctx.get("kb") or "",
    }
    for spec in action.fields:
        current = merged.get(spec.name)
        if current not in (None, ""):
            continue
        if spec.default not in (None, "", False, True, [], ()):
            merged[spec.name] = spec.default
            continue
        key = spec.from_context
        if key and alias.get(key):
            merged[spec.name] = alias[key]
    return merged


def validate_params(action: ActionSpec, params: dict[str, Any], *, confirm: bool = False) -> list[str]:
    errors: list[str] = []
    if action.danger and not confirm:
        errors.append(f"{action.id} changes program or corpus state; set confirm=true to run it")
    for spec in action.fields:
        value = params.get(spec.name)
        if spec.required and value in (None, "", False):
            errors.append(f"{spec.name} is required")
            continue
        if value in (None, ""):
            continue
        if spec.choices and str(value) not in spec.choices:
            errors.append(f"{spec.name} must be one of {', '.join(spec.choices)}")
        if spec.kind == "int":
            try:
                int(value)
            except (TypeError, ValueError):
                errors.append(f"{spec.name} must be an integer")
        if spec.kind == "float":
            try:
                float(value)
            except (TypeError, ValueError):
                errors.append(f"{spec.name} must be a number")
        if spec.kind == "path" and "\x00" in str(value):
            errors.append(f"{spec.name} is not a usable path")
        if spec.name in DANGEROUS_CORPUS and value not in (None, "", False) and not confirm:
            errors.append(f"{spec.name} is a destructive option; set confirm=true")
    return errors


def _cli_entry(script: str, dotted: str) -> list[str]:
    """Prefer the installed console script; fall back to an in-process launcher."""
    import shutil

    found = shutil.which(script)
    if found:
        return [found]
    module, name = dotted.split(":")
    return [
        sys.executable,
        "-c",
        (
            "import sys;"
            f"from {module} import {name} as _entry;"
            "sys.argv = [sys.argv[0]] + sys.argv[1:];"
            "raise SystemExit(_entry() if _entry.__code__.co_argcount == 0 "
            "else _entry(sys.argv[1:]))"
        ),
    ]


def _module_launcher(module: str) -> list[str]:
    return _cli_entry(
        {
            "agentdecompile_recovery.corpus.cli": "agentdecompile-corpus",
            "agentdecompile_recovery.frontdoor": "agentdecompile-reconstruct",
            "agentdecompile_recovery.cli": "agentdecompile-recover",
        }.get(module, module),
        f"{module}:main",
    )


def build_command(action: ActionSpec, params: dict[str, Any]) -> list[str]:
    """Return the exact argv that will run. Never interpolates a shell string."""
    if action.backend == "mcp-cli":
        arguments = {
            spec.name: params[spec.name]
            for spec in action.fields
            if spec.name in params and params[spec.name] not in (None, "")
        }
        mcp_url = env_defaults()["mcp_url"]
        return [
            *_cli_entry("agentdecompile-cli", "agentdecompile_cli.cli:cli_entry_point"),
            "--mcp-server-url",
            mcp_url,
            "tool",
            action.command,
            json.dumps(arguments, separators=(",", ":")),
        ]

    if action.backend == "corpus-cli":
        argv = [*_module_launcher("agentdecompile_recovery.corpus.cli"), action.command]
    elif action.backend == "recover-cli":
        argv = [*_module_launcher("agentdecompile_recovery.cli"), action.command]
    elif action.backend == "reconstruct-cli":
        argv = [*_module_launcher("agentdecompile_recovery.frontdoor")]
        if action.command:
            argv.append(action.command)
    elif action.backend == "click-cli":
        argv = [*_cli_entry("agentdecompile-cli", "agentdecompile_cli.cli:cli_entry_point")]
        if action.command:
            argv.append(action.command)
    else:
        raise ValueError(f"unknown backend {action.backend}")

    extra: list[str] = []
    for spec in action.fields:
        value = params.get(spec.name)
        if value in (None, ""):
            continue
        if spec.name == "argv":
            extra = shlex.split(str(value))
            continue
        if spec.kind == "bool":
            if value in (True, "true", "1", "yes", "on"):
                argv.append(spec.flag or f"--{spec.name}")
            continue
        if spec.positional:
            argv.append(str(value))
            continue
        argv.extend([spec.flag or f"--{spec.name}", str(value)])
    argv.extend(extra)
    return argv
