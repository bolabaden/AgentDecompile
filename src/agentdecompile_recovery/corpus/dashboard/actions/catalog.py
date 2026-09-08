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
# CLI flags that must be a file (PE/ELF/Mach-O), never a shared-fs repos folder.
FILE_BINARY_FIELDS = frozenset({"binary", "input"})

DANGEROUS_CORPUS = frozenset({
    "force",
    "apply",
    "llm-cleanup",
    "watch",
})

DANGEROUS_ARGV_FLAGS = frozenset({
    "--force",
    "--apply",
    "-f",
    "--llm-cleanup",
    "--watch",
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
    schema: dict[str, Any] | None = None

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

        _ACTIONS = generate_actions() + [ActionSpec(
            id="workbench.prepare", title="Prepare project", group="workbench",
            backend="preparation", command="prepare", mutating=True, long_running=True,
            summary="Automatically prepare, compare, and recover without a wall-time limit by default. Optional finite budgets and per-function attempt limits remain available. Completion is not proof.",
            fields=tuple(FieldSpec(name, from_context=name) for name in ("locator", "program", "slug")) + (FieldSpec("resume", kind="bool", default=False),),
        ), ActionSpec(
            id="workbench.merge-evidence", title="Bind compared knowledge", group="workbench",
            backend="merge-evidence", command="merge-evidence", mutating=True,
            summary="Bind accepted matches without rebuilding existing identities. Fill missing source attribution while retaining human metadata.",
            fields=(FieldSpec("db", required=True, from_context="db"), FieldSpec("run", required=True)),
        ), ActionSpec(
            id="workbench.workflow-control", title="Adjust automatic workflow", group="workbench",
            backend="workflow-control", command="workflow-control", mutating=True,
            summary="Pause, resume, stop, or adjust the remaining workflow budget. Set unlimited=true to remove its wall-time limit. Accepted native operations drain before stopping.",
            fields=(FieldSpec("preparation_id", required=True), FieldSpec("operation", required=True, choices=("pause", "resume", "stop", "budget", "priority")), FieldSpec("seconds", kind="int"), FieldSpec("unlimited", kind="bool"), FieldSpec("priority", kind="int")),
        ), ActionSpec(
            id="workbench.activity-snapshot", title="Read workspace activity", group="workbench",
            backend="activity-snapshot", command="activity-snapshot",
            summary="Read entity activity, progress, queue state, and receipt-backed evidence.",
            fields=(FieldSpec("locator", from_context="locator"), FieldSpec("slug", from_context="slug")),
        ), ActionSpec(
            id="workbench.export-source-zip", title="Download binary source ZIP", group="workbench",
            backend="source-archive", command="source-archive", long_running=True,
            summary="Export whole-program decompiled C and available source witnesses with an inventory and coverage manifest. Compilation and byte verification remain separate.",
            fields=(FieldSpec("slug", required=True, from_context="slug"), FieldSpec("locator", from_context="locator"), FieldSpec("program", from_context="program")),
        ), ActionSpec(
            id="workbench.commit-signatures", title="Commit similarity signatures", group="workbench",
            backend="bsim-cli", command="commitsigs", mutating=True, danger=True, long_running=True,
            summary="Import generated BSim signature XML without opening a Ghidra project.",
            fields=(FieldSpec("bsimUrl", required=True), FieldSpec("signatureDirectory", kind="path", required=True)),
        )]
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
    if kb is None:
        ghidra_kb = os.environ.get("AGENT_DECOMPILE_GHIDRA_KNOWLEDGE_DB", "").strip()
        if ghidra_kb:
            kb = Path(ghidra_kb).expanduser()
        elif root is not None:
            kb = root / "ghidra_knowledge.sqlite"
        else:
            kb = Path("ghidra_knowledge.sqlite")
    mcp = (
        os.environ.get("AGENT_DECOMPILE_MCP_URL")
        or os.environ.get("AGENT_DECOMPILE_MCP_SERVER_URL")
        or os.environ.get("AGENTDECOMPILE_MCP_SERVER_URL")
        or f"http://127.0.0.1:{os.environ.get('AGENT_DECOMPILE_PORT', '8080')}/mcp"
    )
    return {
        "db": str(db) if db else "",
        "work_dir": str(root) if root else "",
        "report_file": str(root / "recovery-report.json") if root else "",
        "kb": str(kb) if kb else "",
        "mcp_url": mcp,
    }


def apply_defaults(action: ActionSpec, params: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fill empty fields from page context and corpus environment."""
    merged = dict(params)
    if action.backend == "mcp-cli":
        from agentdecompile_cli.registry import normalize_identifier
        canonical = {normalize_identifier(spec.name): spec.name for spec in action.fields}
        for key, value in params.items():
            target = canonical.get(normalize_identifier(key))
            if target and target != key:
                merged.pop(key, None)
                if target not in params:
                    merged[target] = value
    ctx = dict(env_defaults())
    if context:
        for key, value in context.items():
            if value not in (None, ""):
                ctx[key] = value
    alias = {
        "program": ctx.get("program") or ctx.get("slug") or ctx.get("repo") or "",
        "slug": ctx.get("slug") or "",
        "addr": ctx.get("addr") or ctx.get("address") or "",
        "name": ctx.get("name") or "",
        "repo": ctx.get("repo") or ctx.get("program") or ctx.get("slug") or "",
        "db": ctx.get("db") or "",
        "work_dir": ctx.get("work_dir") or ctx.get("out_dir") or "",
        "kb": ctx.get("kb") or "",
        "report_file": ctx.get("report_file") or "",
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
    if ctx.get("locator"):
        merged["locator"] = ctx["locator"]
    _rewrite_file_binary_params(action, merged, ctx)
    _drop_shared_fs_project(merged)
    return merged


def _drop_shared_fs_project(merged: dict[str, Any]) -> None:
    """shared-fs repos folders are not --project for reconstruct."""
    raw = str(merged.get("project") or "").strip()
    if not raw or raw.startswith("ghidra://") or raw.lower().endswith(".gpr"):
        return
    path = Path(raw)
    if not path.is_dir():
        return
    if (path / "~index.dat").is_file() or (path / "idata").is_dir() or (path / "data").is_dir():
        return
    merged.pop("project", None)
    merged.pop("project-program", None)


def _rewrite_file_binary_params(
    action: ActionSpec, merged: dict[str, Any], ctx: dict[str, Any]
) -> None:
    """Shared-fs locators are directories. File verbs need the program PE."""
    program = str(ctx.get("program") or merged.get("program") or merged.get("from") or "").strip()
    work_dir = str(ctx.get("work_dir") or merged.get("work-dir") or merged.get("out-dir") or "").strip()
    locator = str(
        ctx.get("locator")
        or ctx.get("repo")
        or merged.get("repository")
        or merged.get("repo")
        or ""
    ).strip()
    resolved = _resolve_program_file(program, work_dir, locator)
    locator_name = Path(locator).name if locator else ""
    for spec in action.fields:
        if spec.name not in FILE_BINARY_FIELDS:
            continue
        current = merged.get(spec.name)
        path = Path(str(current)) if current not in (None, "") else None
        if path is not None and path.is_file():
            continue
        if resolved is not None:
            merged[spec.name] = str(resolved)
        elif path is not None and path.is_dir():
            # Keep the directory so validate_params can name it; do not invent a path.
            pass
    if action.id == "corpus.extract-stabs":
        ident = str(merged.get("id") or "").strip()
        if program and (not ident or ident == locator_name):
            merged["id"] = program


def _resolve_program_file(program: str, work_dir: str, locator: str) -> Path | None:
    name = (program or "").strip()
    if not name:
        return None
    roots: list[Path] = []
    if work_dir:
        roots.append(Path(work_dir) / "imports")
        roots.append(Path(work_dir))
    if locator:
        loc = Path(locator)
        if loc.is_dir():
            roots.append(loc)
    suffix = "__" + name
    for root in roots:
        exact = root / name
        if exact.is_file():
            return exact
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_file():
                continue
            if child.name == name or child.name.endswith(suffix):
                return child
    return None


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
        if spec.kind == "array" and not isinstance(value, list):
            errors.append(f"{spec.name} must be a JSON array")
        if spec.kind == "object" and not isinstance(value, dict):
            errors.append(f"{spec.name} must be a JSON object")
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
        if spec.name in FILE_BINARY_FIELDS and spec.kind == "path":
            try:
                as_path = Path(str(value))
            except (TypeError, ValueError):
                as_path = None
            if as_path is not None and as_path.is_dir():
                errors.append(
                    f"{spec.name} is a directory ({as_path}); pass the program PE "
                    "or Ghidra program file, not the shared-fs repos folder"
                )
        if spec.name in DANGEROUS_CORPUS and value not in (None, "", False) and not confirm:
            errors.append(f"{spec.name} is a destructive option; set confirm=true")
    argv_val = params.get("argv")
    if argv_val not in (None, ""):
        for token in shlex.split(str(argv_val)):
            flag = token.split("=", 1)[0]
            if flag in DANGEROUS_ARGV_FLAGS and not confirm:
                errors.append("argv contains destructive flags; set confirm=true")
                break
    return errors


def _cli_entry(script: str, dotted: str) -> list[str]:
    """Run this tree's package through the dashboard interpreter.

    ``shutil.which`` would pick ``~/.local/bin`` and skip workspace fixes.
    """
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
    if action.backend == "bsim-cli":
        from agentdecompile_recovery.corpus.bsim_ops import find_bsim_launcher
        launcher = find_bsim_launcher()
        if launcher is None:
            raise ValueError("Ghidra support/bsim not found; configure GHIDRA_INSTALL_DIR")
        return [str(launcher), "commitsigs", str(params["bsimUrl"]), str(params["signatureDirectory"])]
    if action.backend in {"workflow-control", "activity-snapshot", "merge-evidence", "source-archive"}:
        return [action.id]
    if action.backend == "preparation":
        return ["workbench.prepare"]
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
