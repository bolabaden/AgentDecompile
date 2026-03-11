#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import os
import queue
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import jedi


def _path_to_uri(path: Path) -> str:
    return path.resolve().as_uri()


def _uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        raise ValueError(f"Unsupported URI scheme: {uri}")
    netloc = f"//{parsed.netloc}" if parsed.netloc else ""
    return Path(url2pathname(f"{netloc}{parsed.path}"))


def _sanitize_node_id(value: str) -> str:
    cleaned = []
    for char in value:
        if char.isalnum() or char == "_":
            cleaned.append(char)
        else:
            cleaned.append("_")
    return "".join(cleaned)


def _module_name_for(root: Path, file_path: Path) -> str:
    relative = file_path.resolve().relative_to(root.resolve()).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else root.name


def _resolve_input_paths(paths: list[Path]) -> list[Path]:
    resolved: list[Path] = []
    for path in paths:
        current = path.resolve()
        if current.is_dir():
            resolved.extend(sorted(p for p in current.rglob("*.py") if p.is_file()))
        elif current.is_file() and current.suffix == ".py":
            resolved.append(current)
    return sorted(dict.fromkeys(resolved))


def _default_root(paths: list[Path]) -> Path:
    resolved = [path.resolve() for path in paths]
    if not resolved:
        raise ValueError("No input paths were provided")
    common = Path(os.path.commonpath([str(path) for path in resolved]))
    if common.is_file():
        return common.parent
    return common


def _detect_jedi_lsp_command() -> list[str]:
    scripts_dir = Path(sys.executable).resolve().parent
    candidates = [
        scripts_dir / "jedi-language-server.exe",
        scripts_dir / "jedi-language-server",
    ]
    for candidate in candidates:
        if candidate.exists():
            return [str(candidate)]
    return [sys.executable, "-m", "jedi_language_server.cli"]


@dataclass(slots=True)
class SymbolRecord:
    node_id: str
    kind: str
    qualname: str
    display_name: str
    module_name: str
    file_path: str
    line: int
    column: int
    parent_id: str | None


@dataclass(slots=True)
class CallSite:
    source_id: str
    source_qualname: str
    file_path: str
    line: int
    column: int
    callee_expr: str
    class_id: str | None


@dataclass(slots=True)
class FileAnalysis:
    file_path: str
    module_name: str
    symbols: list[SymbolRecord]
    contains: list[EdgeRecord]
    imports: list[EdgeRecord]
    calls: list[CallSite]
    bindings: dict[str, str]
    class_members: dict[str, dict[str, str]]


@dataclass(slots=True)
class EdgeRecord:
    kind: str
    source: str
    target: str
    label: str | None = None


class _SourceAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: Path, root: Path) -> None:
        self.file_path = file_path
        self.root = root
        self.module_name = _module_name_for(root, file_path)
        self.module_id = f"module::{self.module_name}"
        self.module_symbol = SymbolRecord(
            node_id=self.module_id,
            kind="module",
            qualname=self.module_name,
            display_name=self.module_name,
            module_name=self.module_name,
            file_path=str(self.file_path),
            line=1,
            column=0,
            parent_id=None,
        )
        self.symbols: list[SymbolRecord] = [self.module_symbol]
        self.contains: list[EdgeRecord] = []
        self.imports: list[EdgeRecord] = []
        self.calls: list[CallSite] = []
        self.bindings: dict[str, str] = {self.module_name.split(".")[-1]: self.module_id}
        self.class_members: dict[str, dict[str, str]] = {}
        self._stack: list[SymbolRecord] = [self.module_symbol]

    def current_symbol(self) -> SymbolRecord:
        return self._stack[-1]

    def _push_symbol(self, node: ast.AST, kind: str, name: str) -> SymbolRecord:
        parent = self.current_symbol()
        qualname = f"{parent.qualname}.{name}" if parent.kind != "module" else f"{self.module_name}.{name}"
        record = SymbolRecord(
            node_id=qualname,
            kind=kind,
            qualname=qualname,
            display_name=name,
            module_name=self.module_name,
            file_path=str(self.file_path),
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0),
            parent_id=parent.node_id,
        )
        self.symbols.append(record)
        if parent.kind == "module":
            self.bindings[name] = record.node_id
        elif parent.kind == "class":
            members = self.class_members.setdefault(parent.node_id, {})
            members[name] = record.node_id
        self.contains.append(EdgeRecord(kind="contains", source=parent.node_id, target=record.node_id))
        self._stack.append(record)
        return record

    def _pop_symbol(self) -> None:
        self._stack.pop()

    def _resolve_import_target(self, module: str | None, level: int, name: str | None = None) -> str | None:
        if level > 0:
            current_parts = self.module_name.split(".")
            if self.file_path.name == "__init__.py":
                base_parts = current_parts
            else:
                base_parts = current_parts[:-1]
            if level - 1 > len(base_parts):
                return None
            base_parts = base_parts[: len(base_parts) - (level - 1)]
        else:
            base_parts = []

        target_parts = list(base_parts)
        if module:
            target_parts.extend(module.split("."))
        if name:
            target_parts.append(name)
        return ".".join(part for part in target_parts if part)

    def _call_position(self, func: ast.expr) -> tuple[int, int]:
        if isinstance(func, ast.Name):
            return func.lineno, func.col_offset
        if isinstance(func, ast.Attribute):
            end_col = getattr(func, "end_col_offset", func.col_offset + len(func.attr))
            return func.end_lineno or func.lineno, max(func.col_offset, end_col - len(func.attr))
        return getattr(func, "lineno", 1), getattr(func, "col_offset", 0)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._push_symbol(node, "class", node.name)
        self.generic_visit(node)
        self._pop_symbol()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        kind = "method" if self.current_symbol().kind == "class" else "function"
        self._push_symbol(node, kind, node.name)
        self.generic_visit(node)
        self._pop_symbol()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        kind = "method" if self.current_symbol().kind == "class" else "function"
        self._push_symbol(node, kind, node.name)
        self.generic_visit(node)
        self._pop_symbol()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target = alias.name.strip()
            if target:
                self.imports.append(EdgeRecord(kind="imports", source=self.module_id, target=f"module::{target}"))
                binding_name = alias.asname or target.split(".", 1)[0]
                self.bindings[binding_name] = f"module::{target}"
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module_target = self._resolve_import_target(node.module, node.level)
        for alias in node.names:
            if alias.name == "*":
                continue
            target = module_target or self._resolve_import_target(node.module, node.level, alias.name)
            if target:
                self.imports.append(EdgeRecord(kind="imports", source=self.module_id, target=f"module::{target}"))
            if module_target:
                self.bindings[alias.asname or alias.name] = f"{module_target}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        line, column = self._call_position(node.func)
        try:
            callee_expr = ast.unparse(node.func)
        except Exception:
            callee_expr = type(node.func).__name__
        self.calls.append(
            CallSite(
                source_id=self.current_symbol().node_id,
                source_qualname=self.current_symbol().qualname,
                file_path=str(self.file_path),
                line=line,
                column=column,
                callee_expr=callee_expr,
                class_id=self.current_symbol().node_id if self.current_symbol().kind in {"class", "method"} else (self.current_symbol().parent_id if self.current_symbol().kind == "method" else None),
            )
        )
        self.generic_visit(node)

    def build(self) -> FileAnalysis:
        return FileAnalysis(
            file_path=str(self.file_path),
            module_name=self.module_name,
            symbols=self.symbols,
            contains=self.contains,
            imports=self.imports,
            calls=self.calls,
            bindings=self.bindings,
            class_members=self.class_members,
        )


class LspClient:
    def __init__(self, root: Path, command: list[str], timeout: float) -> None:
        self.root = root
        self.command = command
        self.timeout = timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._next_id = 1
        self._lock = threading.Lock()
        self._stderr_lines: list[str] = []

    def start(self) -> None:
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("Failed to start Jedi language server")

        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()
        if self._proc.stderr is not None:
            self._stderr_reader = threading.Thread(target=self._stderr_loop, daemon=True)
            self._stderr_reader.start()
        self.request(
            "initialize",
            {
                "processId": os.getpid(),
                "rootUri": _path_to_uri(self.root),
                "capabilities": {},
                "clientInfo": {"name": "python-lsp-mermaid", "version": "1.0"},
                "workspaceFolders": [{"uri": _path_to_uri(self.root), "name": self.root.name}],
            },
        )
        self.notify("initialized", {})

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self.request("shutdown", None)
        except Exception:
            pass
        try:
            self.notify("exit", None)
        except Exception:
            pass
        self._proc.terminate()
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def notify(self, method: str, params: dict[str, Any] | None) -> None:
        self._write_message({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict[str, Any] | None) -> Any:
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        result_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        self._pending[request_id] = result_queue
        self._write_message({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        try:
            response = result_queue.get(timeout=self.timeout)
        except queue.Empty as exc:
            stderr_text = "\n".join(self._stderr_lines[-10:]).strip()
            detail = f"\nStderr:\n{stderr_text}" if stderr_text else ""
            raise TimeoutError(f"Timed out waiting for LSP response to {method}{detail}") from exc
        finally:
            self._pending.pop(request_id, None)
        if "error" in response:
            raise RuntimeError(f"LSP error for {method}: {response['error']}")
        return response.get("result")

    def _write_message(self, payload: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("LSP client is not running")
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._proc.stdin.write(header)
        self._proc.stdin.write(body)
        self._proc.stdin.flush()

    def _reader_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        while True:
            headers: dict[str, str] = {}
            while True:
                line = stream.readline()
                if not line:
                    return
                if line == b"\r\n":
                    break
                key, _, value = line.decode("ascii", errors="replace").partition(":")
                headers[key.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            if length <= 0:
                continue
            body = stream.read(length)
            if not body:
                return
            payload = json.loads(body.decode("utf-8"))
            if "id" in payload:
                pending = self._pending.get(int(payload["id"]))
                if pending is not None:
                    pending.put(payload)

    def _stderr_loop(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        while True:
            line = self._proc.stderr.readline()
            if not line:
                return
            self._stderr_lines.append(line.decode("utf-8", errors="replace").rstrip())


class JediFallbackResolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = jedi.Project(path=str(root))

    def resolve(self, file_path: Path, line: int, column: int) -> tuple[Path, int, int] | None:
        script = jedi.Script(path=str(file_path), project=self.project)
        try:
            definitions = script.goto(line=line, column=column, follow_imports=True, follow_builtin_imports=False)
        except Exception:
            return None
        for definition in definitions:
            module_path = getattr(definition, "module_path", None)
            if module_path is None:
                continue
            candidate = Path(module_path).resolve()
            if self.root not in candidate.parents and candidate != self.root:
                continue
            def_line = getattr(definition, "line", None)
            def_column = getattr(definition, "column", None)
            if def_line is None or def_column is None:
                continue
            return candidate, int(def_line), int(def_column)
        return None


class MermaidGraphBuilder:
    def __init__(self, root: Path, include_imports: bool = True) -> None:
        self.root = root
        self.include_imports = include_imports
        self.symbols: dict[str, SymbolRecord] = {}
        self.edges: list[EdgeRecord] = []
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._symbols_by_file: dict[Path, list[SymbolRecord]] = {}
        self._file_analysis: dict[Path, FileAnalysis] = {}

    def add_file(self, file_path: Path) -> list[CallSite]:
        source = file_path.read_text(encoding="utf-8")
        analyzer = _SourceAnalyzer(file_path=file_path, root=self.root)
        analyzer.visit(ast.parse(source, filename=str(file_path)))
        analysis = analyzer.build()
        self._file_analysis[file_path.resolve()] = analysis
        for symbol in analysis.symbols:
            self.symbols[symbol.node_id] = symbol
            self._symbols_by_file.setdefault(Path(symbol.file_path).resolve(), []).append(symbol)
        for edge in analysis.contains:
            self._add_edge(edge)
        if self.include_imports:
            for edge in analysis.imports:
                self._add_edge(edge)
        return analysis.calls

    def _add_edge(self, edge: EdgeRecord) -> None:
        key = (edge.kind, edge.source, edge.target)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(edge)

    def resolve_target_symbol(self, file_path: Path, line: int, column: int) -> SymbolRecord | None:
        candidates = sorted(
            self._symbols_by_file.get(file_path.resolve(), []),
            key=lambda symbol: (symbol.line, symbol.column, len(symbol.qualname)),
        )
        if not candidates:
            return None
        for symbol in candidates:
            if symbol.line == line and symbol.column == column:
                return symbol
        for symbol in candidates:
            if symbol.line == line:
                return symbol
        return candidates[0] if candidates else None

    def add_call_edge(self, source_id: str, target_id: str) -> None:
        if source_id not in self.symbols or target_id not in self.symbols:
            return
        self._add_edge(EdgeRecord(kind="calls", source=source_id, target=target_id))

    def add_placeholder_call(self, source_id: str, source_module_name: str, callee_expr: str) -> str:
        placeholder_name = callee_expr.strip() or "<unknown>"
        node_id = f"external::{placeholder_name}"
        if node_id not in self.symbols:
            self.symbols[node_id] = SymbolRecord(
                node_id=node_id,
                kind="external",
                qualname=node_id,
                display_name=placeholder_name,
                module_name="[external]",
                file_path="",
                line=0,
                column=0,
                parent_id=None,
            )
        self._add_edge(EdgeRecord(kind="calls", source=source_id, target=node_id))
        return node_id

    def resolve_symbol_id(self, symbol_id: str) -> SymbolRecord | None:
        direct = self.symbols.get(symbol_id)
        if direct is not None:
            return direct
        if symbol_id.startswith("module::"):
            return self.symbols.get(symbol_id)
        module_candidate = self.symbols.get(f"module::{symbol_id}")
        if module_candidate is not None:
            return module_candidate
        return None

    def resolve_call_locally(self, call_site: CallSite) -> SymbolRecord | None:
        analysis = self._file_analysis.get(Path(call_site.file_path).resolve())
        if analysis is None:
            return None

        expr = call_site.callee_expr.strip()
        if not expr:
            return None

        if "." not in expr:
            if call_site.class_id is not None:
                member = analysis.class_members.get(call_site.class_id, {}).get(expr)
                if member is not None:
                    return self.resolve_symbol_id(member)
            binding = analysis.bindings.get(expr)
            if binding is not None:
                return self.resolve_symbol_id(binding)
            return None

        segments = expr.split(".")
        if len(segments) < 2:
            return None

        prefix = segments[0]
        suffix = segments[1:]

        if prefix in {"self", "cls"} and call_site.class_id is not None:
            candidate = call_site.class_id
            for segment in suffix:
                candidate = f"{candidate}.{segment}"
            return self.resolve_symbol_id(candidate)

        binding = analysis.bindings.get(prefix)
        if binding is None:
            return None

        if binding.startswith("module::"):
            candidate = binding[len("module::") :]
        else:
            candidate = binding
        for segment in suffix:
            candidate = f"{candidate}.{segment}"
        return self.resolve_symbol_id(candidate)

    def render_mermaid(self, direction: str = "TD") -> str:
        lines = [f"flowchart {direction}"]
        lines.append("  classDef module fill:#eef5ff,stroke:#336699,stroke-width:1px")
        lines.append("  classDef class fill:#eefbe7,stroke:#2d6a4f,stroke-width:1px")
        lines.append("  classDef function fill:#fff4e6,stroke:#9c6644,stroke-width:1px")
        lines.append("  classDef method fill:#fff0f6,stroke:#a61e4d,stroke-width:1px")
        lines.append("  classDef external fill:#f8f9fa,stroke:#495057,stroke-dasharray: 4 2")

        modules: dict[str, list[SymbolRecord]] = {}
        for symbol in self.symbols.values():
            modules.setdefault(symbol.module_name, []).append(symbol)

        for module_name in sorted(modules):
            module_node_id = _sanitize_node_id(f"module_{module_name}")
            lines.append(f"  subgraph {module_node_id}[{module_name}]")
            for symbol in sorted(modules[module_name], key=lambda item: (item.line, item.column, item.qualname)):
                node_id = _sanitize_node_id(symbol.node_id)
                label = symbol.display_name if symbol.kind != "module" else module_name
                if symbol.kind in {"function", "method"}:
                    label = f"{label}()"
                lines.append(f"    {node_id}[\"{label}\"]")
                lines.append(f"    class {node_id} {symbol.kind}")
            lines.append("  end")

        for edge in sorted(self.edges, key=lambda item: (item.kind, item.source, item.target)):
            source = _sanitize_node_id(edge.source)
            target = _sanitize_node_id(edge.target)
            if edge.kind == "imports":
                if edge.source not in self.symbols or edge.target not in self.symbols:
                    continue
                lines.append(f"  {source} -. imports .-> {target}")
            elif edge.kind == "contains":
                lines.append(f"  {source} --> {target}")
            elif edge.kind == "calls":
                lines.append(f"  {source} ==> {target}")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "symbols": [asdict(symbol) for symbol in sorted(self.symbols.values(), key=lambda item: item.qualname)],
            "edges": [asdict(edge) for edge in sorted(self.edges, key=lambda item: (item.kind, item.source, item.target))],
        }


def _open_documents(lsp: LspClient, files: list[Path]) -> None:
    for file_path in files:
        lsp.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": _path_to_uri(file_path),
                    "languageId": "python",
                    "version": 1,
                    "text": file_path.read_text(encoding="utf-8"),
                }
            },
        )


def _resolve_with_lsp(lsp: LspClient, file_path: Path, line: int, column: int) -> tuple[Path, int, int] | None:
    result = lsp.request(
        "textDocument/definition",
        {
            "textDocument": {"uri": _path_to_uri(file_path)},
            "position": {"line": line - 1, "character": column},
        },
    )
    if not result:
        return None
    locations = result if isinstance(result, list) else [result]
    for location in locations:
        uri = location.get("uri") or location.get("targetUri")
        range_data = location.get("range") or location.get("targetRange")
        if not uri or not isinstance(range_data, dict):
            continue
        target_path = _uri_to_path(uri).resolve()
        start = range_data.get("start", {})
        return target_path, int(start.get("line", 0)) + 1, int(start.get("character", 0))
    return None


def analyze_project(
    paths: list[Path],
    root: Path,
    include_imports: bool,
    lsp_timeout: float,
) -> tuple[MermaidGraphBuilder, dict[str, int]]:
    files = _resolve_input_paths(paths)
    if not files:
        raise ValueError("No Python files were found to analyze")

    builder = MermaidGraphBuilder(root=root, include_imports=include_imports)
    all_calls: list[CallSite] = []
    for file_path in files:
        all_calls.extend(builder.add_file(file_path))

    lsp = LspClient(root=root, command=_detect_jedi_lsp_command(), timeout=lsp_timeout)
    fallback = JediFallbackResolver(root=root)
    resolved_calls = 0
    fallback_calls = 0
    unresolved_calls = 0
    placeholder_calls = 0

    try:
        lsp.start()
        _open_documents(lsp, files)
        for call_site in all_calls:
            local_target = builder.resolve_call_locally(call_site)
            if local_target is not None:
                builder.add_call_edge(call_site.source_id, local_target.node_id)
                resolved_calls += 1
                continue
            source_path = Path(call_site.file_path).resolve()
            target_location: tuple[Path, int, int] | None
            try:
                target_location = _resolve_with_lsp(lsp, source_path, call_site.line, call_site.column)
            except Exception:
                target_location = None
            if target_location is None:
                target_location = fallback.resolve(source_path, call_site.line, call_site.column)
                if target_location is not None:
                    fallback_calls += 1
            if target_location is None:
                unresolved_calls += 1
                builder.add_placeholder_call(call_site.source_id, builder.symbols[call_site.source_id].module_name, call_site.callee_expr)
                placeholder_calls += 1
                continue
            target_path, target_line, target_column = target_location
            target_symbol = builder.resolve_target_symbol(target_path, target_line, target_column)
            if target_symbol is None:
                target_resolved = target_path.resolve()
                if target_resolved == root.resolve() or root.resolve() in target_resolved.parents:
                    module_name = _module_name_for(root, target_resolved)
                    target_symbol = builder.symbols.get(f"module::{module_name}")
            if target_symbol is None:
                unresolved_calls += 1
                builder.add_placeholder_call(call_site.source_id, builder.symbols[call_site.source_id].module_name, call_site.callee_expr)
                placeholder_calls += 1
                continue
            builder.add_call_edge(call_site.source_id, target_symbol.node_id)
            resolved_calls += 1
    finally:
        lsp.stop()

    summary = {
        "files": len(files),
        "symbols": len(builder.symbols),
        "edges": len(builder.edges),
        "call_sites": len(all_calls),
        "resolved_calls": resolved_calls,
        "fallback_calls": fallback_calls,
        "unresolved_calls": unresolved_calls,
        "placeholder_calls": placeholder_calls,
    }
    return builder, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Mermaid graph for Python source using AST plus Jedi language-server definition resolution.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Python files or directories to analyze")
    parser.add_argument("--root", type=Path, default=None, help="Workspace root for module naming and LSP initialization")
    parser.add_argument("--output", type=Path, required=True, help="Path to write the Mermaid .mmd file")
    parser.add_argument("--json-output", type=Path, default=None, help="Optional path to write graph metadata as JSON")
    parser.add_argument("--markdown-output", type=Path, default=None, help="Optional path to write a Markdown file containing the Mermaid block")
    parser.add_argument("--direction", choices=["TD", "LR", "BT", "RL"], default="TD", help="Mermaid flowchart direction")
    parser.add_argument("--no-imports", action="store_true", help="Disable module import edges")
    parser.add_argument("--lsp-timeout", type=float, default=10.0, help="Seconds to wait for LSP responses")
    args = parser.parse_args(argv)

    root = args.root.resolve() if args.root is not None else _default_root(args.paths)
    builder, summary = analyze_project(
        paths=args.paths,
        root=root,
        include_imports=not args.no_imports,
        lsp_timeout=args.lsp_timeout,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    mermaid = builder.render_mermaid(direction=args.direction)
    args.output.write_text(mermaid, encoding="utf-8")

    if args.markdown_output is not None:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(f"```mermaid\n{mermaid}\n```\n", encoding="utf-8")

    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        payload = builder.to_json()
        payload["summary"] = summary
        args.json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(json.dumps({"output": str(args.output), **summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())