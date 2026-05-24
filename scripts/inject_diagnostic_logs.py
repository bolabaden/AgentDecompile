#!/usr/bin/env python3
"""Inject DEBUG diagnostic logs at function entry (+ except bodies if budget remains).

Inserts logger.debug("diag.enter %s", "<rel>:Qual.name") on the first real
statement line *inside* the function body (never between a decorator and def).

Skips: nested functions, TYPE_CHECKING-only blocks, one-line ``...`` stubs.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "agentdecompile_cli"
DEFAULT_MAX = 1000
SKIP_FILES = frozenset({"_version.py", "app_logger.py"})
FN_MARKER = "diag.enter"
EX_MARKER = "diag.except"


def file_tier(path: Path) -> int:
    s = path.as_posix()
    if "/mcp_server/providers/" in s or "/mcp_server/resources/" in s:
        return 0
    if "/mcp_server/" in s:
        return 1
    if "/tools/" in s or "/mcp_utils/" in s:
        return 2
    return 3


def attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            setattr(child, "parent", node)


def under_type_checking(node: ast.AST) -> bool:
    p: ast.AST | None = getattr(node, "parent", None)
    while p is not None:
        if isinstance(p, ast.If):
            try:
                if "TYPE_CHECKING" in ast.unparse(p.test):
                    return True
            except Exception:
                pass
        p = getattr(p, "parent", None)
    return False


def first_body_stmt_lineno(node: ast.AsyncFunctionDef | ast.FunctionDef) -> int | None:
    """Line of first executable stmt inside function body (after docstring); not decorator line."""
    body = node.body
    if not body:
        return None
    i = 0
    if isinstance(body[0], ast.Expr):
        v = body[0].value
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            i = 1
    while i < len(body) and isinstance(body[i], (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        i += 1
    if i >= len(body):
        return None
    stmt = body[i]
    # Skip typing protocol stubs: def f(self) -> T: ...  (same line as def)
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
        and stmt.lineno == node.lineno
    ):
        return None
    return stmt.lineno


def collect_function_points(tree: ast.AST, rel: str, source_lines: list[str] | None = None) -> list[tuple[int, str]]:
    attach_parents(tree)

    class V(ast.NodeVisitor):
        def __init__(self) -> None:
            self.class_stack: list[str] = []
            self.out: list[tuple[int, str]] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._fn(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._fn(node)
            self.generic_visit(node)

        def _fn(self, node: ast.AsyncFunctionDef | ast.FunctionDef) -> None:
            if node.name.startswith("test"):
                return
            par = getattr(node, "parent", None)
            if not isinstance(par, (ast.Module, ast.ClassDef)):
                return
            if under_type_checking(node):
                return
            ln = first_body_stmt_lineno(node)
            if ln is None:
                return
            if source_lines is not None and 1 <= ln <= len(source_lines) and FN_MARKER in source_lines[ln - 1]:
                return
            qual = ".".join(self.class_stack + [node.name]) if self.class_stack else node.name
            self.out.append((ln, f"{rel}:{qual}"))

    v = V()
    v.visit(tree)
    return v.out


def collect_except_points(tree: ast.AST, rel: str, source_lines: list[str] | None = None) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.body:
            if under_type_checking(node):
                continue
            ln0 = node.body[0].lineno
            if source_lines is not None and 1 <= ln0 <= len(source_lines) and EX_MARKER in source_lines[ln0 - 1]:
                continue
            t = node.type
            if t is None:
                label = "bare"
            else:
                try:
                    label = ast.unparse(t)
                except Exception:
                    label = "typed"
            out.append((ln0, f"{rel}:except:{label}"))
    return out


def detect_logger_var(source: str) -> tuple[str, bool]:
    if re.search(r"^logger\s*=\s*logging\.getLogger\s*\(\s*__name__\s*\)", source, re.MULTILINE):
        return "logger", False
    if re.search(r"^log\s*=\s*logging\.getLogger\s*\(\s*__name__\s*\)", source, re.MULTILINE):
        return "log", False
    return "logger", True


def prepend_logger_setup(source: str) -> str:
    lines = source.splitlines(keepends=True)
    insert_at = 0
    for i, line in enumerate(lines[:80]):
        if line.startswith("from __future__"):
            insert_at = i + 1
    has_import_logging = bool(re.search(r"^import logging\s*$", source, re.MULTILINE))
    block: list[str] = []
    if not has_import_logging:
        block.append("\nimport logging\n")
    block.append("\nlogger = logging.getLogger(__name__)\n")
    lines[insert_at:insert_at] = block
    return "".join(lines)


def line_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def apply_body_injections(source: str, points: list[tuple[int, str, str]], var: str) -> str:
    lines = source.splitlines(keepends=True)
    for lineno, tag, marker in sorted(points, key=lambda x: -x[0]):
        if lineno < 1 or lineno > len(lines):
            continue
        idx = lineno - 1
        cur = lines[idx]
        if marker in cur:
            continue
        esc = tag.replace("\\", "\\\\").replace('"', '\\"')
        ind = line_indent(cur)
        stmt = f'{ind}{var}.debug("{marker} %s", "{esc}")\n'
        lines.insert(idx, stmt)
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Inject logger.debug diag.enter/diag.except sites.")
    p.add_argument("--max", type=int, default=DEFAULT_MAX, metavar="N", help="max injections (default %(default)s)")
    p.add_argument(
        "--tier",
        type=int,
        default=None,
        metavar="T",
        help="only files in tier T (0=providers/resources, 1=mcp_server, 2=tools/mcp_utils, 3=rest)",
    )
    ns = p.parse_args(argv)
    max_total: int = ns.max
    only_tier: int | None = ns.tier

    all_fn: list[tuple[Path, int, str, int]] = []
    all_ex: list[tuple[Path, int, str, int]] = []

    for path in sorted(ROOT.rglob("*.py")):
        if path.name in SKIP_FILES:
            continue
        rel = path.relative_to(ROOT).as_posix()
        tier = file_tier(path)
        if only_tier is not None and tier != only_tier:
            continue
        try:
            src = path.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        lines_list = src.splitlines()
        for ln, tag in collect_function_points(tree, rel, lines_list):
            all_fn.append((path, ln, tag, tier))
        for ln, tag in collect_except_points(tree, rel, lines_list):
            all_ex.append((path, ln, tag, tier))

    all_fn.sort(key=lambda x: (x[3], str(x[0]), x[1]))
    chosen_fn = all_fn[:max_total]
    remaining = max_total - len(chosen_fn)
    all_ex.sort(key=lambda x: (x[3], str(x[0]), x[1]))
    chosen_ex = all_ex[: max(0, remaining)]

    by_file: dict[Path, list[tuple[int, str, str]]] = {}
    for path, ln, tag, _ in chosen_fn:
        by_file.setdefault(path, []).append((ln, tag, FN_MARKER))
    for path, ln, tag, _ in chosen_ex:
        by_file.setdefault(path, []).append((ln, tag, EX_MARKER))

    grand = 0
    for path in sorted(by_file.keys(), key=lambda p: str(p)):
        raw = by_file[path]
        orig = path.read_text(encoding="utf-8")
        var, needs_logger = detect_logger_var(orig)
        new_src = apply_body_injections(orig, raw, var)
        if needs_logger and new_src != orig:
            new_src = prepend_logger_setup(new_src)
        if new_src != orig:
            path.write_text(new_src, encoding="utf-8")
            grand += len(raw)
            print(path.relative_to(ROOT.parent), "+", len(raw))

    print("total injections", grand)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
