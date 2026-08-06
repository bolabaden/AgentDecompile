"""Utility functions for inserting a matched decompilation into project source.

Ports the upstream integrator-helpers: common patterns across decomp projects
for replacing a `INCLUDE_ASM(...)`/`#pragma GLOBAL_ASM(...)` stub with real C
code, once objdiff confirms a byte-exact match.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


class IntegratorError(Exception):
    pass


class IntegratorHelpers:
    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root
        self.logs: list[str] = []

    def find_source_file(self, function_name: str) -> Path:
        src_dir = self._project_root / "src"
        if not src_dir.is_dir():
            raise IntegratorError(f"src/ directory not found in project at {self._project_root}")

        escaped = re.escape(function_name)
        include_asm_pattern = re.compile(rf"INCLUDE_ASM\s*\([^,]*,\s*{escaped}\s*\)\s*;")
        pragma_pattern = re.compile(rf'#pragma\s+GLOBAL_ASM\s*\(\s*"[^"]*{escaped}[^"]*"\s*\)')

        for file_path in sorted(src_dir.rglob("*.c")):
            content = file_path.read_text(encoding="utf-8", errors="replace")
            if include_asm_pattern.search(content) or pragma_pattern.search(content):
                return file_path

        raise IntegratorError(f'Could not find source file containing stub for function "{function_name}" in {src_dir}')

    def replace_include_asm(self, file_path: Path, function_name: str, code: str) -> None:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        escaped = re.escape(function_name)
        pattern = re.compile(rf"INCLUDE_ASM\s*\([^,]*,\s*{escaped}\s*\)\s*;[ \t]*\n?")

        if not pattern.search(content):
            raise IntegratorError(f'Could not find INCLUDE_ASM stub for "{function_name}" in {file_path}')

        updated = pattern.sub(code.rstrip() + "\n", content, count=1)
        file_path.write_text(updated, encoding="utf-8")
        self.logs.append(f"Replaced INCLUDE_ASM stub for {function_name} in {file_path.relative_to(self._project_root)}")

    def replace_pragma_global_asm(self, file_path: Path, function_name: str, code: str) -> None:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        escaped = re.escape(function_name)
        pattern = re.compile(rf'#pragma\s+GLOBAL_ASM\s*\(\s*"[^"]*{escaped}[^"]*"\s*\)[ \t]*\n?')

        if not pattern.search(content):
            raise IntegratorError(f'Could not find #pragma GLOBAL_ASM for "{function_name}" in {file_path}')

        updated = pattern.sub(code.rstrip() + "\n", content, count=1)
        file_path.write_text(updated, encoding="utf-8")
        self.logs.append(
            f"Replaced #pragma GLOBAL_ASM for {function_name} in {file_path.relative_to(self._project_root)}"
        )

    _DECL_SCAN_RE = re.compile(r"(?:^|[\n;{}])\s*(?:extern\s+)?[\w\s*]+?\b(\w+)\s*\(", re.MULTILINE)
    _DECL_LINE_RE = re.compile(r"^(?:extern\s+)?[\w\s*]+?\b(\w+)\s*\([^)]*\)\s*;\s*$")

    def strip_duplicate_declarations(self, file_path: Path, code: str) -> str:
        """Strip forward/extern declarations from `code` already present in `file_path`.

        Only strips declaration lines before the first `{` in `code`, so
        declarations that happen to appear inside a function body are left alone.
        """
        file_content = file_path.read_text(encoding="utf-8", errors="replace")
        declared_names = {match.group(1) for match in self._DECL_SCAN_RE.finditer(file_content)}

        lines = code.split("\n")
        seen_open_brace = False
        filtered: list[str] = []
        for line in lines:
            trimmed = line.strip()
            if "{" in trimmed:
                seen_open_brace = True

            if not seen_open_brace:
                decl_match = self._DECL_LINE_RE.match(trimmed)
                if decl_match and decl_match.group(1) in declared_names:
                    self.logs.append(f"Stripped duplicate declaration for {decl_match.group(1)}")
                    continue

            filtered.append(line)

        result = "\n".join(filtered)
        return re.sub(r"^\n+", "", result)

    def exec_command(self, command: str, *, timeout: float = 120.0) -> str:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(self._project_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            executable=shutil.which("bash"),
        )
        if completed.returncode != 0:
            raise IntegratorError(completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}")
        return completed.stdout

    def log(self, message: str) -> None:
        self.logs.append(message)
