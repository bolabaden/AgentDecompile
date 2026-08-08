"""Compile C source to an object file via a configurable shell compiler script.

Ports the upstream CCompiler: a thin, toolchain-agnostic wrapper. The caller
supplies a shell script template with `{{cFilePath}}`/`{{objFilePath}}`/
`{{functionName}}` placeholders that invokes whatever actual compiler the
target project needs (agbcc, mwcc, gcc, a cross-compiler, ...) -- this module
just handles context-prepending, comment-stripping (old compilers choke on
some modern comment forms), preprocessing, and running that script.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_ERROR_LINE_RE = re.compile(r"^(.+?):(\d+):\s*(.+)$")
_MARKER = "extern void _AGENTDECOMPILE_CONCATENATED_CODE();"
_MARKER_NEEDLE = "_AGENTDECOMPILE_CONCATENATED_CODE"


@dataclass
class CompilationError:
    line: int
    message: str


@dataclass
class CompileResult:
    success: bool
    obj_path: Path | None = None
    error_message: str | None = None
    compilation_errors: list[CompilationError] = field(default_factory=list)


def _format_compilation_errors(raw_error: str, context_line_count: int) -> list[CompilationError]:
    errors: list[CompilationError] = []
    for line in raw_error.split("\n"):
        match = _ERROR_LINE_RE.match(line)
        if match:
            _file, line_num, message = match.groups()
            errors.append(CompilationError(line=int(line_num) - context_line_count, message=message.strip()))
    return errors


class GnuCCompiler:
    def __init__(self, compiler_script: str, project_root: Path) -> None:
        self._compiler_script = compiler_script
        self._project_root = project_root

    def compile(self, function_name: str, c_code: str, context_content: str) -> CompileResult:
        tmp_dir = Path(tempfile.mkdtemp(prefix="agentdecompile-compile-"))
        combined_path = tmp_dir / f"{function_name}_combined.c"
        stripped_path = tmp_dir / f"{function_name}_stripped.c"
        preprocessed_path = tmp_dir / f"{function_name}_preprocessed.c"
        obj_path = tmp_dir / f"{function_name}.o"
        script_path = tmp_dir / f"{function_name}_compile.sh"

        succeeded = False
        try:
            combined = f"{context_content}\n{_MARKER}\n{c_code}"
            combined_path.write_text(combined, encoding="utf-8")

            stripped = _BLOCK_COMMENT_RE.sub("", combined)
            stripped_path.write_text(stripped, encoding="utf-8")

            cpp = shutil.which("cpp")
            if cpp is None:
                return CompileResult(success=False, error_message="cpp is not on PATH.")
            cpp_result = subprocess.run(
                [cpp, "-P", str(stripped_path), str(preprocessed_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if cpp_result.returncode != 0:
                raw_error = cpp_result.stderr.strip() or cpp_result.stdout.strip()
                return self._error_result(raw_error, preprocessed_path if preprocessed_path.exists() else stripped_path)

            rendered_script = (
                self._compiler_script.replace("{{cFilePath}}", str(preprocessed_path))
                .replace("{{objFilePath}}", str(obj_path))
                .replace("{{functionName}}", function_name)
            )
            script_path.write_text("set -e\n" + rendered_script, encoding="utf-8")
            compile_result = subprocess.run(
                ["bash", str(script_path)],
                cwd=str(self._project_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if compile_result.returncode != 0:
                raw_error = compile_result.stderr.strip() or compile_result.stdout.strip()
                return self._error_result(raw_error, preprocessed_path)

            succeeded = True
            return CompileResult(success=True, obj_path=obj_path)
        finally:
            for intermediate in (combined_path, stripped_path, preprocessed_path, script_path):
                intermediate.unlink(missing_ok=True)
            if not succeeded:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _error_result(raw_error: str, preprocessed_path: Path) -> CompileResult:
        try:
            preprocessed_source = preprocessed_path.read_text(encoding="utf-8")
            marker_line = 1 + next(
                (i for i, line in enumerate(preprocessed_source.split("\n")) if _MARKER_NEEDLE in line), -1
            )
            compilation_errors = _format_compilation_errors(raw_error, marker_line)
            return CompileResult(
                success=False,
                error_message="Compilation failed" if compilation_errors else raw_error,
                compilation_errors=compilation_errors,
            )
        except OSError:
            return CompileResult(success=False, error_message=raw_error)
