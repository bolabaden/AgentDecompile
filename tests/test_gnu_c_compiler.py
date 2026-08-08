"""Tests for gnu_c_compiler.py, exercised against the real system cpp/gcc toolchain."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.gnu_c_compiler import GnuCCompiler

pytestmark = pytest.mark.unit

_HAS_TOOLCHAIN = shutil.which("cpp") is not None and (shutil.which("gcc") is not None or shutil.which("cc") is not None)


@pytest.mark.skipif(not _HAS_TOOLCHAIN, reason="requires cpp and gcc/cc on PATH")
class TestGnuCCompilerRealToolchain:
    def _compiler(self, tmp_path: Path) -> GnuCCompiler:
        cc = shutil.which("gcc") or shutil.which("cc")
        script = f'{cc} -c "{{{{cFilePath}}}}" -o "{{{{objFilePath}}}}"\n'
        return GnuCCompiler(script, tmp_path)

    def test_compiles_valid_c_code_to_an_object_file(self, tmp_path: Path):
        compiler = self._compiler(tmp_path)

        result = compiler.compile("my_func", "int my_func(void) { return 42; }", "")

        assert result.success is True
        assert result.obj_path is not None
        assert result.obj_path.is_file()

    def test_prepends_context_content_before_the_function(self, tmp_path: Path):
        compiler = self._compiler(tmp_path)

        result = compiler.compile(
            "uses_type",
            "int uses_type(void) { struct Foo f; f.x = 1; return f.x; }",
            "struct Foo { int x; };",
        )

        assert result.success is True

    def test_reports_compilation_errors_for_invalid_c(self, tmp_path: Path):
        compiler = self._compiler(tmp_path)

        # Use unambiguously invalid syntax: older GCC versions only *warn* on
        # `return ;` in a non-void function, which would falsely pass this test.
        result = compiler.compile("broken", "int broken(void) { !!!not_valid_c!!! }", "")

        assert result.success is False
        assert result.error_message

    def test_strips_block_comments_before_compiling(self, tmp_path: Path):
        compiler = self._compiler(tmp_path)

        result = compiler.compile(
            "commented", "/* old-style comment that some compilers choke on */\nint commented(void) { return 1; }", ""
        )

        assert result.success is True

    def test_cleans_up_intermediate_files_on_success(self, tmp_path: Path):
        compiler = self._compiler(tmp_path)

        result = compiler.compile("clean_test", "int clean_test(void) { return 1; }", "")

        assert result.success is True
        obj_dir = result.obj_path.parent
        remaining = list(obj_dir.iterdir())
        assert remaining == [result.obj_path]


def test_reports_error_when_cpp_binary_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentdecompile_recovery.gnu_c_compiler.shutil.which", lambda name: None)
    compiler = GnuCCompiler("true\n", tmp_path)

    result = compiler.compile("f", "int f(void) { return 1; }", "")

    assert result.success is False
    assert "cpp" in (result.error_message or "")
