"""Tests for integrator_helpers.py, ported from the upstream integrator-helpers spec."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.integrator_helpers import IntegratorError, IntegratorHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    return tmp_path


class TestFindSourceFile:
    def test_finds_file_containing_include_asm_for_function(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text(
            "\n".join(
                [
                    '#include "global.h"',
                    'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000960);',
                    'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000978);',
                ]
            ),
            encoding="utf-8",
        )

        helpers = IntegratorHelpers(project_root)
        assert helpers.find_source_file("FUN_08000960") == file_path

    def test_finds_file_containing_pragma_global_asm_for_function(self, project_root: Path):
        file_path = project_root / "src" / "module.c"
        file_path.write_text('#pragma GLOBAL_ASM("asm/jp/nonmatchings/code/m_demo/func_800CDB10_jp.s")\n', encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        assert helpers.find_source_file("func_800CDB10_jp") == file_path

    def test_raises_when_function_is_not_found(self, project_root: Path):
        (project_root / "src" / "math.c").write_text("int main() {}", encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        with pytest.raises(IntegratorError, match="Could not find source file"):
            helpers.find_source_file("nonexistent")

    def test_searches_subdirectories_recursively(self, project_root: Path):
        nested = project_root / "src" / "game" / "interactables"
        nested.mkdir(parents=True)
        file_path = nested / "spring.c"
        file_path.write_text('INCLUDE_ASM("asm/spring", MyFunc);', encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        assert helpers.find_source_file("MyFunc") == file_path


class TestReplaceIncludeAsm:
    def test_replaces_include_asm_stub_with_c_code(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text(
            "\n".join(
                [
                    '#include "global.h"',
                    'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000960);',
                    'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000978);',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        helpers = IntegratorHelpers(project_root)
        helpers.replace_include_asm(file_path, "FUN_08000960", "s16 FUN_08000960(s32 a) {\n    return a;\n}")

        result = file_path.read_text(encoding="utf-8")
        assert "s16 FUN_08000960(s32 a) {\n    return a;\n}" in result
        assert 'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000960)' not in result
        assert 'INCLUDE_ASM("asm/nonmatchings/math", FUN_08000978)' in result

    def test_raises_when_stub_is_not_found(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text("int main() {}", encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        with pytest.raises(IntegratorError, match="Could not find INCLUDE_ASM stub"):
            helpers.replace_include_asm(file_path, "FUN_08000960", "code")


class TestReplacePragmaGlobalAsm:
    def test_replaces_pragma_global_asm_with_c_code(self, project_root: Path):
        file_path = project_root / "src" / "module.c"
        file_path.write_text(
            "\n".join(
                [
                    '#include "module.h"',
                    '#pragma GLOBAL_ASM("asm/jp/nonmatchings/code/module/func_A.s")',
                    '#pragma GLOBAL_ASM("asm/jp/nonmatchings/code/module/func_B.s")',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        helpers = IntegratorHelpers(project_root)
        helpers.replace_pragma_global_asm(file_path, "func_A", "void func_A(void) {\n}")

        result = file_path.read_text(encoding="utf-8")
        assert "void func_A(void) {\n}" in result
        assert "func_A.s" not in result
        assert "func_B.s" in result


class TestLog:
    def test_captures_log_messages(self, project_root: Path):
        helpers = IntegratorHelpers(project_root)
        helpers.log("step 1")
        helpers.log("step 2")
        assert helpers.logs == ["step 1", "step 2"]


class TestStripDuplicateDeclarations:
    def test_strips_declarations_for_functions_already_in_the_file(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text(
            "\n".join(
                [
                    '#include "global.h"',
                    "extern s16 FUN_080518a4(s32 a, s16 b);",
                    "",
                    "s16 FUN_08000960(s32 arg0, s16 arg1) {",
                    "    return (s16)FUN_080518a4(arg0 << 8, arg1);",
                    "}",
                ]
            ),
            encoding="utf-8",
        )

        helpers = IntegratorHelpers(project_root)
        code = "s16 FUN_080518a4(s32, s16);\n\ns16 FUN_08000978(s16 arg0) {\n    return FUN_080518a4(0x10000, arg0);\n}"
        result = helpers.strip_duplicate_declarations(file_path, code)

        assert "FUN_080518a4(s32, s16);" not in result
        assert "FUN_08000978" in result

    def test_strips_extern_declarations_too(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text("s16 FUN_080518a4(s32 a, s16 b);\n", encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        code = "extern s16 FUN_080518a4(s32 a, s16 b);\n\nvoid foo(void) {}"
        result = helpers.strip_duplicate_declarations(file_path, code)

        assert "extern" not in result
        assert "void foo(void) {}" in result

    def test_keeps_declarations_for_functions_not_in_the_file(self, project_root: Path):
        file_path = project_root / "src" / "math.c"
        file_path.write_text('#include "global.h"\n', encoding="utf-8")

        helpers = IntegratorHelpers(project_root)
        code = "extern s16 FUN_080518a4(s32 a, s16 b);\n\nvoid foo(void) {}"
        result = helpers.strip_duplicate_declarations(file_path, code)

        assert "extern s16 FUN_080518a4" in result
        assert "void foo(void) {}" in result


class TestExecCommand:
    def test_runs_shell_commands_in_project_root(self, project_root: Path):
        helpers = IntegratorHelpers(project_root)
        output = helpers.exec_command("pwd")
        assert Path(output.strip()).resolve() == project_root.resolve()

    def test_raises_on_non_zero_exit_code(self, project_root: Path):
        helpers = IntegratorHelpers(project_root)
        with pytest.raises(IntegratorError):
            helpers.exec_command("exit 1")
