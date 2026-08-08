"""Tests for integrator_plugin.py's user-module dispatch and build verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.integrator_plugin import IntegratorPlugin, load_integrator_module
from agentdecompile_recovery.integrator_helpers import IntegratorError

pytestmark = pytest.mark.unit


def _write_integrator_module(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_load_integrator_module_raises_when_integrate_is_missing(tmp_path: Path):
    module_path = _write_integrator_module(tmp_path / "no_integrate.py", "x = 1\n")

    with pytest.raises(IntegratorError, match="does not export"):
        load_integrator_module(module_path)


def test_load_integrator_module_returns_a_callable_integrate(tmp_path: Path):
    module_path = _write_integrator_module(
        tmp_path / "mod.py", "def integrate(**kwargs):\n    return {'filesModified': [], 'summary': 'ok'}\n"
    )

    module = load_integrator_module(module_path)
    assert callable(module.integrate)


class TestIntegratorPlugin:
    def test_fails_when_no_generated_code_in_context(self, tmp_path: Path):
        module_path = _write_integrator_module(tmp_path / "mod.py", "def integrate(**kwargs):\n    pass\n")
        plugin = IntegratorPlugin(module_path, tmp_path)

        result, _context = plugin.execute({"functionName": "f"})

        assert result.status == "failure"
        assert "No generated code" in result.error

    def test_calls_integrate_with_helpers_and_returns_success(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        stub_path = tmp_path / "src" / "math.c"
        stub_path.write_text('INCLUDE_ASM("asm/math", target_func);', encoding="utf-8")

        module_path = _write_integrator_module(
            tmp_path / "mod.py",
            "def integrate(*, function_name, generated_code, project_root, helpers):\n"
            "    file_path = helpers.find_source_file(function_name)\n"
            "    helpers.replace_include_asm(file_path, function_name, generated_code)\n"
            "    return {'filesModified': [str(file_path)], 'summary': f'Integrated {function_name}'}\n",
        )
        plugin = IntegratorPlugin(module_path, tmp_path)

        result, _context = plugin.execute({"functionName": "target_func", "generatedCode": "void target_func(void) {}"})

        assert result.status == "success"
        assert result.data["integrationSummary"] == "Integrated target_func"
        assert stub_path.read_text(encoding="utf-8") == "void target_func(void) {}\n"
        assert any("Replaced INCLUDE_ASM stub" in log for log in result.data["logs"])

    def test_propagates_integration_errors_as_plugin_failure(self, tmp_path: Path):
        module_path = _write_integrator_module(
            tmp_path / "mod.py",
            "from agentdecompile_recovery.integrator_helpers import IntegratorError\n"
            "def integrate(**kwargs):\n"
            "    raise IntegratorError('stub not found')\n",
        )
        plugin = IntegratorPlugin(module_path, tmp_path)

        result, _context = plugin.execute({"functionName": "f", "generatedCode": "void f(void) {}"})

        assert result.status == "failure"
        assert "stub not found" in result.error

    def test_runs_build_command_after_successful_integration(self, tmp_path: Path):
        module_path = _write_integrator_module(
            tmp_path / "mod.py",
            "def integrate(**kwargs):\n    return {'filesModified': [], 'summary': 'ok'}\n",
        )
        plugin = IntegratorPlugin(module_path, tmp_path, build_command="echo build-succeeded")

        result, _context = plugin.execute({"functionName": "f", "generatedCode": "void f(void) {}"})

        assert result.status == "success"
        assert "build-succeeded" in result.data["buildOutput"]

    def test_reports_failure_when_build_command_fails(self, tmp_path: Path):
        module_path = _write_integrator_module(
            tmp_path / "mod.py",
            "def integrate(**kwargs):\n    return {'filesModified': [], 'summary': 'ok'}\n",
        )
        plugin = IntegratorPlugin(module_path, tmp_path, build_command="exit 1")

        result, _context = plugin.execute({"functionName": "f", "generatedCode": "void f(void) {}"})

        assert result.status == "failure"
        assert "Build failed" in result.error
