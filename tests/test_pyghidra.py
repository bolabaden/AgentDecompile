"""Test PyGhidra integration for headless Ghidra operation.

Verifies that:
- PyGhidra can be imported
- Ghidra can be initialized in headless mode
- Basic Ghidra functionality works (program creation, etc.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingTypeStubs, reportMissingModuleSource]

from tests.helpers import assert_bool_invariants, assert_int_invariants, assert_string_invariants


class TestPyGhidraIntegration:
    """Test that PyGhidra integration works correctly"""

    def test_pyghidra_imports(self):
        """PyGhidra module can be imported"""
        import pyghidra

        assert pyghidra is not None
        assert_bool_invariants(pyghidra is not None)

    def test_ghidra_initialized(self, ghidra_initialized: bool):
        """Ghidra can be initialized in headless mode"""
        # The fixture handles initialization
        # Just verify we can import Ghidra classes
        from ghidra.program.database import ProgramDB  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        from ghidra.program.model.lang import LanguageID  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]

        assert ProgramDB is not None, "Failed to import Ghidra ProgramDB class"
        assert LanguageID is not None, "Failed to import Ghidra LanguageID class"
        assert_bool_invariants(ProgramDB is not None)
        assert_bool_invariants(LanguageID is not None)

    def test_test_program_created(
        self,
        test_program: GhidraProgram | None,
    ):
        """Test program fixture creates valid program"""
        assert test_program is not None, "Failed to create test program"
        assert_bool_invariants(test_program is not None)

        # Verify program properties
        assert test_program.getName() == "TestHeadlessProgram"
        assert_string_invariants(test_program.getName(), expected="TestHeadlessProgram")

        # Verify memory was created
        memory = test_program.getMemory()
        assert memory is not None

        # Verify .text section exists
        text_block = memory.getBlock(".text")
        assert text_block is not None
        assert text_block.getStart().getOffset() == 0x00401000
        assert text_block.getSize() == 0x1000
        assert_int_invariants(text_block.getStart().getOffset(), min_value=0)
        assert_int_invariants(text_block.getSize(), min_value=1)

    def test_agentdecompile_classes_importable(self, ghidra_initialized: bool):
        """AgentDecompile classes can be imported after Ghidra initialization"""
        from agentdecompile.headless import AgentDecompileHeadlessLauncher  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]

        assert AgentDecompileHeadlessLauncher is not None
        assert_bool_invariants(AgentDecompileHeadlessLauncher is not None)

    def test_java_output_redirect_via_callback(self, ghidra_initialized: bool):
        """Java System.out/err can be redirected via StderrWriter callback (no Python subclass of OutputStream)."""
        from agentdecompile_cli import __main__ as cli_main

        # Should not raise; redirect uses Java interface impl from Python, not extending OutputStream
        cli_main._redirect_java_outputs()
