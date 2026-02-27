"""Program lookup utility for AgentDecompile Python implementation.

Provides program validation and lookup with helpful error messages,
.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from agentdecompile_cli.mcp_utils.debug_logger import DebugLogger

if TYPE_CHECKING:
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingTypeStubs, reportMissingImports, reportMissingModuleSource]
        Program as GhidraProgram,
    )


class ProgramValidationException(Exception):
    """Exception raised when program validation fails."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message: str = message


class ProgramLookupUtil:
    """Utility for program validation and lookup with helpful error messages."""

    @staticmethod
    def get_validated_program(
        program_path: str,
        available_programs: list[GhidraProgram] | None = None,
    ) -> GhidraProgram:
        """Get and validate a program by path with helpful error messages.

        Args:
            program_path: Path to the program to find
            available_programs: Optional list of currently open programs to search in

        Returns:
            The validated program

        Raises:
            ProgramValidationException: If program cannot be found or validated
        """
        if not program_path or not program_path.strip():
            raise ProgramValidationException("Program path cannot be empty")

        program_path = program_path.strip()
        DebugLogger.debug(ProgramLookupUtil, f"Looking up program: {program_path}")

        # Try to find the program in available programs
        if available_programs:
            program = ProgramLookupUtil._find_program_in_list(program_path, available_programs)
            if program:
                DebugLogger.debug(ProgramLookupUtil, f"Found program in available list: {program.getName()}")
                return program

        # If we don't have a list of available programs, we can't validate
        # This is a limitation compared to the Java version which has access to the plugin system
        raise ProgramValidationException(
            f"Program '{program_path}' not found. Note: Program validation requires access to currently open Ghidra programs.",
        )

    @staticmethod
    def _find_program_in_list(program_path: str, programs: list[Program]) -> Program | None:
        """Find a program in the list by path or name.

        Args:
            program_path: The program path or name to search for
            programs: List of available programs

        Returns:
            The matching program, or None if not found
        """
        if not programs:
            return None

        # First try exact path match
        for program in programs:
            domain_file = program.getDomainFile()
            if domain_file:
                file_path = domain_file.getPathname()
                if file_path == program_path:
                    return program

        # Then try name match
        program_name = Path(program_path).name
        for program in programs:
            if program.getName() == program_name:
                return program

        # Try partial name match
        for program in programs:
            name = program.getName()
            if name and (program_name in name or name in program_name):
                return program

        return None

    @staticmethod
    def get_available_programs_info(available_programs: list[Program]) -> str:
        """Get a formatted string listing available programs for error messages.

        Args:
            available_programs: List of available programs

        Returns:
            Formatted string with program information
        """
        if not available_programs:
            return "No programs are currently open."

        lines = ["Available programs:"]
        for program in available_programs:
            name = program.getName()
            domain_file = program.getDomainFile()
            path = domain_file.getPathname() if domain_file else "unknown"
            lines.append(f"  - {name} ({path})")

        return "\n".join(lines)

    @staticmethod
    def suggest_similar_programs(target_path: str, available_programs: list[Program], max_suggestions: int = 3) -> list[str]:
        """Suggest similar program names based on fuzzy matching.

        Args:
            target_path: The target program path
            available_programs: List of available programs
            max_suggestions: Maximum number of suggestions to return

        Returns:
            List of suggested program names
        """
        if not available_programs:
            return []

        target_name = Path(target_path).name.lower()

        # Simple similarity scoring based on common substrings
        suggestions = []
        for program in available_programs:
            program_name = program.getName()
            if program_name:
                program_name_lower = program_name.lower()

                # Exact substring match gets highest score
                if target_name in program_name_lower or program_name_lower in target_name:
                    suggestions.append(program_name)
                    if len(suggestions) >= max_suggestions:
                        break

        return suggestions

    @staticmethod
    def validate_program_path_format(program_path: str) -> bool:
        """Validate that a program path has a reasonable format.

        Args:
            program_path: The program path to validate

        Returns:
            True if the path format is valid
        """
        if not program_path or not program_path.strip():
            return False

        path = Path(program_path.strip())

        # Check for obviously invalid paths
        if path.is_reserved() or ".." in path.parts:
            return False

        # Check for reasonable file extensions (optional, just a heuristic)
        valid_extensions = {".exe", ".dll", ".so", ".dylib", ".bin", ".out", ".elf"}
        if path.suffix.lower() in valid_extensions:
            return True

        # Allow paths without extensions (they might still be valid binaries)
        return len(path.name) > 0

    @staticmethod
    def get_program_display_name(program: Program) -> str:
        """Get a display name for a program suitable for error messages.

        Args:
            program: The program to get display name for

        Returns:
            Display name string
        """
        if program is None:
            return "unknown program"

        name = program.getName()
        if name:
            domain_file = program.getDomainFile()
            if domain_file:
                path = domain_file.getPathname()
                return f"{name} ({path})"

        return name or "unnamed program"
