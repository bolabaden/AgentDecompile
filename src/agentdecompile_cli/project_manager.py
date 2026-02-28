"""Compatibility module mirrored in launcher.py as the primary implementation.
This file is kept for backward-compatibility.
Prefer importing from agentdecompile_cli.launcher.

Project management for AgentDecompile CLI.
Handles creation and management of Ghidra projects in .agentdecompile/projects/
within the current working directory, similar to how .git or .vscode work.
"""

from __future__ import annotations

import sys

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.listing import Program as GhidraProgram


class ProjectManager:
    """Manages Ghidra project creation and lifecycle for AgentDecompile CLI."""

    def __init__(
        self,
        projects_dir: Path | None = None,
    ):
        """Initialize project manager.

        Args:
            projects_dir: Custom projects directory, defaults to .agentdecompile/projects/ in current directory
        """
        if projects_dir is None:
            self.projects_dir = Path.cwd() / ".agentdecompile" / "projects"
        else:
            self.projects_dir = Path(projects_dir)

        # Don't create directory here - defer until first tool use (lazy initialization)
        self.project: GhidraProject | None = None
        self._opened_programs: list[GhidraProgram] = []
        self._initialized: bool = False

    def _ensure_initialized(self):
        """Ensure the project directory exists and project is opened.

        This implements lazy initialization - the .agentdecompile directory and Ghidra project
        are only created when first needed (e.g., when importing a binary).
        """
        if self._initialized:
            return

        # Create projects directory
        self.projects_dir.mkdir(parents=True, exist_ok=True)

        # Open/create the Ghidra project
        self.open_project()

        self._initialized = True

    def get_project_name(self) -> str:
        """Get project name based on current working directory.

        Returns:
            Project name derived from current directory name
        """
        cwd: Path = Path.cwd()
        # Use current directory name as project name
        project_name: str = cwd.name.strip()

        # Sanitize project name for Ghidra
        # Remove invalid characters and replace with underscores
        sanitized: str = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)

        # Ensure name is not empty
        if not sanitized or sanitized.startswith("."):
            sanitized = "default_project"

        return sanitized

    def get_or_create_project(self) -> tuple[str, Path]:
        """Get or create Ghidra project for current working directory.

        Returns:
            Tuple of (project_name, project_directory_path)
        """
        project_name: str = self.get_project_name()
        project_path: Path = self.projects_dir / project_name

        # Create project directory if it doesn't exist
        project_path.mkdir(parents=True, exist_ok=True)

        return project_name, project_path

    def open_project(self) -> GhidraProject:
        """Open or create Ghidra project using PyGhidra.

        Returns:
        -------
            Ghidra Project instance (GhidraProject wrapper)

        Raises:
        ------
            ImportError: If Ghidra/PyGhidra not available
        """
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_name, project_path = self.get_or_create_project()

        # Use GhidraProject (PyGhidra's approach) - handles protected constructor properly
        project_locator = ProjectLocator(str(project_path), project_name)

        # Try to open existing project or create new one
        if project_locator.getProjectDir().exists() and project_locator.getMarkerFile().exists():
            sys.stderr.write(f"Opening existing project: {project_name}\n")
            self.project = GhidraProject.openProject(
                str(project_path),
                project_name,
                True,
            )
        else:
            sys.stderr.write(f"Creating new project: {project_name} at {project_path}\n")
            project_path.mkdir(parents=True, exist_ok=True)
            self.project = GhidraProject.createProject(
                str(project_path),
                project_name,
                False,
            )

        return self.project
    def import_binary(
        self,
        binary_path: Path,
        program_name: str | None = None,
    ) -> GhidraProgram | None:
        """Import a binary file into the opened project.

        Args:
        ----
            binary_path: Path to binary file to import
            program_name: Optional custom program name, defaults to binary filename

        Returns:
        -------
            Imported GhidraProgram instance, or None if import fails
        """
        # Ensure project is initialized (lazy initialization on first use)
        self._ensure_initialized()

        if not binary_path.exists() or not binary_path.is_file():
            sys.stderr.write(f"Warning: Binary not found: {binary_path}\n")
            return None

        if program_name is None or not program_name.strip():
            program_name = binary_path.name

        try:
            sys.stderr.write(f"Importing binary: '{binary_path}' as '{program_name}'\n")
            from java.io import File  # pyright: ignore[reportMissingImports]

            # Use GhidraProject's importProgram method (auto-detects language/loader)
            program: GhidraProgram = self.project.importProgram(File(str(binary_path)))  # pyright: ignore[reportOptionalMemberAccess, reportArgumentType, reportUnknownLambdaType]

            # Save with custom name if specified
            if program_name.lower().strip() != binary_path.name.lower().strip():
                self.project.saveAs(program, "/", program_name, True)  # pyright: ignore[reportOptionalMemberAccess]

            self._opened_programs.append(program)

        except Exception as e:
            sys.stderr.write(f"Error importing binary '{binary_path}': {e.__class__.__name__}: {e}\n")
            import traceback

            traceback.print_exc(file=sys.stderr)
            return None

        else:
            sys.stderr.write(f"Successfully imported: '{program_name}'\n")
            return program

    def cleanup(self):
        """Clean up opened programs and close project."""
        # Release opened programs
        for program in self._opened_programs:
            try:
                if program is not None and not program.isClosed():
                    program.release(None)
            except Exception as e:
                sys.stderr.write(f"Error releasing program: {e.__class__.__name__}: {e}\n")

        self._opened_programs.clear()

        # Close project
        if self.project is not None:
            try:
                self.project.close()
            except Exception as e:
                sys.stderr.write(f"Error closing project: {e.__class__.__name__}: {e}\n")
            finally:
                self.project = None
