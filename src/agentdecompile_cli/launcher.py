"""
Java AgentDecompile launcher wrapper for Python CLI.

Handles PyGhidra initialization, AgentDecompile server startup, and project management.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING


def _log_config_block(projects_dir: Path, project_name: str) -> None:
    """Write a single readable configuration block to stderr (no password value)."""
    lines = [
        "AgentDecompile configuration:",
        f"  project: {projects_dir / project_name}",
    ]
    project_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH")
    if project_path:
        lines.append(f"  AGENT_DECOMPILE_PROJECT_PATH: {project_path}")
    host = os.getenv("AGENT_DECOMPILE_SERVER_HOST")
    port = os.getenv("AGENT_DECOMPILE_SERVER_PORT")
    repo = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY")
    if host or port or repo:
        lines.append(
            f"  server: host={host or '(not set)'}, port={port or '(not set)'}, repository={repo or '(not set)'}"
        )
    if os.getenv("AGENT_DECOMPILE_SERVER_USERNAME"):
        lines.append("  AGENT_DECOMPILE_SERVER_USERNAME: (set)")
    if os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD"):
        lines.append("  AGENT_DECOMPILE_SERVER_PASSWORD: (set)")
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if ghidra_dir:
        lines.append(f"  GHIDRA_INSTALL_DIR: {ghidra_dir}")
    sys.stderr.write("\n".join(lines) + "\n")

if TYPE_CHECKING:
    from agentdecompile.headless import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        AgentDecompileHeadlessLauncher,
    )


class AgentDecompileLauncher:
    """Wraps AgentDecompile headless launcher with Python-side project management.

    NOTE: Stdio mode uses ephemeral projects in temp directories by default.
    Projects are created per-session and cleaned up on exit.
    If AGENT_DECOMPILE_PROJECT_PATH environment variable is set, uses that project instead.
    """

    def __init__(
        self,
        config_file: Path | None = None,
        use_random_port: bool = True,
    ):
        """
        Initialize AgentDecompile launcher.

        Args:
        ----
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
        """
        self.config_file: Path | None = config_file
        self.use_random_port: bool = use_random_port
        self.java_launcher: AgentDecompileHeadlessLauncher | None = None
        self.port: int | None = None
        self.temp_project_dir: Path | None = None
        self.user_project_path: Path | None = None

    def start(self) -> int:
        """
        Start AgentDecompile headless server.

        Returns:
        -------
            Server port number

        Raises:
        ------
            RuntimeError: If server fails to start
        """
        try:
            # Import AgentDecompile launcher (PyGhidra already initialized by CLI)
            import tempfile

            from java.io import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                File,
            )
            from agentdecompile.headless import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                AgentDecompileHeadlessLauncher,
            )

            from .project_manager import ProjectManager

            # Check for AGENT_DECOMPILE_PROJECT_PATH environment variable
            project_gpr_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH")

            if project_gpr_path:
                # Use user-specified project from environment variable
                project_gpr = Path(project_gpr_path)

                # Validate it's a .gpr file
                if not project_gpr.suffix.lower() == ".gpr":
                    raise ValueError(
                        f"AGENT_DECOMPILE_PROJECT_PATH must point to a .gpr file, got: {project_gpr_path}"
                    )

                # Validate the file exists
                if not project_gpr.exists():
                    raise FileNotFoundError(
                        f"Project file specified in AGENT_DECOMPILE_PROJECT_PATH does not exist: {project_gpr_path}"
                    )

                # Extract project directory and name (same logic as open tool for projects)
                project_dir = project_gpr.parent
                project_name = project_gpr.stem  # Gets filename without extension

                if not project_name:
                    raise ValueError(
                        f"Invalid project name extracted from path: {project_gpr_path}"
                    )

                # Store the user project path (so we don't clean it up)
                self.user_project_path = project_gpr

                # Use the project directory
                projects_dir = project_dir
            else:
                # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
                # Keeps working directory clean - no .agentdecompile creation in cwd
                self.temp_project_dir = Path(tempfile.mkdtemp(prefix="agentdecompile_project_"))
                project_manager = ProjectManager()
                project_name = project_manager.get_project_name()

                # Use temp directory for the project (not .agentdecompile/projects)
                projects_dir = self.temp_project_dir

            # Log configuration once in a readable block (no password value)
            _log_config_block(projects_dir, project_name)

            # Convert to Java File objects
            java_project_location = File(str(projects_dir))

            # Create launcher with project parameters
            if self.config_file:
                java_config_file = File(str(self.config_file))
                self.java_launcher = AgentDecompileHeadlessLauncher(
                    java_config_file,
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )
            else:
                # Use constructor with project parameters
                self.java_launcher = AgentDecompileHeadlessLauncher(
                    None,
                    True,  # autoInitializeGhidra
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )

            self.java_launcher.start()  # pyright: ignore[reportOptionalMemberAccess]

            if self.java_launcher.waitForServer(30000):  # pyright: ignore[reportOptionalMemberAccess]
                self.port = self.java_launcher.getPort()  # pyright: ignore[reportOptionalMemberAccess]
                sys.stderr.write(f"AgentDecompile ready on port {self.port}\n")

                return self.port  # pyright: ignore[reportReturnType]
            else:
                raise RuntimeError("Server failed to start within timeout")

        except Exception as e:
            sys.stderr.write(f"Error starting AgentDecompile server: {e}\n")
            import traceback

            traceback.print_exc(file=sys.stderr)
            raise

    def get_port(self) -> int | None:
        """
        Get the server port.

        Returns:
            Server port number, or None if not started
        """
        return self.port

    def is_running(self) -> bool:
        """
        Check if server is running.

        Returns:
        --------
            True if server is running
        """
        if self.java_launcher:
            return self.java_launcher.isRunning()
        return False

    def stop(self):
        """Stop the AgentDecompile server and cleanup."""
        if self.java_launcher:
            sys.stderr.write("Stopping AgentDecompile server...\n")
            try:
                self.java_launcher.stop()
            except Exception as e:
                sys.stderr.write(f"Error stopping server: {e}\n")
            finally:
                self.java_launcher = None
                self.port = None

        # Clean up temporary project directory (only if using temp project, not user project)
        if self.temp_project_dir and self.temp_project_dir.exists():
            try:
                import shutil

                shutil.rmtree(self.temp_project_dir)
                sys.stderr.write(
                    f"Cleaned up temporary project directory: {self.temp_project_dir}\n"
                )
            except Exception as e:
                sys.stderr.write(f"Error cleaning up temporary directory: {e}\n")
            finally:
                self.temp_project_dir = None
