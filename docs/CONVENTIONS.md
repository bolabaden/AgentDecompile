# AgentDecompile Conventions

This document records the repository conventions used by developers and automated agents.

Repository layout
- `src/main/java/agentdecompile` — Java source (Ghidra extension, target Java 21+)
- `src/agentdecompile_cli` — Python CLI and stdio bridge
- `dist/` — produced extension `.zip`
- `build-and-install.ps1` — Windows build-and-install helper

Environments
- Java: JDK 17+ required on PATH (recommended: JDK 21). Check: `java -version`.
- Gradle: system Gradle is used by scripts; a Gradle wrapper is not provided. Gradle can be installed non-interactively:
	- Ubuntu/Fedora: SDKMAN! or `sudo snap install gradle --classic` (SDKMAN! preferred).
	- macOS: Homebrew `brew install gradle` or SDKMAN!.
	- Windows: Chocolatey `choco install gradle -y` (admin) or scoop `scoop install gradle` (user-level).
	- Manual/scriptable: download `https://services.gradle.org/distributions/gradle-9.3.0-bin.zip`, extract and add `gradle/bin` to PATH.
- Python: Python 3.11+ recommended. Use a virtual environment for CLI work.

Build and install patterns
- Use `build-and-install.ps1` on Windows to build the Java extension and install it into Ghidra. The script prefers a `GRADLE_PATH` and `GHIDRA_INSTALL_DIR` environment variable.
- The Python CLI is installed from `pyproject.toml` / `requirements.txt` in a venv: `python -m venv .venv && .venv\Scripts\pip install -e .`.

Testing and runtime
- Integration tests require a headless Ghidra environment and may require `java.awt.headless=false` in CI.
- The CLI launches a headless Java process via PyGhidra. Keep the CLI running in the foreground to expose the MCP HTTP endpoint.

Common pitfalls
- Locked files: Ghidra extension files under `Ghidra/Extensions/agentdecompile` can be locked by running Python/Ghidra processes — stop those before reinstall.
- Python package pins: older pinned binary packages (e.g., old `pandas`) can fail to build on newer Pythons. Prefer creating a supported Python (3.11/3.12) or update pinned versions.
- Gradle versions: Gradle 9.x+ works; some Gradle deprecation warnings may appear. The scripts attempt to resolve `gradle` from PATH and prompt if not found.

Ghidra usage notes
- Enabling the extension (GUI): In Ghidra, open `File -> Install Extensions` and click the `AgentDecompile` extension to enable it.
- Configure server options (GUI): In Ghidra, go to `File -> Configure -> AgentDecompile Server Options` to set the host, port, and credentials.
- Running Ghidra for configuration: Run `run_ghidra.bat` on Windows, or the `run_ghidra` launcher on Linux/macOS. Create or open a project, then open the Code Browser (the green dragon) to access `File -> Extensions` and enable `AgentDecomp` and `PyGhidra`.

Example decompile server (optional)
- Host: biodecompwarehouse.beatapostapita.bolabaden.org
- User: OldRepublicDevs
- Password: changeme (may also be `MuchaShakaPaka` — verify with server admin)

If you are an AI agent: prefer non-interactive operations, set environment variables in the process before invoking build scripts, and keep long-running processes (CLI/server) running in a dedicated terminal session.

If you are an AI agent: prefer non-interactive operations, set environment variables in the process before invoking build scripts, and keep long-running processes (CLI/server) running in a dedicated terminal session.
