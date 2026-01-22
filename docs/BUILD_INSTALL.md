# Build & Install (Terminal-only)

This file contains explicit, non-interactive instructions to build and install AgentDecompile.

Prerequisites
- Java JDK 17+ on PATH (recommended JDK 21). Verify: `java -version`.
- Gradle on PATH (the scripts use a system Gradle). Verify: `gradle -v`.
- Python 3.11+ for CLI work; create and use a venv for all Python operations.
- `GHIDRA_INSTALL_DIR` must point to your local Ghidra root.

Windows (recommended non-interactive flow)
1. Open an elevated PowerShell (if you need Chocolatey installs).
2. Set `GHIDRA_INSTALL_DIR` in the environment for the session (example):

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\Users\you\Downloads\ghidra_12.0_PUBLIC\ghidra_12.0_PUBLIC'
```

3. If Gradle is not installed, use Chocolatey (requires admin):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco install gradle -y
```

4. From the repo root, run the installer script non-interactively (specify Gradle path if needed):

```powershell
# Example: use system gradle
D:\AgentDecompile\build-and-install.ps1 -ProjectDir 'D:\AgentDecompile' -GhidraInstallDir $env:GHIDRA_INSTALL_DIR -GradlePath 'C:\Gradle\bin\gradle.bat' -ForceKillLocks
```

5. Create and activate a Python venv, then install CLI deps:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e .
```

6. Start the CLI (keep this terminal open to keep the MCP endpoint available):

```powershell
.\.venv\Scripts\python -m agentdecompile_cli --verbose
```

Ghidra: enable & configure
- Enable extension via Ghidra UI: `File -> Install Extensions` and enable `AgentDecompile`.
- Configure server options via `File -> Configure -> AgentDecompile Server Options` to change host/port/credentials.

Run Ghidra for configuration (Windows):

```powershell
# From your Ghidra install dir
.\support\analyzeHeadless.bat    # or run_ghidra.bat to open the GUI
```

Run Ghidra (Linux/macOS):

```bash
./run_ghidra      # executable in the Ghidra root
```

After Ghidra boots, open or create a project, open the Code Browser (green dragon), then `File -> Extensions` and enable `AgentDecomp` and `PyGhidra`.

Example external decompile server
- Host: biodecompwarehouse.beatapostapita.bolabaden.org
- User: OldRepublicDevs
- Password: changeme (may also be `MuchaShakaPaka`) — verify with admin.

Ubuntu / Fedora
- Recommended: SDKMAN!

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install gradle
```

Alternative (snap):

```bash
sudo snap install gradle --classic
```

macOS
- Use Homebrew:

```bash
brew install gradle
```

Or use SDKMAN! as above.

Manual (all OS) — scriptable
- Download Gradle binary and extract; add `gradle/bin` to PATH. Example download URL: `https://services.gradle.org/distributions/gradle-9.3.0-bin.zip`.

Troubleshooting
- If `build-and-install.ps1` fails due to locked files: stop Python/Ghidra processes that reference `agentdecompile` and retry.
- If Python deps fail (e.g., `pandas` pinned to older versions), either use a supported Python version or update the pinned package.