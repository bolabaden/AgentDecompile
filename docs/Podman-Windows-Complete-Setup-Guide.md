# Complete Podman on Windows Setup Guide: Docker Replacement, Compose, and Builds

**A step-by-step walkthrough for running Podman on Windows 10 and 11, making `docker` and `docker compose` work, and avoiding common build failures.**

---

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: Install Podman Desktop and Podman](#step-1-install-podman-desktop-and-podman)
- [Step 2: Make `docker` and `docker compose` Use Podman](#step-2-make-docker-and-docker-compose-use-podman)
  - [Option A: Symlink `docker.exe` to Podman (CLI parity)](#option-a-symlink-dockerexe-to-podman-cli-parity)
  - [Option B: Real Docker CLI + Podman socket (best for IDEs)](#option-b-real-docker-cli--podman-socket-best-for-ides)
  - [Option C: WSL2 + batch wrappers (all from Windows shell)](#option-c-wsl2--batch-wrappers-all-from-windows-shell)
- [Step 3: Set up Compose in Podman Desktop](#step-3-set-up-compose-in-podman-desktop)
- [Step 4: Build Caching and BuildKit](#step-4-build-caching-and-buildkit-cache-mounts)
- [Step 5: Building Images with Podman](#step-5-building-images-with-podman-eg-dockerfile-that-fetches-github-releases)
- [Quick reference](#quick-reference)
- [Bibliography (Chicago style)](#bibliography-chicago-style)

---

## Introduction

On Windows, many guides and scripts assume the Docker CLI and `docker compose`. If you use **Podman** instead of Docker Desktop—for licensing, resource use, or preference—you can still run the same workflows by pointing `docker` and `docker compose` at Podman. This guide walks through the **best-practice setup** on Windows 10 and 11: installing Podman, making `docker` and `docker compose` usable from PowerShell and Command Prompt, and fixing issues such as GitHub release URLs returning HTML instead of JSON in container builds.

---

## Prerequisites

- **Windows 10** (build 19043 or later) or **Windows 11**
- **WSL 2** (Windows Subsystem for Linux 2). Podman on Windows runs via a WSL 2 backend. <sup>1</sup>
- At least **6 GB RAM** for the Podman machine
- **Administrator rights** for enabling WSL and installing software

Enable WSL 2 if needed:

```powershell
wsl --install --no-distribution
```

Restart when prompted, then optionally install a distribution (e.g. Ubuntu) from the Microsoft Store.

---

## Step 1: Install Podman Desktop and Podman

1. Download the Windows installer from the official site: [Podman Desktop – Get Started](https://podman-desktop.io/downloads/windows). <sup>2</sup>
2. Run the installer. During first launch, complete the setup (image registries, Podman engine, WSL 2 if required).
3. Confirm Podman is on your PATH: open a **new** PowerShell or Command Prompt and run:

   ```powershell
   podman --version
   ```

   You should see a version string (e.g. Podman 4.x or 5.x).

4. *(Optional)* Install the Docker CLI for later steps (symlink or socket method):
   ```powershell
   winget install Docker.DockerCLI
   ```

---

## Step 2: Make `docker` and `docker compose` Use Podman

Three approaches are widely recommended; choose one.

### Option A: Symlink `docker.exe` to Podman (CLI parity)

This is the approach documented in multiple community articles. <sup>3,4</sup> After installing the Docker CLI via `winget`, replace `docker.exe` with a symlink to Podman so that `docker` and `docker compose` both run Podman.

1. Open PowerShell and go to the WinGet links directory:
   ```powershell
   cd $env:LOCALAPPDATA\Microsoft\WinGet\Links
   ```
2. Back up and replace the Docker executable:
   ```powershell
   Rename-Item docker.exe docker-ori.exe
   New-Item -ItemType SymbolicLink -Path "docker.exe" -Target "C:\Program Files\RedHat\Podman\podman.exe"
   ```
   Adjust the `Target` path if Podman is installed elsewhere (e.g. under `Program Files`).
3. *(Optional)* Add your user to `docker-users` and restart:
   ```powershell
   net localgroup docker-users /add
   net localgroup docker-users $env:USERNAME /add
   ```
   Then log out and back in (or restart).
4. Verify:
   ```powershell
   docker --version
   docker compose version
   ```

**Caveat:** Some sources report that this symlink works for the command line but not for all IDEs (e.g. Visual Studio, VS Code). <sup>5</sup> If your IDE expects a real Docker CLI talking to a socket, use Option B instead.

### Option B: Real Docker CLI + Podman socket (best for IDEs)

Use the **official Docker CLI** and point it at Podman’s socket so that `docker` and `docker compose` talk to Podman. This is the approach recommended when tools (including IDEs) invoke `docker` and expect API/socket behavior. <sup>5</sup>

1. Install Podman Desktop and ensure a Podman machine is running.
2. In **Podman Desktop**: **Settings → Docker Compatibility** → enable Docker compatibility.  
   Default Windows socket: `npipe:////./pipe/docker_engine`. <sup>6</sup>
3. Install the Docker CLI (e.g. from [Docker’s static binaries](https://download.docker.com/win/static/stable/x86_64/) or via `winget install Docker.DockerCLI`). Put `docker.exe` in a folder on your PATH.
4. Set the Podman pipe so the Docker CLI uses Podman:
   ```powershell
   # Get the pipe path (if different from default)
   podman machine inspect --format '{{.ConnectionInfo.PodmanPipe.Path}}'
   # Set DOCKER_HOST (use forward slashes and npipe:// prefix)
   [System.Environment]::SetEnvironmentVariable('DOCKER_HOST', 'npipe:////./pipe/docker_engine', 'User')
   ```
   Restart the terminal (or reboot) so the variable is picked up.
5. In the same terminal:
   ```powershell
   docker ps
   docker compose version
   ```

Podman Desktop’s docs note that on Windows you may need to set `DOCKER_HOST` explicitly for commands like `podman compose` or when the “socket of machine is not set” error appears. <sup>7</sup>

### Option C: WSL2 + batch wrappers (all from Windows shell)

If Podman and Compose run **inside WSL2**, you can expose `docker` and `docker compose` from Windows by placing small batch files on your PATH that forward to WSL. This pattern is used in projects such as **wsl2-podman**. <sup>8,9</sup>

1. Install WSL2 and a distribution (e.g. Ubuntu). Inside WSL, install Podman (and optionally `podman-compose`).
2. On Windows, create a folder on your PATH (e.g. `C:\Users\<You>\bin`). Add a file `docker.cmd`:
   ```batch
   @echo off
   wsl -d Ubuntu -- podman %*
   ```
   Replace `Ubuntu` with your WSL distro name (`wsl -l -q` to list).
3. For Compose, create `docker-compose.cmd`:
   ```batch
   @echo off
   wsl -d Ubuntu -- podman compose %*
   ```
4. From cmd or PowerShell you can then run `docker` and `docker compose`; they execute Podman (and Podman Compose) inside WSL.

---

## Step 3: Set up Compose in Podman Desktop

For Compose to work cleanly with Podman Desktop:

1. Open **Podman Desktop** → **Settings** → **Resources**.
2. Under **Compose**, click **Setup** and follow the prompts to install/configure the Compose CLI.
3. Verify in a terminal:
   ```powershell
   podman compose --help
   ```
   If you used Option A or B, also run `docker compose --help`.

You can run Compose apps with either `podman compose` or `docker compose` once the above is configured. <sup>10</sup>

---

## Step 4: Build Caching and BuildKit (cache mounts)

The AgentDecompile Dockerfile uses **layer caching** (same as Docker) and optional **cache mounts** (apk, Gradle) to speed up rebuilds. Both work with Podman.

- **Layer cache:** Podman caches steps (e.g. install packages, download Ghidra). When only your code changes, earlier steps are reused. No extra setup.
- **Cache mounts:** The Dockerfile uses `--mount=type=cache` for `/var/cache/apk` and `/root/.gradle`. To enable these with Podman (or when using `docker compose build` against Podman), set **BuildKit** mode:

  **PowerShell (current session):**
  ```powershell
  $Env:DOCKER_BUILDKIT="1"
  ```

  **PowerShell (permanent for your user):**
  ```powershell
  [System.Environment]::SetEnvironmentVariable('DOCKER_BUILDKIT','1','User')
  ```
  Restart the terminal (or reboot) so new processes see it.

  **Command Prompt (current session):**
  ```cmd
  set DOCKER_BUILDKIT=1
  ```

Then run `podman compose build` or `docker compose build` as usual. With `DOCKER_BUILDKIT=1`, apk and Gradle caches are reused across builds so repeated builds are faster even when a step is re-run.

---

## Step 5: Building Images with Podman (e.g. Dockerfile that fetches GitHub releases)

Many Dockerfiles use `curl` to fetch “latest” release metadata from GitHub. A common mistake is to request the **web** URL (e.g. `https://github.com/Org/Repo/releases/latest`), which returns **HTML**. Scripts that pipe that response into `jq` then fail with parse errors.

**Fix:** Use the **GitHub API** URL so the response is JSON:

- **Web (HTML):** `https://github.com/NationalSecurityAgency/ghidra/releases/latest`
- **API (JSON):** `https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest`

In your Dockerfile or build script:

1. Use the API base URL, e.g. `https://api.github.com/repos/NationalSecurityAgency/ghidra`.
2. Request the release endpoint with `curl -sSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/Org/Repo/releases/latest"`.
3. Pipe that output to `jq` to extract asset URLs (e.g. `.assets[].browser_download_url`).

Example pattern:

```dockerfile
ENV GHIDRA_GITHUB_API=https://api.github.com/repos/NationalSecurityAgency/ghidra
RUN API_URL="${GHIDRA_GITHUB_API}/releases/latest"; \
    BODY="$(curl -sSL -H 'Accept: application/vnd.github+json' "${API_URL}")"; \
    DOWNLOAD_URL="$(echo "${BODY}" | jq -r '.assets[] | select(.name | test("\\.zip$")) | .browser_download_url' | head -n 1)"; \
    curl -sSL -o /tmp/ghidra.zip "${DOWNLOAD_URL}"; \
    # ... unzip and install
```

This works the same under both Docker and Podman.

---

## Quick reference

| Goal                         | Action |
|-----------------------------|--------|
| Use `docker` as Podman      | Symlink `docker.exe` → `podman.exe` (Option A) or set `DOCKER_HOST` to Podman socket (Option B). |
| Use `docker compose`       | Option A or B, and complete Podman Desktop Compose setup (Step 3). |
| IDE (VS/VS Code) + Podman  | Prefer Option B (real Docker CLI + `DOCKER_HOST`). <sup>5</sup> |
| No Docker CLI at all       | Use `podman` and `podman compose` directly; optional batch wrappers (Option C) from Windows to WSL. |
| Build cache mounts (apk/Gradle) | Set `DOCKER_BUILDKIT=1` (PowerShell: `$Env:DOCKER_BUILDKIT="1"`). See Step 4. |
| Reliable GitHub release URL| Use `api.github.com/repos/.../releases/latest` and `Accept: application/vnd.github+json`. |

---

## Bibliography (Chicago style)

1. Red Hat, Inc. “Installing Podman Desktop and Podman on Windows.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/installation/windows-install](https://podman-desktop.io/docs/installation/windows-install).

2. Podman Desktop. “Downloads – Windows.” Podman Desktop. Accessed February 21, 2026. [https://podman-desktop.io/downloads/windows](https://podman-desktop.io/downloads/windows).

3. Peter Saktor. “Replacing Docker with Podman on Windows.” DEV Community. February 2024. [https://dev.to/petersaktor/replacing-docker-with-podman-on-windows-56ee](https://dev.to/petersaktor/replacing-docker-with-podman-on-windows-56ee).

4. “Replacing Docker with Podman on Windows.” ClawCloud Run Blog. 2024. [https://blog.run.claw.cloud/17/](https://blog.run.claw.cloud/17/).

5. Aloneguid. “Making Docker tools work with Podman on Windows.” December 2024. [https://www.aloneguid.uk/posts/2024/12/making-docker-tools-work-with-podman-windows/](https://www.aloneguid.uk/posts/2024/12/making-docker-tools-work-with-podman-windows/).

6. Red Hat, Inc. “Managing Docker compatibility.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/migrating-from-docker/managing-docker-compatibility](https://podman-desktop.io/docs/migrating-from-docker/managing-docker-compatibility).

7. Red Hat, Inc. “Using the DOCKER_HOST environment variable.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/migrating-from-docker/using-the-docker_host-environment-variable](https://podman-desktop.io/docs/migrating-from-docker/using-the-docker_host-environment-variable).

8. Rosenbjerg. “WSL2 + podman.” Rosenbjerg blog. Accessed February 21, 2026. [https://rosenbjerg.dk/posts/podman-docker-desktop-alternative/](https://rosenbjerg.dk/posts/podman-docker-desktop-alternative/).

9. rosenbjerg. *wsl2-podman*. GitHub repository. [https://github.com/rosenbjerg/wsl2-podman](https://github.com/rosenbjerg/wsl2-podman).

10. Red Hat, Inc. “Running Compose files.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/compose/running-compose](https://podman-desktop.io/docs/compose/running-compose).

11. Red Hat, Inc. “Setting up Compose.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/compose/setting-up-compose](https://podman-desktop.io/docs/compose/setting-up-compose).

12. Red Hat, Inc. “Emulating Docker CLI with Podman.” Podman Desktop Documentation. Accessed February 21, 2026. [https://podman-desktop.io/docs/migrating-from-docker/emulating-docker-cli-with-podman](https://podman-desktop.io/docs/migrating-from-docker/emulating-docker-cli-with-podman).

---

*This guide is intended for use with AgentDecompile and general Podman-on-Windows workflows. For the latest Podman Desktop and Windows support, refer to the official Podman Desktop documentation.*
