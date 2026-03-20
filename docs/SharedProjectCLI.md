# Shared Ghidra project via CLI

This describes how to use the CLI so that **open** connects to a **shared** Ghidra server repository (not a local project). After that, **list-project-files** shows contents from the shared repo (`source: shared-server-session`), and **import-binary** with `enableVersionControl: true` adds binaries to that repo. All tools (analyze-program, decompile-function, checkout-program, etc.) then operate on the shared session.

## Prerequisites

1. **Ghidra server** must be running and reachable (e.g. `docker run` with Ghidra server image, or `svrLaunch` / `ghidraSvr` from a Ghidra install).
2. **agentdecompile-server** (MCP backend) must be running with a local project path for PyGhidra (e.g. `--project-path ./docker/shared_server_project`). The backend uses this dir for project metadata; shared repo content comes from the Ghidra server. Use the **latest code** (run from source with `uv run agentdecompile-server ...` or rebuild the Docker image) so shared-project behavior is correct: repo creation when missing, **import-binary** using shared mode (`mode == "shared-server"`), and **list-project-files** always returning `source: shared-server-session` when the session is shared.
3. **CLI** talks to the backend (direct `--server-url` or via a proxy).
4. **First step:** always call **open** with `shared: true` and server/repo args so the session is in shared-server mode. Then **list-project-files**, **import-binary**, **checkout-program**, **analyze-program**, **decompile-function**, etc. all use that shared project.

## 1. Start Ghidra server (example)

From the repo root, if using Docker:

```powershell
# Example: run Ghidra server (adjust image/ports as needed)
docker run -d -p 13100:13100 --name ghidra-svr <your-ghidra-server-image>
```

Or use Ghidra’s `server/svrLaunch` (or `ghidraSvr console`) and create a repository (e.g. `agentrepo`) and user (e.g. `admin`/password).

## 2. Start the MCP backend

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"   # or your install
uv run agentdecompile-server -t streamable-http --host 127.0.0.1 --port 8080 --project-path ./docker/shared_server_project
```

Leave this running.

## 3. Open shared project and list files (CLI)

Use **open** with shared server args, then **list-project-files**. The response should show `"source": "shared-server-session"` when the session is using the shared repo.

**PowerShell (JSON from file, recommended):**

```powershell
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq (Get-Content scripts\shared_open_list.json -Raw)
```

**PowerShell (one-liner with inline JSON):**

```powershell
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq '[{"name":"open","arguments":{"shared":true,"serverHost":"127.0.0.1","serverPort":13100,"serverUsername":"admin","serverPassword":"admin","path":"agentrepo"}},{"name":"list-project-files","arguments":{}}]'
```

**Using env vars (no auth in command):**

```powershell
$env:AGENT_DECOMPILE_GHIDRA_SERVER_HOST = "127.0.0.1"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_PORT = "13100"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME = "admin"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD = "admin"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY = "agentrepo"
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq (Get-Content scripts\shared_open_list.json -Raw)
```

If **open** succeeds, **list-project-files** returns entries from the shared repository and the response includes `"source": "shared-server-session"`. If the Ghidra server is not reachable, you get a clear error (e.g. “Ghidra server not reachable at …”).

## 4. Import a binary into the shared repo

After opening the shared project, use **import-binary** with `enableVersionControl: true` so the binary is added to the shared repository (not only to a local project):

```powershell
uv run agentdecompile-cli tool-seq '[{"name":"open","arguments":{"shared":true,"serverHost":"127.0.0.1","serverPort":13100,"serverUsername":"admin","serverPassword":"admin","path":"agentrepo"}},{"name":"import-binary","arguments":{"path":"C:\\path\\to\\some.exe","enableVersionControl":true}},{"name":"list-project-files","arguments":{}}]' --server-url http://127.0.0.1:8080
```

Then confirm with **list-project-files** or on the Ghidra server (e.g. `svrAdmin -list`) that the binary appears in the shared repo.

## Verifying shared mode

To confirm the session is using the shared repository (not a local project):

1. After **open** with shared args, run **list-project-files**. The response must include `"source": "shared-server-session"`.
2. If you see `"source": "local-ghidra-project"`, the session is not in shared mode—call **open** again with `shared: true` and valid `serverHost`/`serverPort`/credentials/`path`.

**Test script (Python, recommended):**

```bash
uv run python scripts/test_shared_project.py
# Or with a custom server URL:
uv run python scripts/test_shared_project.py http://127.0.0.1:8080
```

**Test script (PowerShell):** Use single-line JSON so the argument is passed correctly: `scripts\shared_open_list_oneline.json`, then run `.\scripts\test_shared_project.ps1`.

## Docker Compose

With `docker-compose up` (ghidra + agentdecompile-mcp), the MCP backend runs inside a container and has `AGENT_DECOMPILE_GHIDRA_SERVER_HOST=ghidra` set so it can reach the Ghidra service. From the host, run the CLI **without** setting `AGENT_DECOMPILE_GHIDRA_SERVER_HOST` so the backend uses its container env (the host’s 127.0.0.1 would not reach Ghidra from inside the container). **Ghidra server has no users by default.** Add one so the backend can connect and create repositories: `docker exec ghidra /ghidra/server/svrAdmin -add ghidra`, then `docker restart ghidra` and wait ~15s. Use `scripts\shared_open_list_docker.json` (includes path, repositoryName, serverUsername; set serverPassword in the JSON if the user has a password). The backend creates the repository `agentrepo` if it does not exist when serverUsername is provided.

```powershell
# If Docker was using a broken context (e.g. podman-machine-default2), switch to default:
docker context use default

docker-compose up -d ghidra agentdecompile-mcp
# Add a user (required; Ghidra has no users by default):
docker exec ghidra /ghidra/server/svrAdmin -add ghidra
docker restart ghidra
# Wait ~15s for Ghidra to come back, then verify shared project (one command):
uv run python scripts/verify_shared_project_full.py --server-url http://127.0.0.1:8080 --server-host ghidra --username ghidra --password admin

# Optional: full workflow including import + checkout + analyze + list-functions (use a path to a real binary):
uv run python scripts/verify_shared_project_full.py --server-url http://127.0.0.1:8080 --server-host ghidra --username ghidra --password admin --binary tests/fixtures/test_x86_64
```

Quick CLI check (open + list only):

```powershell
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq (Get-Content scripts\shared_open_list_docker.json -Raw)
```

## E2E script

To verify the shared-project flow end-to-end (open → list with `source: shared-server-session`):

```powershell
# Backend + Ghidra on same host (set host/port/credentials):
$env:AGENT_DECOMPILE_GHIDRA_SERVER_HOST = "127.0.0.1"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_PORT = "13100"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME = "admin"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD = "admin"
uv run python scripts/run_shared_project_e2e.py

# Docker Compose (backend has host=ghidra in container; do not set host on Windows):
uv run python scripts/run_shared_project_e2e.py --server-url http://127.0.0.1:8080
```

Exit code 0 means `list-project-files` returned `source: shared-server-session`.

## Troubleshooting

- **“Ghidra server not reachable” / “[Errno 22] Invalid argument”**  
  Ensure `serverHost` is a valid hostname or IP and `serverPort` is an integer (e.g. `13100`). Start the Ghidra server and retry.

- **list-project-files shows local project content**  
  Call **open** first with `shared: true` and valid `serverHost`/`serverPort`/credentials/`path` (repo name). After a successful shared open, listing uses the shared repo and shows `"source": "shared-server-session"`.

- **Backend not found**  
  Start **agentdecompile-server** and point the CLI at it with `--server-url` (or use a proxy that forwards to that backend).
