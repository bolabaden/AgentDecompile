# AGENTS.md

See [README.md](README.md) for project overview, [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, and [src/CLAUDE.md](src/CLAUDE.md) for architecture details.

## Cursor Cloud specific instructions

### Environment

- **Python 3.10+** and **Java 21** (OpenJDK) are pre-installed in the VM.
- **Ghidra 12.0.4** is installed at `/opt/ghidra-install/ghidra_12.0.4_PUBLIC`. Set `GHIDRA_INSTALL_DIR` accordingly.
- **uv** package manager is at `~/.local/bin/uv`. Ensure `$HOME/.local/bin` is on `PATH`.
- **PyGhidra** is installed from Ghidra's bundled pypkg (not PyPI). The update script reinstalls it from `$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg`.
- **ruff** is installed for linting (not a project dependency, installed separately via `uv pip install ruff`).
- chromadb (semantic search) is optional and not installed; the server logs a warning but operates normally without it.

### Injected secrets (environment variables)

**agentdecompile-server** is always a local instance (PyGhidra/JVM); it does not use proxy URL env vars. For local server runs, **unset** Ghidra server credentials if you do not want HTTP Basic Auth on MCP requests:

```bash
unset AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME
unset AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD
unset AGENT_DECOMPILE_GHIDRA_SERVER_HOST
unset AGENT_DECOMPILE_GHIDRA_SERVER_PORT
unset AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY
```

To run in **proxy mode** (forward to a remote MCP backend), use **agentdecompile-proxy** and set `AGENT_DECOMPILE_MCP_SERVER_URL` or `AGENTDECOMPILE_MCP_SERVER_URL` (or pass `--backend-url`).

**Auto match-function propagation** (optional):

- **`AGENTDECOMPILE_AUTO_MATCH_PROPAGATE`**: When set to `1` or `true`, after function-modifying tools (`rename-function`, `manage-function` with rename/set_prototype/set_return_type/set_calling_convention, `manage-comments` with set/post/eol/etc., `manage-function-tags` with add/remove), the server automatically runs match-function for the modified function to configured target binaries, propagating names, tags, all comment types, prototype, and bookmarks, and checks in target programs (minimizing lock time when it checked them out). For **local .gpr projects**, propagation runs in a **child process** (ProcessPoolExecutor, spawn) so the main MCP process is not blocked; for shared-server or other sessions it runs in-process. **HTTP equivalent:** send header `X-AgentDecompile-Auto-Match-Propagate` with value `1`, `true`, or `yes` (per-request override).
- **`AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS`**: Optional comma-separated list of target program paths for auto propagation. If unset, other open programs in the session are used as targets. **HTTP equivalent:** `X-AgentDecompile-Auto-Match-Target-Paths` (comma-separated paths; per-request override).

**Checkin all**: Call **checkin-program** with no `programPath` (or omit the parameter) to check in every open program in the session that is checked out and can be checked in, so changes are not left locked.

### Running the MCP server locally

```bash
export PATH="$HOME/.local/bin:$PATH"
export GHIDRA_INSTALL_DIR=/opt/ghidra-install/ghidra_12.0.4_PUBLIC
# Unset Ghidra server credentials if you do not want auth (see above)
uv run agentdecompile-server -t streamable-http --host 127.0.0.1 --port 8080 \
  --project-path /tmp/agentdecompile-projects /path/to/binary
```

The server takes ~3 seconds to initialize PyGhidra/JVM. Once running, use the CLI:

```bash
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq \
  '[{"name":"open-project","arguments":{"path":"/path/to/binary"}},
    {"name":"analyze-program","arguments":{"programPath":"binaryname"}},
    {"name":"list-functions","arguments":{"programPath":"binaryname","limit":10}}]'
```

### Session and proxy behavior

- **Session id:** The server (or proxy) assigns an MCP session id at initialization and returns it in response headers (`mcp-session-id`). Clients must send it on all subsequent requests (MCP Streamable HTTP spec).
- **CLI persistence:** The CLI persists the session id per normalized backend URL (in `.agentdecompile/cli_state.json`) and sends it on later invocations when the same `--server-url` is used, so `open-project` in one run and `checkout-program` in a second run can reuse the same server session.
- **Proxy forwarding:** Proxies (e.g. agentdecompile-proxy) must forward the client's `mcp-session-id` header to the backend so the same logical session is used end-to-end. Without that, the backend sees a new session each request and shared-project state from a previous `open-project` is not available.

### Session state caveat

CLI reuses the same server session across invocations when the same `--server-url` is used, provided the server (or proxy) forwards the session id. If you use a proxy, ensure it forwards `mcp-session-id` to the backend. Programs loaded in one session are available in the next run only when the session is preserved. Use `tool-seq` to chain multiple tool calls (open, analyze, list, decompile) within a single run, or pass binaries as positional arguments to `agentdecompile-server` so they are imported at startup.

### Lint, test, build

| Task | Command |
|------|---------|
| Lint | `uv run ruff check --no-fix src/ tests/` |
| Test (all) | `uv run pytest tests/ -v --timeout=180` |
| Test (unit only) | `uv run pytest -m unit -v` |
| Build | `uv build` |

Pre-existing lint violations (36 errors) exist in the codebase; they are not caused by the development environment. Unit tests have 1 pre-existing failure in `test_unified_provider_advertisement.py`; Docker-dependent e2e tests require a running Docker environment to pass.

## Naming Conventions

When generating or suggesting names for symbols, variables, parameters, fields, types, or constants during reverse engineering work, apply these conventions consistently:

| Identifier kind | Convention | Example |
|---|---|---|
| Local variables | `camelCase` | `itemCount`, `saveBuffer` |
| Global variables | `camelCase` | `gameState`, `playerStats` |
| Function parameters | `camelCase` | `charIndex`, `saveFilePath` |
| Classes and types | `CapitalCase` (PascalCase) | `SaveGameHeader`, `ItemRecord` |
| Structure fields | `snake_case` | `save_version`, `char_name` |
| Enum constants | `COBRA_CASE` (SCREAMING_SNAKE) | `SAVE_SLOT_EMPTY`, `ITEM_TYPE_WEAPON` |

Apply these conventions in:
- Decompiled pseudocode variable and parameter names produced by `decompile-function` or `execute-script`
- Symbol rename suggestions from `rename-function`, `rename-variable`, `rename-data-label`
- Structure and field names in `create-structure` / `edit-structure` tool calls
- Enum members defined via `create-enum` / `edit-enum`
- Documentation, comments, and analysis summaries that reference named symbols

When a name is ambiguous or cannot be inferred, prefer the convention that matches the identifier category above rather than leaving it in a raw mangled/numbered form (e.g., prefer `slotIndex` over `local_8` for a loop counter).

## Learned User Preferences

- Prefer implementing and running (config, env, live tests) over returning instructions for the user to run.
- After fixing an issue, continue with the task without asking; run and verify, and if still broken fix and rerun until functional.
- Fix the underlying behavior so the same user commands work unchanged; do not only improve error messages or documentation.
- Use the MCP server tools (e.g. user-agdec-http) for agentdecompile workflows rather than the CLI when both are available.
- Default to markdown (not JSON) for tool output; scale output detail by result count (few results = full detail, many = trimmed).
- Prefer supporting Ghidra server auth via headers or CLI args when possible, not only via process environment.

## Learned Workspace Facts

- When editing KOTOR or video-derived docs (e.g. docs/from_video), use correct terms: KOTOR (not Cotor), PyGhidra (Ghidra v12 Python wrapper), swkotor.exe (not sodtor.exe), CSWMinigame (not miniame).
- open-project: analyzeAfterImport is optional and defaults to true.
- Load Ghidra path from environment (e.g. GHIDRA_INSTALL_DIR); use a top-level .env at repo root; do not hardcode install paths.
- Project-level Cursor skills live under .cursor/skills/ (SKILL.md + references/), not under docs/.
- In prompts and docs use semantic tool names (rename-function, set-function-prototype) not the legacy manage-function name.
- For proxy mode: set AGENTDECOMPILE_PROJECT_PATH (and AGENTDECOMPILE_PROJECT_NAME) so the proxy sends X-AgentDecompile-Project-Path to the backend; for two simultaneous sessions with different projects run two backends and point each proxy at a different backend URL.
- For tools that accept an optional program_path (e.g. checkout-status), resolve the domain file by that path (session + project_data) and use it for the operation; do not default to the active program only, so shared-only paths report versioned status correctly.
- CLI persists MCP session id per server URL so that open-project then checkout-program in two separate invocations reuse the same server session when the same --server-url is used.

## MCP server debugging & self-healing

When investigating or fixing MCP server issues (timeouts, schema, GUI/coords, sandbox), use the **mcp-debugging** skill: open [.cursor/skills/mcp-debugging/SKILL.md](.cursor/skills/mcp-debugging/SKILL.md) or invoke `/mcp-debugging` in Agent chat. The skill references the meta-debug loop and the five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI). Detailed docs: [references/CLIS_AND_META_DEBUG.md](.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md), [references/WORKFLOWS.md](.cursor/skills/mcp-debugging/references/WORKFLOWS.md), [references/CLAUDE_MCP_DEBUG.md](.cursor/skills/mcp-debugging/references/CLAUDE_MCP_DEBUG.md).
