---
name: agentdecompile-server-env
description: Environment setup, env-var reference, and MCP session/proxy behavior for running the agentdecompile MCP server, including on the Cursor Cloud VM. Use when starting the MCP server locally, configuring auto-match/auto-checkin/analysis-tier env vars, or debugging session-id/proxy-forwarding behavior.
---

# AgentDecompile MCP Server: Environment and Session Reference

## Environment

- **Python 3.10+** and **Java 21** (OpenJDK) are pre-installed in the Cursor Cloud VM.
- **Ghidra 12.0.4** is installed at `/opt/ghidra-install/ghidra_12.0.4_PUBLIC`. Set `GHIDRA_INSTALL_DIR` accordingly.
- **uv** package manager is at `~/.local/bin/uv`. Ensure `$HOME/.local/bin` is on `PATH`.
- **PyGhidra** is installed from Ghidra's bundled pypkg (not PyPI). The update script reinstalls it from `$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg`.
- **ruff** is in the `dev` dependency group (`uv sync --dev`); CI runs `uv run ruff check` via `test-unit.yml`.
- chromadb (semantic search) is optional and not installed; the server logs a warning but operates normally without it.

## Injected secrets (environment variables)

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

**Max analysis tier filter** (optional):

- **`AGENTDECOMPILE_MAX_ANALYSIS_TIER`** (alias **`AGENT_DECOMPILE_MAX_ANALYSIS_TIER`**): When set to `2` or `3`, `tools/list` and `agentdecompile://capabilities` expose only tools with `analysis_tier` ≤ that value. Unset = no filter. **`tools/call` is unchanged** — tier-3 tools remain callable when hidden from the list. **HTTP equivalent:** header `X-AgentDecompile-Max-Analysis-Tier` with value `2` or `3` (per-request override; invalid values fall back to env).

**Auto check-in** (optional):

- **`AGENTDECOMPILE_AUTO_CHECKIN`**: When set to `1` or `true`, after any modifying tool succeeds (e.g. `manage-symbols` rename/create_label, `manage-function` rename/set_prototype, `manage-comments` set, `manage-structures` create/apply, `apply-data-type`, `manage-bookmarks` set, `manage-function-tags` add/remove, `match-function`), the server automatically runs **checkin-program** with no path (check in all): for **shared/versioned** programs it checks them in to the server; for **local** (non-versioned) programs it saves to disk. When this is set, **checkin-program** is not advertised, since check-ins/saves happen automatically.

**Checkin all** (when auto-checkin is off): Call **checkin-program** with no `programPath` (or omit the parameter) to check in every open program in the session that is checked out and can be checked in, so changes are not left locked.

## Running the MCP server locally

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

## Session and proxy behavior

- **Session id:** The server (or proxy) assigns an MCP session id at initialization and returns it in response headers (`mcp-session-id`). Clients must send it on all subsequent requests (MCP Streamable HTTP spec).
- **CLI persistence:** The CLI persists the session id per normalized backend URL (in `.agentdecompile/cli_state.json`) and sends it on later invocations when the same `--server-url` is used, so `open-project` in one run and `checkout-program` in a second run can reuse the same server session.
- **Proxy forwarding:** Proxies (e.g. agentdecompile-proxy) must forward the client's `mcp-session-id` header to the backend so the same logical session is used end-to-end. Without that, the backend sees a new session each request and shared-project state from a previous `open-project` is not available.

## Default session

When no session id is provided (no `mcp-session-id` header and no session cookie), the server uses a single stable session id `"default"`. All such requests share the same in-memory session, so multiple requests (e.g. sequential CLI invocations) can reuse the same session without the client persisting a session id. **Caveat:** Multiple independent clients that do not send a session id will share the same default session. Single-user or single-client use is the intended case for "no session id"; for multi-user or multi-session use, clients should send distinct session ids (or use cookies so each gets a distinct id).

## Session id in logs (security)

Do not log full MCP session ids. Use a redacted form (e.g. first 8-12 characters + "…") or "present" in all log messages. If any middleware or handler logs response bodies, ensure `sessionId` is redacted or excluded (e.g. debug_info returns `sessionId` in payloads; do not log those payloads in full).

## Session state caveat

CLI reuses the same server session across invocations when the same `--server-url` is used, provided the server (or proxy) forwards the session id. If you use a proxy, ensure it forwards `mcp-session-id` to the backend. Programs loaded in one session are available in the next run only when the session is preserved. Use `tool-seq` to chain multiple tool calls (open, analyze, list, decompile) within a single run, or pass binaries as positional arguments to `agentdecompile-server` so they are imported at startup.

## Lint, test, build

| Task | Command |
|------|---------|
| Lint | `uv run ruff check --no-fix src/ tests/` |
| Test (all) | `uv run pytest tests/ -v --timeout=180` |
| Test (unit only) | `uv run pytest -m unit -v` |
| Test (analysis gate) | `uv run pytest tests/test_program_analysis_gate.py tests/test_tool_providers_analysis_gate.py -m unit -q` |
| CI (unit, no Ghidra) | GitHub Actions workflow `test-unit.yml` on PRs to `master` |
| Build | `uv build` |

Pre-existing lint violations (36 errors) exist in the codebase; they are not caused by the development environment. Docker-dependent e2e tests require a running Docker environment to pass.
