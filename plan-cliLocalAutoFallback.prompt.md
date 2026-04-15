## Plan: CLI Local Auto-Fallback

Add automatic local execution behavior to `agentdecompile-cli` when no explicit MCP backend was requested. Recommended behavior: preserve strict failure for explicit `--server-url` / `--host` / `--port` intent, ignore invalid env/default backend targets, first try a reusable local auto-started HTTP server, and fall back to the existing in-process `LocalToolBackend` when no usable local server is available. Persist local server endpoint/process metadata in the existing CLI state file so later invocations can reuse it.

**Steps**
1. Define backend-intent classification in `src/agentdecompile_cli/cli.py` / `src/agentdecompile_cli/executor.py`: distinguish explicit CLI target (`--server-url`, `--host`, `--port`, aliases), env-derived target, cached auto-start target, and implicit default localhost target. This step blocks all later work because fallback policy depends on knowing whether the user explicitly asked for a remote/local HTTP backend.
2. Add a small local-backend orchestration layer, preferably as a focused helper module such as `src/agentdecompile_cli/local_autostart.py` or adjacent helpers in `src/agentdecompile_cli/cli.py`. Responsibilities: probe whether a candidate MCP server is reachable, read/write persisted local server metadata from `.agentdecompile/cli_state.json`, choose a port, spawn `agentdecompile_cli.server` / `agentdecompile-server` in background on localhost, wait for readiness, and discard stale state when the process/port is dead. This depends on step 1.
3. Update CLI dispatch in `src/agentdecompile_cli/cli.py` so `_execute_tool_call()` no longer treats all `ServerNotRunningError` cases equally. Flow: if `--local` was explicitly selected, keep current in-process behavior; otherwise, when no explicit backend target was requested, attempt HTTP client against cached/default local endpoint, auto-start local server if needed, then retry the tool call; if auto-start cannot succeed, route the command through `LocalToolBackend` in-process. If the backend target came from env vars and is invalid, ignore it and follow the same local fallback path. If the backend target came from explicit CLI parameters, preserve current failure semantics and show the connection error.
4. Extend CLI state handling in `src/agentdecompile_cli/cli.py` to persist auto-start metadata under the existing backend-scoped state structure or a clearly separated `local_server` section. Store only what is needed for reuse and cleanup decisions: normalized localhost MCP URL, chosen port, start timestamp, optional pid, and maybe a marker that the endpoint was CLI-managed. Make sure cached server metadata does not override explicit `--server-url` or leak into remote/shared scopes. This can be implemented in parallel with step 3 once the orchestration API shape is clear.
5. Update user-facing messaging and help text in `src/agentdecompile_cli/cli.py` and `src/agentdecompile_cli/executor.py`: remove or narrow the current “Please start the AgentDecompile server first” guidance so it is shown only for explicit CLI backend targets or for true unrecoverable local startup failures. Add concise stderr diagnostics for the new path, for example: reusing cached local server, starting local server on port X, or falling back to in-process local mode.
6. Add focused automated coverage. Recommended split: unit tests for backend-intent classification and state persistence helpers; CLI tests that mock connection failure, auto-start success, env-url ignore behavior, and explicit `--server-url` strict failure; one integration-style test that exercises `tool execute-script` through the new path without a prestarted server. This depends on steps 1-5.
7. Update docs only where this behavior is user-visible and likely to surprise people: CLI help examples in `README.md`, `USAGE.md`, and possibly `CONTRIBUTING.md` runtime flow notes. Keep the docs precise about precedence: explicit CLI backend wins, invalid env/default backend is ignored, local fallback/autostart happens only when no explicit backend target was supplied. This depends on the final implemented behavior and should happen after tests/terminal verification.
8. Run terminal-first verification against the real entrypoint, not only mocks. Required checks: command succeeds with no server running and no env URL; second command reuses cached local server state; explicit bad `--server-url` still fails; invalid env URL is ignored and the command still succeeds locally; `tool-seq` still works within one invocation. This depends on all implementation work.

**Relevant files**
- `c:/GitHub/agentdecompile/src/agentdecompile_cli/cli.py` — main Click entrypoint, `_client()`, `_execute_tool_call()`, CLI state helpers, option precedence, and most of the behavior change.
- `c:/GitHub/agentdecompile/src/agentdecompile_cli/executor.py` — `resolve_backend_url()` and current server-start guidance; likely needs new metadata or helper APIs to classify backend origin instead of only returning a URL.
- `c:/GitHub/agentdecompile/src/agentdecompile_cli/bridge.py` — current `ServerNotRunningError` construction; may need a lighter-weight probe path or clearer differentiation between recoverable connection failures and explicit-target hard failures.
- `c:/GitHub/agentdecompile/src/agentdecompile_cli/local_backend.py` — existing in-process fallback path to reuse as the last-resort execution mode.
- `c:/GitHub/agentdecompile/src/agentdecompile_cli/server.py` — local server startup entrypoint and argument contract to reuse for background auto-start.
- `c:/GitHub/agentdecompile/README.md` — CLI behavior examples and expectations.
- `c:/GitHub/agentdecompile/USAGE.md` — user-facing command guidance for server-less CLI behavior.
- `c:/GitHub/agentdecompile/CONTRIBUTING.md` — runtime flow notes that currently describe the CLI as HTTP-first.
- `c:/GitHub/agentdecompile/tests/` — new or updated CLI-focused tests for precedence, fallback, and auto-start behavior.

**Verification**
1. Run `uv run agentdecompile-cli tool execute-script '{"code":"__result__ = {\"value\": 7}","responseFormat":"json"}'` with no prestarted server and no MCP server URL env vars; confirm it succeeds and emits either auto-start or local fallback diagnostics instead of the old failure message.
2. Run the same command a second time and confirm the CLI reuses cached local server metadata from `.agentdecompile/cli_state.json` instead of repeating full cold-start behavior.
3. Run `uv run agentdecompile-cli --server-url http://127.0.0.1:65500 tool execute-script '{"code":"__result__ = {\"value\": 7}","responseFormat":"json"}'` and confirm it still fails fast rather than ignoring the explicit CLI target.
4. Set `AGENT_DECOMPILE_MCP_SERVER_URL=http://127.0.0.1:65500` and rerun the plain command without `--server-url`; confirm the invalid env target is ignored and the tool still succeeds locally.
5. Run a small `tool-seq` command to confirm the auto-started local server remains usable across multiple tool calls inside one CLI invocation.
6. Run focused automated tests, then at least the impacted subset of `uv run pytest` covering CLI behavior.

**Decisions**
- Included scope: `agentdecompile-cli` only; server auto-start/fallback behavior is for the Click CLI tool path, not for `mcp-agentdecompile` stdio bridge mode unless separately requested.
- Included scope: explicit CLI backend options remain authoritative and are never silently ignored.
- Included scope: invalid env-provided MCP server URLs are best-effort only and may be ignored in favor of local auto-start/fallback.
- Included scope: reuse the existing in-process `LocalToolBackend` as the final recovery path instead of inventing a second local execution engine.
- Excluded scope: optimizing multi-command cold-start cost beyond cached local server reuse; the first command may still take several seconds.
- Excluded scope: changing shared Ghidra server credential semantics or proxy mode behavior.

**Further Considerations**
1. Recommended implementation detail: introduce a small structured resolver result such as `BackendResolution(url, source, explicit)` rather than overloading `resolve_backend_url()` with more booleans. That keeps precedence tests readable and avoids subtle regressions in existing call sites.
2. Recommended operational detail: prefer background local HTTP server first and in-process local fallback second. That preserves current HTTP/session semantics for repeated CLI invocations and `tool-seq`, while still guaranteeing one-off commands work when server start fails.
3. Recommended Windows detail: persist only localhost endpoints that the CLI started itself, and treat missing pid or failed health probe as stale state to clear automatically. That avoids long-lived broken cache entries on Windows after terminal/process shutdown.
