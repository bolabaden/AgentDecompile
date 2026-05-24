---
name: Fix shared project CLI persistence
overview: "Fix the CLI so that shared-project (connect-shared-project) state is correctly reused across separate invocations when calling tools like checkout-program. Root cause: the proxy does not forward the client's Mcp-Session-Id to the backend, so the backend never sees the same session that had open. Secondary: error message is misleading and CLI could optionally persist/retry shared-project context. Deepened with canonical session handling, security, framework docs, MCP debugging, and agent-native parity."
todos:
  - id: proxy-forward-session-id
    content: Add mcp-session-id to allowed_headers in _forwardable_shared_headers (proxy_server.py)
    status: completed
  - id: reword-checkout-error
    content: Reword path-not-resolved error and nextSteps in import_export.py (no 'new session' claim)
    status: completed
  - id: verify-proxy-flow
    content: "Verify proxy flow: open then checkout-program in second run with same --server-url"
    status: completed
  - id: verify-direct-server
    content: "Verify direct server: same two-run test, no regression"
    status: completed
  - id: verify-error-copy
    content: Verify error message no longer says 'Each CLI run uses a new session'
    status: completed
  - id: optional-agents-session-doc
    content: "(Optional) AGENTS.md: add Session and proxy behavior; update Session state caveat"
    status: completed
  - id: optional-session-handling-doc
    content: (Optional) Create docs/session-handling.md or document in one place
    status: completed
  - id: optional-logging-redact
    content: (Optional) Redact full session_id in tool_providers.py and project.py logs
    status: completed
  - id: optional-cli-retry
    content: "(Optional) CLI: persist connect-shared-project args and retry or hint on path-not-resolved"
    status: cancelled
isProject: false
---

## Enhancement Summary

**Deepened on:** 2026-03-12  
**Sections enhanced:** Root cause, Fixes, Verification, plus new sections (Canonical session handling, Security considerations, Agent-native / Action parity, MCP debugging, References).  
**Research agents used:** best-practices-researcher, framework-docs-researcher, generalPurpose (agent-native audit).

### Key Improvements

1. **Canonical session handling** — Align with MCP spec (MCP-Session-Id MUST be sent by client on subsequent requests; proxy must forward it to backend). Add single source of truth for session lifecycle (e.g. AGENTS.md or docs/session-handling.md).
2. **Security** — Forward only an allowlisted set of headers (include mcp-session-id); do not log full session id; treat session id as non-auth per MCP security guidance.
3. **Agent-native parity** — Fixing the proxy restores cross-invocation (CLI) and cross-turn (agent) parity; document session id semantics in one place so CLI and proxy stay aligned.
4. **Verification** — Use MCP debugging CLIs (Inspector, mcptools, mcp-trace) to confirm session id is forwarded and behavior matches spec.

### New Considerations Discovered

- MCP spec (2025-11-25) and GitHub modelcontextprotocol/inspector#492: proxy must forward MCP-Session-Id to backend for spec-compliant behavior.
- Existing logs in `tool_providers.py` and `project.py` log full `session_id`; security guidance: log only "present" or redacted (e.g. first 8 chars).
- AGENTS.md "Session state caveat" wording conflicts with design (persistence); should be updated when implementing.

---

# Fix shared-project CLI across invocations

## Problem

User runs:

1. `agentdecompile-cli --server-url http://HOST:8080/mcp --ghidra-server-host HOST ... open` → succeeds (shared repo, 26 programs).
2. `agentdecompile-cli --server-url http://HOST:8080 tool checkout-program '{"programPath": "/K1/k1_win_gog_swkotor.exe"}'` → fails with "Could not resolve program path in the current project" and the message "Each CLI run uses a new session...".

Design intent (from AGENTS.md): CLI persists MCP session id per server URL so that `open` then `checkout-program` in two separate invocations reuse the same server session when the same `--server-url` is used.

## Root cause

- **Session persistence on the CLI side is correct:** [cli.py](src/agentdecompile_cli/cli.py) loads `cli_state.json` by backend scope (`_cache_scope_key`), sends `Mcp-Session-Id` in `extra_headers` ([lines 175–184](src/agentdecompile_cli/cli.py)), and persists the session id after tool calls ([943–962](src/agentdecompile_cli/cli.py)). `normalize_backend_url` makes `http://HOST:8080` and `http://HOST:8080/mcp` the same scope, so the second run does send the persisted session id.
- **Proxy does not forward session id to backend:** When the user hits a **proxy** at 8080, the proxy reads `mcp-session-id` for its own routing ([proxy_server.py 323–326](src/agentdecompile_cli/mcp_server/proxy_server.py)) but does **not** include it in `_forwardable_shared_headers` ([299–313](src/agentdecompile_cli/mcp_server/proxy_server.py)). So `_set_streamable_http_headers(session_id, _forwardable_shared_headers(scope))` never stores the client's session id. The bridge then builds the backend client with `merged_headers = _get_streamable_http_headers(sid) + _proxy_project_path_headers()` ([bridge.py 838–842](src/agentdecompile_cli/bridge.py)); the backend's `RawMcpHttpBackend` therefore does not send the client's session id to the real server. The backend server sees a new or "default" session on every request and never has the session that ran `connect-shared-project`.
- **Direct-to-server case:** If the user talks to the raw server (no proxy), the server does receive `Mcp-Session-Id` and uses it ([server.py 701–704, 728](src/agentdecompile_cli/mcp_server/server.py)). So direct-to-server can work; the failure in the user's run is consistent with using the proxy at 8080.

## Canonical session handling

Sessions should be handled in a single, spec-aligned way across CLI, proxy, and server.

- **MCP spec (Streamable HTTP):** Server MAY assign a session ID at initialization via `MCP-Session-Id` on the response; if set, clients **MUST** include it on all subsequent requests. Header names are case-insensitive; use lowercase for comparison and when building response headers (ASGI).  
  - **Source:** [MCP Transports – Session Management](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management).
- **Proxy obligation:** A proxy that is the client toward the backend must forward the client's `MCP-Session-Id` (or `mcp-session-id`) to the backend so the same logical session is used end-to-end. Using it only for frontend routing and not forwarding is the current bug.  
  - **Source:** [modelcontextprotocol/inspector#492](https://github.com/modelcontextprotocol/inspector/issues/492) (proxy must retain and pass session id on Proxy ↔ Server leg).
- **Allowlist:** Forward only an explicit allowlist of headers (client → proxy → backend). Include `mcp-session-id` in that allowlist. Blind forwarding enables header injection/spoofing.
- **Single source of truth:** Document in **one** place (AGENTS.md subsection or `docs/session-handling.md`): who assigns the session id, who persists it (CLI per normalized backend URL), what the proxy must forward, and how backend scope is defined (`normalize_backend_url`), so CLI and proxy stay aligned.

### Research Insights

- **HTTP session persistence (APIs):**
  - Prefer **custom header** (e.g. `Authorization`, `X-Session-Id`, or protocol-specific like `Mcp-Session-Id`) for machine-to-machine and programmatic clients: avoids cookie scope/CSRF concerns, scales without cookie jar, and aligns with stateless or stateful backends that key by header.
  - Use **cookies** when the client is a browser and you need SameSite/HttpOnly/Secure and automatic send; for APIs consumed only by CLIs or servers, headers are standard.
  - **Secure:** Set `Secure` on any cookie carrying a session id so it is only sent over HTTPS (OWASP: mandatory to prevent MitM disclosure).
  - **HttpOnly:** Set `HttpOnly` on session cookies to prevent JavaScript access and reduce XSS-based session theft (OWASP: mandatory for session cookies).
  - **SameSite:** Use `Strict` or `Lax` for same-site cookies to reduce CSRF; use `None` only when cross-site send is required (and then only with `Secure`).
  - **Server-assigned vs client-provided:** Prefer **server-assigned** session ids (generated with CSPRNG, at least 64 bits entropy); never accept client-provided session ids as authoritative without strict validation to avoid fixation.
  - **Stateless vs stateful:** Stateless (e.g. JWT in header) avoids server-side session store; stateful (server stores session keyed by id) is standard when server must hold per-session state (e.g. MCP server session). Choose by whether the backend needs to hold session state.
- **MCP (Streamable HTTP) session semantics:**
  - **Spec (2025-06-18 / 2025-11-25):** Server MAY assign a session id at initialization by including it in the `Mcp-Session-Id` header on the HTTP response that contains `InitializeResult`. If present, clients **MUST** include that header on all subsequent HTTP requests (POST and GET). Session id MUST contain only visible ASCII (0x21–0x7E); SHOULD be globally unique and cryptographically secure (e.g. UUID, JWT, or cryptographic hash).
  - **Client expectations:** After init, client sends `Mcp-Session-Id` on every request; missing header (after init) → server SHOULD respond 400; unknown/expired id → 404; client SHOULD start new session (new `InitializeRequest` without session id) on 404. Client MAY send HTTP DELETE to the MCP endpoint with `Mcp-Session-Id` to terminate the session.
  - **Proxy forwarding:** A proxy that is the client toward the backend MUST forward the client’s `Mcp-Session-Id` (or `mcp-session-id`) to the backend so the same logical session is used end-to-end; using it only for frontend routing and not forwarding breaks cross-invocation and cross-turn reuse (see modelcontextprotocol/inspector#492).
- **Python / FastAPI / Starlette:**
  - **Setting cookies:** Use `Response.set_cookie(key, value, ...)` on the response object (e.g. `JSONResponse` or inject `Response` in the path operation). Starlette signature: `set_cookie(key, value, max_age=None, expires=None, path="/", domain=None, secure=False, httponly=False, samesite="lax", partitioned=False)`. For session cookies, set `secure=True`, `httponly=True`, and `samesite="lax"` (or `"strict"`) in production over HTTPS.
  - **Reading Cookie header:** Use `request.cookies.get('name')`; cookies are case-insensitive; invalid cookies are ignored per RFC 2109. For session id in a **header** (e.g. MCP), use `request.headers.get("mcp-session-id")` (ASGI lowercases header names).
  - **Validating/sanitizing session id:** Treat session id as untrusted input. Apply: **allowlist** character set (e.g. visible ASCII 0x21–0x7E per MCP; or alphanumeric + hyphen only); **max length** (e.g. 128–256 chars to avoid DoS and injection); **reject** if format invalid. Never use session id in SQL, HTML, or logs without validation/encoding; do not log full value (log “present” or redacted prefix). OWASP: session ids must be validated and verified like any other user input to prevent injection and fixation.
- **CLI tools and stateful HTTP backends:**
  - **Cookie jar vs JSON state file:** Cookie jars (e.g. HTTPie) persist cookies per host and send them automatically; suitable when the backend sets session via `Set-Cookie`. When the backend uses a **custom header** (e.g. `Mcp-Session-Id`) and returns the id in response headers, the CLI must persist that value itself (e.g. in a **JSON state file** keyed by backend scope) and send it as a header on subsequent requests—cookie jar does not apply.
  - **When to omit session id (“default” behavior):** Omit session id only on the **first** request (e.g. `InitializeRequest`) so the server can assign one. For “single default session” backends that do not require a session id, document that explicitly; otherwise, after init, always send the session id. If the CLI does not persist a session id (e.g. `sessionMode: none`), each invocation is effectively a new session; for reuse across invocations, persist and send the id (e.g. `sessionMode: existing`).

### References (session / transport)


| Topic                            | Doc URL                                                                                                                                                                                                              | Note                                                                         |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| MCP Streamable HTTP + session    | [https://modelcontextprotocol.io/specification/2025-11-25/basic/transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)                                                               | Clients MUST include MCP-Session-Id on all subsequent requests.              |
| MCP proxy session id             | [https://github.com/modelcontextprotocol/inspector/issues/492](https://github.com/modelcontextprotocol/inspector/issues/492)                                                                                         | Proxy must pass session id on subsequent requests (Proxy ↔ Server).          |
| MCP Security – Session hijacking | [https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking) | Don't use session IDs for auth; use secure random IDs.                       |
| ASGI request/response headers    | [https://asgi.readthedocs.io/en/stable/specs/www.html](https://asgi.readthedocs.io/en/stable/specs/www.html)                                                                                                         | Header names lowercased for comparison; response headers must be lowercased. |
| OWASP Session Management         | [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)                                             | Secure/HttpOnly/SameSite, validation, entropy, no caching.                   |
| FastAPI response cookies         | [https://fastapi.tiangolo.com/advanced/response-cookies/](https://fastapi.tiangolo.com/advanced/response-cookies/)                                                                                                   | Setting cookies via Response parameter or direct Response.                   |
| Starlette Requests / Responses   | [https://starlette.dev/requests/](https://starlette.dev/requests/), [https://starlette.dev/responses/](https://starlette.dev/responses/)                                                                             | `request.cookies.get()`, `Response.set_cookie()` signature and options.      |


## Security considerations

- **Allowlist only:** Add `mcp-session-id` to the existing allowlist in `_forwardable_shared_headers`; do not broaden to “forward all headers” (reverse proxy header attacks: [Praetorian](https://www.praetorian.com/blog/reverse-proxy-header-attacks/)).
- **Do not log full session id:** Per FastAPI/security guidance, do not log `Authorization`, `MCP-Session-Id`, or `Cookie`. Existing logs that include full `session_id`:
  - [tool_providers.py 1895](src/agentdecompile_cli/mcp_server/tool_providers.py): `logger.info("mcp call_tool tool=%s session_id=%s", ...)`.
  - [project.py 713](src/agentdecompile_cli/mcp_server/providers/project.py): `logger.info("[connect-shared-project] session=%s, ...", session_id, ...)`.  
  Prefer logging “present” or a redacted hint (e.g. `session_id[:8] + "…"` or `session_id[:12]`) if needed for debugging; consider a follow-up change.
- **Session id ≠ auth:** Per MCP security best practices, session IDs must not be used for authentication; use secure random IDs and optional binding to user-specific data.

## Fixes

### 1. Proxy: forward `mcp-session-id` to the backend (primary fix)

**File:** [src/agentdecompile_cli/mcp_server/proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py)

- In `_forwardable_shared_headers`, add `"mcp-session-id"` to `allowed_headers` (canonical lowercase so backend receives it; HTTP header names are case-insensitive).
- Effect: When the CLI (or any client) sends `Mcp-Session-Id: <persisted_id>`, the proxy will store it in streamable headers for that frontend session and pass it in `merged_headers` to `RawMcpHttpBackend`. The backend will then send that session id to the real server, which will reuse the session that already ran `connect-shared-project`, so `checkout-program` and other tools can resolve shared paths.

### 2. Error message: stop saying "Each CLI run uses a new session"

**File:** [src/agentdecompile_cli/mcp_server/providers/import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py)

- At [1119–1122](src/agentdecompile_cli/mcp_server/providers/import_export.py), replace the current `error` and `nextSteps` text so that:
  - The message no longer claims "Each CLI run uses a new session" (session is persisted by the CLI).
  - It states that **this server session** has no shared project open (e.g. call `open` first with shared-server options, or use the same `--server-url` and ensure the server process wasn't restarted).
- Keep `nextSteps` actionable: same-session options (pass ghidra-server-* with the tool, or use `tool-seq` with open then checkout-program).

### 3. (Optional) CLI: persist last connect-shared-project args and retry or hint

**Scope:** Lower priority; can be a follow-up.

- **Option A – Persist and retry:** In `cli_state.json` (per backend scope), persist last successful `connect-shared-project` arguments (e.g. `server_host`, `server_port`, `path`/repository, and optionally redacted auth hints). When a tool returns a structured "path-not-resolved" for a path that looks shared (e.g. starts with `/`), the CLI could call `open` with those args then retry the tool once (if the backend is the same and we have the args).
- **Option B – Hint only:** Persist the same args for display only; when showing the error, suggest "If using a proxy, ensure the proxy forwards the session id; otherwise call open in the same session (e.g. tool-seq) or pass --ghidra-server-host and --server-repository with this command."

Recommendation: Implement **1** and **2** first so shared project works with the proxy and the message is correct. Add **3** only if you want automatic retry or richer hints.

### 4. (Optional) Document session handling in one place

- **AGENTS.md:** Add a short “Session and proxy behavior” subsection: session id is assigned by the server and returned in responses; CLI persists it per normalized backend URL and sends it on subsequent invocations; proxies must forward `mcp-session-id` to the backend; update “Session state caveat” so it no longer says “Each CLI invocation creates a new MCP session” and instead reflects persistence and the requirement that server/proxy forward the id.
- **Or** a dedicated `docs/session-handling.md` as single source of truth; AGENTS.md and this plan can point to it.

## Agent-Native / Action parity

**Score: 3/5** — Same-turn and tool-seq flows work for both user and agent; cross-invocation (CLI) and cross-turn (agent) flows via proxy fail for both until the proxy forwards the session id.

**Gaps:**

- Proxy does not forward `mcp-session-id` to the backend, so any client (CLI or agent) that reconnects with a persisted/returned session id does not get the same server session when going through the proxy.
- Session id semantics are split: CLI persists the id from the response (backend id); proxy keys frontend state by that same value but does not send it to the backend, causing a new or mismatched backend session.
- AGENTS.md still says “Each CLI invocation creates a new MCP session,” which conflicts with the design of “CLI persists MCP session id per server URL.”

**Recommendations:**

1. Apply the planned proxy fix so the backend sends the client’s session id to the real server; this restores cross-invocation (CLI) and cross-turn (agent) parity when using the proxy.
2. Clarify session id in one place (AGENTS.md or docs/session-handling.md): who assigns it, who persists it, what the proxy must forward.
3. Update AGENTS.md “Session state caveat” to reflect persistence and the need for server/proxy to forward the id.
4. Deploy the error-message change in import_export.py (no “new session” claim; explain this server session has no shared project).
5. Optional: Document that when using the proxy, the session id returned to the client should be the one the proxy sends to the backend so reconnection maps to one backend session.

## Verification

- **Proxy flow:** Run open against proxy (with ghidra-server-*), then in a second run checkout-program with same --server-url (no ghidra-server-*). Expect checkout to succeed for a path like `/K1/k1_win_gog_swkotor.exe`.
- **Direct server:** Same two-run test against the streamable HTTP server directly; should still work (no regression).
- **Error copy:** Trigger path-not-resolved (e.g. wrong path or fresh server). Confirm the message no longer says "Each CLI run uses a new session" and correctly describes missing shared project in this server session.

### MCP debugging (verification)

Use the **mcp-debugging** skill and CLIs to confirm session behavior after implementing the fix:

- **Meta-debug loop:** Inspect → on failure run trace + analyze → self-correct → retry.
- **Inspector / mcptools:** Call `open` then `checkout-program` in two requests with the same session id; verify the second request succeeds and that the proxy forwards `mcp-session-id` to the backend (e.g. via mcp-trace or proxy logs).
- **Reference:** [.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md](.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md).

## Security ownership (optional)

Session and auth-adjacent code (proxy header forwarding, session context, cli_state.json) are sensitive touchpoints. If the repo uses a security ownership map (e.g. `scripts/run_ownership_map.py` from the security-ownership-map skill), consider including:

- `src/agentdecompile_cli/mcp_server/proxy_server.py` (forwardable headers, session id),
- `src/agentdecompile_cli/mcp_server/session_context.py`,
- `src/agentdecompile_cli/cli.py` (cli_state, session persistence),

so that future changes to session/auth behavior get appropriate review.

## Summary


| Item                                                                             | Action                                                                                                                                  |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| [proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py)             | Add `mcp-session-id` to `allowed_headers` in `_forwardable_shared_headers`.                                                             |
| [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py) | Reword checkout-program path-not-resolved error and nextSteps (no "new session" claim; explain missing shared project in this session). |
| AGENTS.md                                                                        | Optional: add “Session and proxy behavior”; update “Session state caveat” to reflect persistence.                                       |
| CLI state / retry (optional)                                                     | Defer or do in a follow-up.                                                                                                             |
| Logging (optional)                                                               | Consider redacting full session_id in tool_providers.py and project.py logs (security best practice).                                   |


