# Session handling (MCP Streamable HTTP)

Single source of truth for how MCP session ids are assigned, persisted, and forwarded so CLI and proxy stay aligned. User-facing summary: [AGENTS.md](../AGENTS.md) § Session and proxy behavior.

## Rules

- **Who assigns:** The server (or proxy, when it is the client toward the backend) assigns a session id at initialization and returns it in the `mcp-session-id` (or `MCP-Session-Id`) response header. Per [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), clients must send it on all subsequent requests.
- **Who persists:** The CLI persists the session id per **normalized backend URL** in `.agentdecompile/cli_state.json` and sends it on later invocations when the same `--server-url` is used. Backend scope is defined by `normalize_backend_url` (e.g. `http://host:8080` and `http://host:8080/mcp` map to the same scope).
- **What the proxy must forward:** Proxies must include `mcp-session-id` in the allowlist of headers forwarded from client to backend so the same logical session is used end-to-end. See [modelcontextprotocol/inspector#492](https://github.com/modelcontextprotocol/inspector/issues/492).
- **Session id ≠ auth:** Session IDs must not be used for authentication; use secure random IDs (MCP security best practices).

## References

- [MCP Transports – Session Management](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management)
- [MCP Security – Session hijacking](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking)
- [ASGI HTTP – headers](https://asgi.readthedocs.io/en/stable/specs/www.html) (header names lowercased for comparison)
