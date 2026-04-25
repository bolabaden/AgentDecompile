# AgentDecompile 2.0.0

> Historical release note: this file documents the 2.0.0 release and is intentionally version-specific.

AgentDecompile 2.0.0 is a major release focused on transport reliability, shared-project workflows, expanded tooling, and stronger end-to-end validation.

## Release Scope

- Compare range: `v1.0.0...v2.0.0`
- Diff summary: 352 files changed, 64,686 insertions, 25,290 deletions
- Full compare: https://github.com/bolabaden/AgentDecompile/compare/v1.0.0...v2.0.0

## Highlights

- MCP transport and session lifecycle improvements:
  - Stateful session recovery and improved session persistence across CLI/proxy flows.
  - Compatibility updates for MCP HTTP path handling and request routing.
  - Better diagnostics and error handling around backend connectivity.
- Shared Ghidra server and repository workflows:
  - Expanded shared checkout/check-in handling and project open/write behavior.
  - Stronger sync/push/pull handling with transaction and domain-file lifecycle fixes.
  - Additional shared auth/header mapping and repository setup support.
- Tooling and provider evolution:
  - Added web UI support for tool execution and resource inspection.
  - Added and refined tool providers (including dissect/search/function-detail improvements).
  - Improved output and response normalization across providers and CLI rendering.
- Conflict resolution and propagation features:
  - Added explicit modification-conflict handling flows.
  - Added/expanded auto-check-in and auto match-function propagation behavior.
- CLI, docs, and development quality:
  - Broader command and alias consistency updates (including open/open-project harmonization).
  - Significant documentation refresh across usage, transport, and shared workflows.
  - Expanded unit/integration/e2e test coverage for transport and shared-project contracts.

## Notable Behavior Changes

- Tool and CLI naming/alias cleanup progressed toward a consistent `open` flow.
- Session handling behavior was revised for better continuity and fallback behavior in real MCP usage.
- Shared project operations now emphasize safe write paths and explicit transaction lifecycle control.
- Several legacy/obsolete tests and docs were removed or replaced as part of suite modernization.

## Upgrade Notes

- Revisit automation/scripts that call older command or tool aliases and migrate to current names.
- If you use shared repositories, validate session/header propagation end-to-end in your client/proxy path.
- For CI workflows, prefer the newer transport/session patterns and updated examples in docs.
