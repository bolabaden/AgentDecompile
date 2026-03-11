# AgentDecompile – Copilot/Claude Instructions

## Terminal-First Verification Policy

- Any code change that affects runtime behavior, transports, CLI behavior, MCP tool routing, project opening, shared-server access, sync, import/export, or server startup must be verified in the terminal before being treated as complete.
- Prefer running the real local entry points from this repo such as `uv run agentdecompile-server ...` and `uv run agentdecompile-cli ...` instead of only reasoning from source or updating tests.
- When a change touches MCP behavior, verify the actual transport path that the user will exercise: stdio, streamable-http, proxy mode, or CLI, as applicable.
- Validate behavior with real tool calls whenever terminal access is available. Do not stop at `tools/list` or startup health alone when the affected feature is deeper than that.
- After terminal verification, update or add focused tests that reflect the observed real behavior. Tests are secondary to terminal validation, not a substitute for it.
- If terminal validation is blocked by a missing local prerequisite, unavailable credential flow, or unavailable tool capability, say exactly what blocked it and what was still validated.

## Planning and Documentation Diagram Policy

- Every new or updated planning/design document must include at least one Mermaid diagram.
- The diagram should appear near the top (after objective/scope) and provide a high-level flow.
- Keep diagrams synchronized with the written steps when plans evolve.
- Prefer simple `flowchart TD` diagrams for execution plans and phase sequencing.
- If a document has multiple phases/modules, include one top-level diagram plus optional focused diagrams.
