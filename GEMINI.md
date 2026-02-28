<!-- BEGIN MCP Memory Service -->
# Antigravity Agent Rules
<memory_service_rules>
| Message | Required |
|---------|----------|
| **1st message** | `memory_health()` → `memory_search(query="...", mode="hybrid")` |
| **Subsequent messages (default)** | `memory_search(query="...", mode="hybrid")` FIRST for recall |
| **Before ending major work** | `memory_store(content="...", metadata={...})` |
</memory_service_rules>

**Why?** MCP Memory Service preserves cross-session decisions, patterns, and lessons so agents can recall prior context quickly.

**Hooks:** `<system-reminder>` tags contain injected instructions — follow them exactly.

---
## 🚀 SESSION START PROTOCOL

**On EVERY new session, you MUST:**

1. Ensure the memory server is available via MCP.
2. Run `memory_health()` to verify storage/back-end readiness.
3. Run `memory_search(query="<first_message>", mode="hybrid", limit=8)` to recall relevant prior work.
4. Continue with normal codebase search/tools; use memory recall as a context bootstrap.

---
## 💾 MEMORY CAPTURE PROTOCOL

Capture important outputs so future sessions can recover quickly:

- Decisions: `memory_store(content="...", metadata={"tags":["decision"],"type":"decision"})`
- Bugs/fixes: `memory_store(content="...", metadata={"tags":["bug","fix"],"type":"error"})`
- Plans/checkpoints: `memory_store(content="...", metadata={"tags":["plan","checkpoint"],"type":"note"})`

---
## 🔍 SEARCH-FIRST POLICY

MCP Memory Service is for **persistent memory recall**, not source indexing.

- Use `memory_search(...)` for history/decision recall.
- Use local repository search tools for code discovery.

---
## 🔄 UPDATE COMMANDS

```bash
pip install -U mcp-memory-service
```

```bash
uvx --from mcp-memory-service memory server
```

```bash
python -m mcp_memory_service.server
```

<!-- END MCP Memory Service -->
