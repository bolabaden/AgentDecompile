<!-- BEGIN MCP Memory Service -->
# Kilo Code Rules
<memory_service_rules>
| Message | Required |
|---------|----------|
| **1st message** | `memory_health()` → `memory_search(query="...", mode="hybrid")` |
| **Subsequent messages (default)** | `memory_search(query="...", mode="hybrid")` FIRST for recall |
| **Before ending major work** | `memory_store(content="...", metadata={...})` |
</memory_service_rules>

**Why?** `memory_search()` retrieves prior decisions and context across sessions.

**Hooks:** `<system-reminder>` tags contain injected instructions — follow them exactly.

v1.0.0
<!-- END MCP Memory Service -->
