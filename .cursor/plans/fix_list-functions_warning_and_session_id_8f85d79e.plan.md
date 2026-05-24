---
name: Fix list-functions warning and session_id
overview: "Fix two server issues: (1) \"Tool 'list-functions' not listed, no validation will be performed\" by advertising tool names in canonical kebab-case so they match client-sent names; (2) \"cannot access local variable 'session_id' where it is not associated with a value\" by ensuring session_id is always assigned at the start of call_tool before any early return or use."
todos: []
isProject: false
---

# Fix list-functions validation warning and session_id UnboundLocalError

## 1. "Tool 'list-functions' not listed, no validation will be performed"

**Cause:** The MCP server advertises tools via `list_tools()` with **snake_case** names (e.g. `list_functions`) from [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) line 1796 (`name=to_snake_case(canonical_name)`). The client (e.g. Cursor) sends tool names in **kebab-case** (e.g. `list-functions`). Validation compares the incoming name to the advertised list, so `list-functions` is not found and the warning is logged (likely by the MCP SDK or the IDE).

**Fix:** Advertise tool names in **canonical kebab-case** so they match what clients send. In [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), in `ToolProviderManager.list_tools()`, change the `Tool` construction to use the canonical name instead of snake_case:

- **Current (line 1796):** `name=to_snake_case(canonical_name)` → advertises `list_functions`
- **Change to:** `name=canonical_name` → advertises `list-functions`

`ADVERTISED_TOOLS` and `canonical_name` are already kebab-case (e.g. `list-functions` from [registry.py](src/agentdecompile_cli/registry.py) `ToolName.LIST_FUNCTIONS.value`). This makes the tools/list response match typical client usage and removes the validation warning. No change to execution: `resolve_tool_name()` and normalization already accept both forms.

## 2. "cannot access local variable 'session_id' where it is not associated with a value"

**Cause:** Python raises `UnboundLocalError` when a variable is assigned in one branch and read in another branch where it was never assigned. In [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), `call_tool` uses `session_id` in many places (session history, program resolution, auto-match) but currently assigns it only at line 1841, **after** an early return for GUI-only tools (lines 1829–1839). If any code path or exception handling ever references `session_id` before that assignment (e.g. in a nested call or edge case), the error appears.

**Fix:** Assign `session_id` at the **very beginning** of `call_tool`, before any early returns or use, so it is always defined.

- In [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), in `call_tool`:
  - **Current order:** (1) `program_info` check, (2) `resolved_name` / `tool_enum`, (3) GUI-only early return, (4) `session_id = get_current_mcp_session_id()` at 1841.
  - **New order:** Right after the `program_info` check (and before `resolved_name`), add:
    - `session_id: str = get_current_mcp_session_id()`
  - Remove the later assignment at line 1841 so it is only assigned once at the top.

This guarantees `session_id` is set for every code path (including early returns and any future exception handling that might reference it).

## Summary of edits


| File                                                                     | Change                                                                                                                                                                              |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) | In `list_tools()`, use `name=canonical_name` instead of `name=to_snake_case(canonical_name)` when building `types.Tool`.                                                            |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) | In `call_tool()`, assign `session_id = get_current_mcp_session_id()` at the start (after `program_info` check), and remove the duplicate assignment that is currently at line 1841. |


## Verification

- Run the server and call `list-functions` (e.g. via CLI or Cursor); the "not listed, no validation" warning should stop.
- Call `list-functions` (and optionally other tools) and confirm the tool returns a normal result instead of the `session_id` error message.

