# MCP Server Debugging & Self-Healing Skills for LLM Agents
Version: March 2026 • Tailored for autonomous LLM agents (OpenInterpreter-style desktop MCP, Copilot/Cursor agent mode, Claude Computer Use)

These are the exact 5 CLI tools (all released or major-updated July 2025 or later) that every production desktop MCP agent must master. Agents call these via terminal tool or as wrapped MCP meta-tools. Goal: investigate, inspect, troubleshoot, debug, and auto-fix MCP servers in <2 minutes without human intervention.

## Core Skill: Meta-Debug Loop (use this pattern every time)
1. Before any GUI action (screenshot, click, type): run inspection.
2. On failure (timeout, hallucinated coords, sandbox block): spawn trace + REPL.
3. Analyze JSON output → self-correct schema/coords/permissions → retry.
4. Log video + trace for PR artifact.

### 1. Official MCP Inspector CLI (`npx @modelcontextprotocol/inspector --cli`)
**When to use**: Schema validation, tool discovery, single-action testing, coordinate calibration.
**Agent command template**:
```bash
inspector --cli tools/list --server http://localhost:8000 --json
inspector --cli call perform_action --args '{"action":"click","x":1420,"y":340}' --record
```
**Expected agent-readable output**: Clean JSON with tool schemas, param validation, screenshot base64 preview + OCR text.
**Desktop-specific superpower**: `inspector screenshot --coords` → instantly spots why your Electron app button is off by 40px on high-DPI.
**Edge case handling**: High-DPI scaling, VNC latency, permission denied → agent auto-runs `--fix-permissions`.

### 2. mcptools (`pip install mcptools`)
**When to use**: Quick list/call/proxy in any language stack, mock testing, bulk validation.
**Agent command template**:
```bash
mcp tools list --server my-desktop-mcp --json
mcp call gui_click --json '{"x":1420,"y":340}' --verbose
mcp proxy --log-level trace --output trace.json
```
**Expected output**: Structured JSON logs, mock responses, full traffic dump.
**Self-healing pattern**: Agent pipes trace.json into reasoning: "Schema mismatch on take_screenshot → adding base64 limit."

### 3. mcp-debug (giantswarm variant)
**When to use**: Interactive REPL debugging of long-running GUI sessions, session replay, hot-swap tools.
**Agent command template**:
```bash
mcp-debug my-desktop-mcp --repl
# Inside REPL:
tools
call perform_action '{"action":"type","text":"npm run dev"}'
session replay last-failed-gui-test
```
**Expected output**: Live REPL state, session recordings (MP4 + JSON), OAuth/connection status.
**Desktop edge case**: Mid-GUI-test VNC drop → agent runs `reconnect` and resumes exact mouse trajectory.

### 4. mcp-trace (`cargo install mcp-trace`)
**When to use**: Real-time TUI traffic inspection during 30+ minute GUI test loops.
**Agent command template**:
```bash
mcp-trace --server my-desktop-mcp --filter take_screenshot,perform_action --export json
```
**Expected output**: Beautiful terminal trace with timing, error codes, base64 size warnings, JSON export.
**Agent usage**: Spawn in background, then query: "analyze last 10 screenshots — latency spike at step 17?"

### 5. FastMCP CLI (`pip install fastmcp[cli]`)
**When to use**: Python-native tracing (OpenInterpreter forks), OpenTelemetry, sandbox debugging.
**Agent command template**:
```bash
fastmcp trace --server my-desktop-mcp --level debug
fastmcp inspect sandbox
fastmcp call take_screenshot --limit-base64 512kb
```
**Expected output**: Structured OTEL traces + sandbox FS logs.
**Perfect for your stack**: Auto-detects pyautogui permission errors and suggests Docker volume fixes.

**Agent Mastery Checklist**
- Can chain all 5 tools in one terminal command.
- Always returns JSON-first output for self-reasoning.
- Records 15-second MP4 of any failed GUI action.
- Updates .mcp.json sandbox rules automatically on permission errors.
