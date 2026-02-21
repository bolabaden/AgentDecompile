# Contributing to AgentDecompile

Thank you for your interest in improving AgentDecompile! We want to make this the best AI companion for reverse engineers.

## Table of Contents

**Part 1 — Start here**

- [How to Contribute](#how-to-contribute)
- [Guidelines](#guidelines)
- [Usage and connection](#usage-and-connection)
- [Feedback](#feedback)

**Part 2 — Development setup**

- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Project Structure](#project-structure)
  - [Architecture (overview)](#architecture-overview)
  - [Adding a new tool](#adding-a-new-tool)

**Part 3 — Architecture and design**

- [Architecture](#architecture)
  - [System Overview](#system-overview)
  - [Component Breakdown](#component-breakdown)
  - [Data Flow](#data-flow)
  - [Deployment Models](#deployment-models)
  - [Remote and Local Connection](#remote-and-local-connection)
  - [Execution Environments](#execution-environments)
  - [Key Design Decisions](#key-design-decisions)
  - [Future Extensibility](#future-extensibility)

**Part 4 — Internals**

- [Internals](#internals)
  - [Network Flow in Detail](#network-flow-in-detail)
  - [Threading and Concurrency](#threading-and-concurrency)
  - [Configuration Management](#configuration-management)
  - [Program Lifecycle](#program-lifecycle)
  - [Tool Provider Pattern](#tool-provider-pattern)
  - [Error Handling](#error-handling)
  - [Performance Considerations](#performance-considerations)
  - [Recommended Reading](#recommended-reading)

**Part 5 — MCP protocol**

- [MCP Protocol](#mcp-protocol)
  - [MCP Overview](#mcp-overview)
  - [AgentDecompile's MCP Implementation](#agentdecompiles-mcp-implementation)
  - [Tool Definitions](#tool-definitions)
  - [Resource Definitions](#resource-definitions)
  - [Request/Response Examples](#requestresponse-examples)
  - [Error Handling](#error-handling-1)
  - [Protocol Compatibility](#protocol-compatibility)
  - [Adding a New Tool](#adding-a-new-tool-1)
  - [Debugging MCP Traffic](#debugging-mcp-traffic)
  - [Further Reading](#further-reading)

**Part 6 — Implementation guides**

- [Batch Add Field Example](#batch-add-field-example)
  - [Problem](#problem)
  - [Solution](#solution)
  - [Benefits](#benefits)
  - [Response Format](#response-format)
  - [Options](#options)
  - [Field Object Properties](#field-object-properties)
  - [Backwards Compatibility](#backwards-compatibility)
  - [Error Handling](#error-handling)
- [Structure Size Preservation](#structure-size-preservation-in-manage-structures-tool)
  - [Problem](#problem-structure-size)
  - [Root Cause](#root-cause)
  - [Technical Details](#technical-details-structure-size)
  - [Implementation Notes](#implementation-notes-structure-size)
- [Disabled Tools Refactoring](#disabled-tools-refactoring)
  - [Overview](#overview)
  - [Refactoring Strategy](#refactoring-strategy)
  - [Completed Refactorings](#completed-refactorings)
  - [Verification Checklist](#verification-checklist)
  - [Upstream Sync Process](#upstream-sync-process)
  - [Files Modified](#files-modified)
  - [Benefits](#benefits-1)
  - [Notes](#notes)
- [Ghidra Scripts Analysis and Coverage](#ghidra-scripts-analysis-and-coverage)
  - [Script Categories](#script-categories)
  - [Priority Gaps to Address](#priority-gaps-to-address)
  - [Implementation Strategy](#implementation-strategy)
- [Ghidra Shared Project API](#ghidra-shared-project-api)
  - [Overview](#overview-1)
  - [Environment variable configuration](#environment-variable-configuration-agentdecompile)
  - [Connect to the Ghidra Repository Server](#1-connect-to-the-ghidra-repository-server)
  - [Setting Credentials (Headless)](#2-setting-credentials-login-for-headless--api-use)
  - [Get a Repository](#3-get-a-repository-shared-project-container)
  - [Ghidra URL for Shared Content](#4-ghidra-url-for-shared-content-server-project-path)
  - [Opening a Project (Local vs Shared)](#5-opening-a-project-local-vs-shared)
  - [ProjectLocator and Transient Projects](#6-projectlocator-and-transient-remote-projects)
  - [Error Handling](#error-handling-2)
  - [Summary Checklist](#8-summary-checklist-for-login-and-use-shared-project-via-api)
  - [References](#9-references-same-as-in-codebase)
- [Shared Project Authentication](#shared-project-authentication)
- [Ghidra Project Authentication](#ghidra-project-authentication-implementation)
  - [Understanding the Problem](#understanding-the-problem)
  - [How Ghidra Authentication Works](#how-ghidra-authentication-works)
  - [Where It Is Implemented](#where-it-is-implemented)
  - [Security Considerations](#security-considerations)
  - [When Authentication Is Needed](#when-authentication-is-needed)
  - [Testing](#testing)
  - [API Reference](#api-reference-project-auth)
- [Ghidra Project Locking](#ghidra-project-locking-explained)
  - [Overview](#overview-3)
  - [How Locking Works](#how-locking-works)
  - [AgentDecompile's Behavior](#agentdecompiles-behavior)
  - [Technical Details](#technical-details-lock)
  - [Summary](#summary-lock)

**Part 7 — Features and reference**

- [Intelligent Features](#intelligent-features-in-agentdecompile)
  - [Overview](#overview-2)
  - [Technical Details](#technical-details)
- [API Documentation Reference](#api-documentation-reference)
  - [Quick Reference – Main Documentation URLs](#quick-reference--main-documentation-urls)
  - [Ghidra API – Package & Class URLs](#ghidra-api--package--class-urls)
  - [MCP (Model Context Protocol) Java SDK](#mcp-model-context-protocol-java-sdk)
  - [How to Add API Documentation Links in Code](#how-to-add-api-documentation-links-in-code)
  - [Package Summary Pages (Ghidra)](#package-summary-pages-ghidra)

---

## How to Contribute

1.  **Fork** the repository.
2.  **Create a branch** for your feature or fix.
3.  **Code** your changes.
4.  **Test** using `gradle test` and `gradle integrationTest`.
5.  **Submit a Pull Request**.

## Guidelines

-   **Code Style**: We follow standard Java conventions.
-   **Documentation**: Please update docs if you change functionality.
-   **License**: By contributing, you agree that your contributions will be licensed under the project's GNU Affero General Public License v3.0 (AGPL-3.0).

## Usage and connection

For connection options, remote access, environment variables, and end-user usage, see [README.md](README.md) and [CLAUDE.md](CLAUDE.md).

## Feedback

If you find a bug or have an idea, please [open an issue](https://github.com/bolabaden/AgentDecompile/issues).

*Part 2 — Development setup: prerequisites, project structure, and adding a new tool.*

---

## Development Setup

This section covers setting up your development environment.

### Prerequisites

-   **Java 21**: We use Java 21 for modern features.
-   **Gradle 8.10+**: Use the system gradle (not wrapper).
-   **Ghidra 12.0+**: Required for the extension.
-   **Python 3.11+**: For the CLI bridge and tests.
-   **uv**: Python package manager.
-   **Git**: Version control.

### Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/bolabaden/AgentDecompile.git
    cd AgentDecompile
    ```

2.  **Environment Variables**:
    Create a `.env` file (optional, or set in shell):
    ```bash
    export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
    ```

3.  **Build**:
    ```bash
    gradle build
    ```

4.  **Install to Ghidra** (Local Dev):
    ```bash
    gradle install
    ```

### Project Structure

-   `src/main/java/agentdecompile`: Core Java extension (server, headless, tools, resources, plugin, util, ui).
-   `src/agentdecompile_cli`: Python CLI package; stdio bridge for `mcp-agentdecompile`, launcher, project_manager.
-   `tests`: Python tests (unit, integration, e2e markers).
-   `src/test`: Java unit tests (no Ghidra env).
-   `src/test.slow`: Java integration tests (GUI/headed required).

### Architecture (overview)

AgentDecompile runs as a Ghidra extension that starts a local HTTP server implementing the Model Context Protocol (MCP).

-   **AgentDecompile plugin**: Manages server lifecycle in GUI mode.
-   **McpServerManager**: Handles MCP requests (list_tools, call_tool, etc.) and Jetty HTTP.
-   **ToolProvider**: Implementations extend `AbstractToolProvider` and register tools with the server.

See the **Architecture**, **Internals**, and **MCP Protocol** sections below for full detail.

### Adding a new tool

1.  Extend `AbstractToolProvider` in `agentdecompile.tools` (e.g. under a subpackage like `decompiler`, `functions`).
2.  Implement `registerTools()`: define tools with `McpSchema.Tool.builder()` and register handlers.
3.  Add the provider in `McpServerManager.initializeToolProviders()`.

See [AGENTS.md](AGENTS.md) and [src/main/java/agentdecompile/tools/CLAUDE.md](src/main/java/agentdecompile/tools/CLAUDE.md) for patterns; the **MCP Protocol** section below has the full checklist.

*Part 3 — Architecture and design: the following sections describe system architecture, components, and design decisions.*

---

## Architecture

This document describes the high-level architecture of the AgentDecompile project, including how components interact and where different types of code live.

### System Overview

AgentDecompile is a **Model Context Protocol (MCP) server** that bridges AI language models to Ghidra's reverse engineering capabilities. It operates in two distinct modes:

#### GUI Mode (Ghidra Plugin)
- Runs as a plugin within a Ghidra GUI instance
- One shared MCP server persists across multiple tools and projects
- Allows direct integration with Ghidra's UI
- Supports file dialogs, progress indicators, and interactive workflows

#### Headless Mode (CLI + Python)
- Runs as a standalone Ghidra headless application
- Spawned by Python CLI (`agentdecompile_cli`) via PyGhidra
- Each invocation creates a new Java process and MCP server
- Suitable for scripting, automation, and non-interactive analysis

### Component Breakdown

#### Source Directory Structure (`src/`)

```
src/
├── agentdecompile_cli/          # Python CLI (stdio bridge)
│   ├── __init__.py, __main__.py  # Entry point: mcp-agentdecompile
│   ├── launcher.py              # Wraps Java AgentDecompileHeadlessLauncher
│   ├── stdio_bridge.py           # MCP stdio ↔ HTTP bridge
│   ├── project_manager.py       # Ghidra project lifecycle
│   ├── mcp_session_patch.py     # Patches MCP SDK RuntimeError bug
│   └── _version.py              # Version (setuptools_scm)
├── main/java/agentdecompile/    # Java extension
│   ├── server/                  # MCP server (McpServerManager, filters)
│   ├── headless/                # Headless launcher, JavaOutputRedirect
│   ├── tools/                   # MCP tool providers (17 tools)
│   ├── resources/               # MCP resource providers
│   ├── plugin/                  # Ghidra plugin integration
│   ├── util/                    # AddressUtil, ProgramLookupUtil, etc.
│   └── ui/                      # GUI components
├── test/                        # Java unit tests (no Ghidra env)
└── test.slow/                   # Java integration tests (GUI required)
```

```
┌─────────────────────────────────────────────────────────────┐
│                   Client Layer (AI Model)                   │
│                    (Claude, etc. via MCP)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP (JSON-RPC over HTTP/Stdio)
┌──────────────────────┴──────────────────────────────────────┐
│                   Stdio Bridge (Python)                      │
│              src/agentdecompile_cli/stdio_bridge.py                   │
│  - Converts stdio JSON-RPC to HTTP requests                 │
│  - Wraps errors and logs as JSON-RPC notifications          │
│  - Handles reconnection and session management              │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP (Streamable HTTP)
                       │ POST /mcp/message
┌──────────────────────┴──────────────────────────────────────┐
│               MCP Server (Java/Jetty)                        │
│          src/main/java/agentdecompile/server/McpServerManager          │
│  - Jetty HTTP server with explicit thread pool config       │
│  - Long keep-alive timeouts (24 hours)                      │
│  - Supports multiple concurrent HTTP clients                │
│  - Routes requests to resource/tool providers               │
└──────────────────────┬──────────────────────────────────────┘
                       │ Ghidra API (Direct Java calls)
┌──────────────────────┴──────────────────────────────────────┐
│              Ghidra Framework (Java)                         │
│  - Program analysis, decompilation, memory access           │
│  - Project/file management                                  │
│  - Symbol/reference resolution                              │
└──────────────────────────────────────────────────────────────┘
```

#### 1. Python CLI Layer (`src/agentdecompile_cli/`)

**Purpose:** Initialize Ghidra, start MCP server, and bridge stdio to HTTP

##### Files:
- **`__main__.py`** - Entry point; initializes PyGhidra, starts Java server, manages filters
- **`launcher.py`** - Wraps Java AgentDecompileHeadlessLauncher; handles project initialization
- **`stdio_bridge.py`** - MCP client that connects to Java server via HTTP; exposes stdio interface
- **`project_manager.py`** - Manages Ghidra project lifecycle (open/close/import)

##### Flow:
1. **Pre-asyncio (blocking):** Install stdout/stderr filters (JSON-RPC only on stdout), initialize PyGhidra, redirect Java System.out/System.err via `JavaOutputRedirect`, create `ProjectManager` (ephemeral temp project for stdio mode unless `AGENT_DECOMPILE_PROJECT_PATH` is set), create `AgentDecompileLauncher`, call `launcher.start()` → starts Java MCP server.
2. **Async stdio bridge:** Create `AgentDecompileStdioBridge(port)`, run `bridge.run()` → connects to `http://localhost:{port}/mcp/message`, proxies all MCP requests (list_tools, call_tool, list_resources, read_resource, list_prompts) stdio ↔ HTTP.

**Bridge stability (stdio_bridge.py):** Concurrency limiting (`asyncio.Semaphore(MAX_CONCURRENT_REQUESTS=3)`), retry with exponential backoff (max 3 retries), circuit breaker (5 consecutive failures → 10s backoff), long timeouts (1 hour for tool calls and connections). `JsonEnvelopeStream` wraps the HTTP stream to convert non-JSON log messages to JSON-RPC notifications.

#### 2. Java MCP Server (`src/main/java/agentdecompile/server/`)

**Purpose:** HTTP server that handles MCP requests and coordinates Ghidra operations

##### Files:
- **`McpServerManager.java`** - Main server orchestrator; manages Jetty, thread pools, tool registration
- **`KeepAliveFilter.java`** - HTTP filter that sets `Connection: keep-alive` headers
- **`RequestLoggingFilter.java`** - Optional debug logging of HTTP requests/responses
- **`ApiKeyAuthFilter.java`** - API key authentication (if enabled)
- **`CachingRequestWrapper.java`** / **`CachingResponseWrapper.java`** - Wrap requests/responses for logging

##### Key Details:
- **Transport:** `HttpServletStreamableServerTransportProvider` (MCP SDK v0.17.0), streamable HTTP (not SSE).
- **Endpoint:** `POST /mcp/message`
- **Filter order:** `GlobalExceptionFilter` → `ApiKeyAuthFilter` (optional) → `RequestLoggingFilter` → `KeepAliveFilter` → MCP handler.
- **Thread Pool:** `QueuedThreadPool` with 24-hour idle timeout (prevents thread exhaustion)
- **Connection Timeouts:** Jetty connector + HTTP config both set to 24 hours
- **Keep-Alive:** MCP SDK `keepAliveInterval(Duration.ofSeconds(30))`; HTTP headers allow long keep-alive

#### 3. Java Headless Launcher (`src/main/java/agentdecompile/headless/`)

**Purpose:** Initialize Ghidra in headless mode and set up server

##### Files:
- **`AgentDecompileHeadlessLauncher.java`** - Initializes Ghidra application, creates/opens project, starts MCP server

##### Key Details:
- Accepts project location and name as parameters (from Python)
- Creates `McpServerManager` with `ConfigManager` (in-memory or file-based)
- Uses random port if requested (avoids conflicts between multiple instances)
- Handles project lock files (can force-ignore if `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` set)
- Starts server in a background thread; waits for startup signal

#### 4. Java Plugin (GUI Mode) (`src/main/java/agentdecompile/plugin/`)

**Purpose:** Register MCP server as a Ghidra plugin to enable persistent, shared server across tools

##### Files:
- **`AgentDecompileApplicationPlugin.java`** - Application-level plugin; creates single `McpServerManager` at app startup
- **`ConfigManager.java`** - Manages configuration (settings, API key, server port/host)
- **`AgentDecompileProgramManager.java`** - Tracks open programs and tool associations

##### Key Details:
- Runs at Ghidra application level (not tool level) so server persists across tool sessions
- One server instance shared by all Ghidra tools
- Listens for project/tool lifecycle events and notifies server

#### 5. Tool Providers (`src/main/java/agentdecompile/tools/*/`)

**Purpose:** Implement MCP tools for specific Ghidra capabilities

**Structure:**
- Each tool category (symbols, strings, decompiler, functions, etc.) has a `*ToolProvider` class
- Each provider registers multiple related MCP tools with the server
- Tools handle request validation, execution, and response formatting

**Examples:**
- `SymbolToolProvider` → `list_symbols`, `rename_symbol`, `demangle`
- `DecompilerToolProvider` → `decompile_function`, `get_decompiled_code`
- `StringToolProvider` → `search_strings`, `list_strings`
- `FunctionToolProvider` → `list_functions`, `get_function_info`, `analyze_function`

#### 6. Resource Providers (`src/main/java/agentdecompile/resources/impl/`)

**Purpose:** Provide read-only data resources to clients

**Examples:**
- `ProgramListResource` → Lists all open programs
- `StaticAnalysisResultsResource` → Provides analysis metadata

#### 7. Utilities (`src/main/java/agentdecompile/util/`)

**Purpose:** Common utilities used across tools

**Key Classes:**
- **`AddressUtil`** - Format Ghidra addresses for JSON
- **`ProgramLookupUtil`** - Resolve program path to Program object
- **`DataTypeParserUtil`** - Parse data type strings
- **`DecompilationContextUtil`** - Decompiler utilities
- **`DebugLogger`** - Structured logging

### Data Flow

#### Request Flow: Client → Java

```
1. Client (Claude) sends JSON-RPC request over stdio
   │
2. stdio_bridge.py receives on stdin
   │
3. Bridge forwards to Java backend:
   POST http://localhost:{port}/mcp/message
   Content-Type: application/json
   {...JSON-RPC request...}
   │
4. Jetty receives HTTP request
   │
5. ApiKeyAuthFilter validates auth (if enabled)
   │
6. RequestLoggingFilter logs request (if enabled)
   │
7. KeepAliveFilter adds keep-alive headers
   │
8. HttpServletStreamableServerTransportProvider routes to MCP server
   │
9. MCP server dispatches to tool/resource provider
   │
10. Provider executes Ghidra operation
    │
11. Provider formats response as MCP CallToolResult
    │
12. MCP server returns via HTTP
    │
13. Bridge receives response, converts to stdio JSON-RPC
    │
14. Client reads JSON-RPC response from stdout
```

#### Response Flow: Java → Client

```
1. Tool provider executes Ghidra API call
   │
2. Tool provider creates MCP response (CallToolResult)
   │
3. MCP server encodes as JSON-RPC response
   │
4. HTTP response sent back to bridge
   │
5. Bridge's ClientSession receives response
   │
6. Bridge converts to stdio JSON-RPC
   │
7. stdio_server writes to stdout
   │
8. Client receives and processes
```

### Deployment Models

#### Model 1: Ghidra GUI with MCP Server (GUI Plugin)

```
┌─────────────────────────────────────┐
│  Ghidra GUI Application             │
│  ┌─────────────────────────────────┐│
│  │ AgentDecompileApplicationPlugin           ││
│  │ (starts on Ghidra init)         ││
│  │ ┌───────────────────────────────┐│
│  │ │ McpServerManager              ││
│  │ │ (HTTP on port 8080)           ││
│  │ └───────────────────────────────┘│
│  │ ┌───────────────────────────────┐│
│  │ │ Tool Providers                ││
│  │ │ (use Ghidra GUI state)        ││
│  │ └───────────────────────────────┘│
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
           ↓ HTTP ↑
    stdio_bridge (Python)
```

**Advantages:**
- Persistent server across tool/project changes
- Can use GUI features (dialogs, progress bars)
- Multiple tools can access same server
- Interactive workflows possible

**Disadvantages:**
- Requires Ghidra GUI to be running
- Server shared; one slow operation affects all clients

#### Model 2: Headless Server with Stdio Bridge (CLI)

```
┌──────────────────────────────────────┐
│ Python CLI (agentdecompile_cli)                │
│ ┌────────────────────────────────────┐
│ │ launcher.py                        │
│ │ (starts Java process)              │
│ │ ┌──────────────────────────────────┐
│ │ │ AgentDecompileHeadlessLauncher (Java)      │
│ │ │ ┌──────────────────────────────┐ │
│ │ │ │ McpServerManager             │ │
│ │ │ │ (HTTP on random port)        │ │
│ │ │ └──────────────────────────────┘ │
│ │ └──────────────────────────────────┘
│ │ stdio_bridge.py                    │
│ │ (connects to HTTP, exposes stdio)  │
│ └────────────────────────────────────┘
└──────────────────────────────────────┘
            ↓ stdin/stdout ↑
         Client (Claude CLI)
```

**Advantages:**
- Headless; no GUI required
- Independent processes (each run is isolated)
- Can run multiple instances
- Suitable for scripting/automation

**Disadvantages:**
- Starts new Ghidra instance each time (slower)
- Project conflicts if multiple instances use same project
- No GUI interaction possible

### Remote and Local Connection

**Default:** Server binds to `127.0.0.1` (configurable port, default 8080; CLI uses a random port). Python bridge connects to `http://localhost:{port}/mcp/message`. No remote access by default.

**Remote access:** No built-in SSH tunneling or WebSocket transport. To allow remote MCP access: (1) set `server.host` to `0.0.0.0` (or a specific IP) via `ConfigManager`, (2) enable API key authentication if desired (`ApiKeyAuthFilter`, `X-API-Key` header), (3) open firewall ports, (4) have clients connect to `http://{remote_ip}:{port}/mcp/message`.

**Shared project auth:** For Ghidra Server (remote repositories), use env vars `AGENT_DECOMPILE_SERVER_USERNAME` / `AGENT_DECOMPILE_SERVER_PASSWORD` or tool params `serverUsername` / `serverPassword` in the open tool—these authenticate to the Ghidra Server, not to the MCP server itself.

**Connection flow summary:**

```
┌─────────────────────────────────────────────────────────┐
│  MCP Client (Claude CLI, VSCode, etc.)                   │
└─────────────────────────────────────────────────────────┘
                    ↓ stdio JSON-RPC (CLI) or HTTP (direct)
┌─────────────────────────────────────────────────────────┐
│  Python: AgentDecompileStdioBridge (CLI only)           │
│  Proxies stdio ↔ HTTP POST /mcp/message                  │
└─────────────────────────────────────────────────────────┘
                    ↓ HTTP POST /mcp/message
┌─────────────────────────────────────────────────────────┐
│  Java: McpServerManager (Jetty)                         │
│  Streamable HTTP, 17 tool providers, resource providers  │
└─────────────────────────────────────────────────────────┘
                    ↓ Java API calls
┌─────────────────────────────────────────────────────────┐
│  Ghidra Framework                                        │
└─────────────────────────────────────────────────────────┘
```

### Execution Environments

#### Java Thread Contexts

**Main Thread (startup):**
- Initializes Ghidra, plugins, tools
- Registers MCP server
- Spawns Jetty in background thread

**Jetty Thread Pool:**
- Handles HTTP requests concurrently
- Executes tool provider handlers
- Critical: configured with explicit thread pool to prevent thread exhaustion

**PyGhidra Thread:**
- When running headless via Python, Ghidra runs in JVM spawned by PyGhidra
- Python async event loop runs simultaneously
- JSON-RPC bridge translates between Python async and Java sync

#### Python Async Contexts

**Main CLI Thread:**
- Synchronous: initializes PyGhidra, starts Java launcher
- Blocks until Java server ready

**stdio_bridge Event Loop:**
- Asynchronous: runs MCP server over stdio
- Handles multiple concurrent client requests
- Forwards requests to Java server via async HTTP client
- Runs until client disconnects

### Key Design Decisions

#### 1. Separate Python and Java Processes
- **Why:** Ghidra requires JVM; Python enables CLI integration with MCP
- **Tradeoff:** IPC overhead vs. language flexibility

#### 2. HTTP for Inter-Process Communication
- **Why:** Clean separation; reuses MCP SDK's HTTP transport
- **Tradeoff:** Network latency vs. simplicity and independence

#### 3. Long Timeout Configuration (24 hours)
- **Why:** Ghidra operations can be slow; prevent premature connection closure
- **Tradeoff:** May hold resources longer; suitable for interactive sessions

#### 4. Multiple Tool Providers Pattern
- **Why:** Modular; easy to add new tools without modifying server core
- **Tradeoff:** More classes; potentially duplicated validation logic

#### 5. Session-based Projects in Headless Mode
- **Why:** Simplify cleanup; avoid project lock conflicts
- **Tradeoff:** Can't persist project state across CLI invocations (unless `AGENT_DECOMPILE_PROJECT_PATH` used)

### Future Extensibility

- **Multiple Ghidra Instances:** Currently one per process; future: pool or attach mode
- **Clustering:** Multiple servers with load balancing (would need state synchronization)
- **Plugins:** Tool providers are discoverable; could be made pluggable
- **Custom Resources:** Easy to add new resource types by extending `AbstractResourceProvider`

*Part 4 — Internals: network flow, threading, configuration, program lifecycle, tool provider pattern, and error handling.*

---

## Internals

This document provides a deep technical dive into the implementation details of AgentDecompile, including network flows, threading models, and design patterns.

### Network Flow in Detail

#### Complete Request Path: Client → Ghidra → Response

##### 1. Client sends JSON-RPC request over stdio

```
{
  "jsonrpc": "2.0",
  "id": 123,
  "method": "call_tool",
  "params": {
    "name": "list_functions",
    "arguments": { "programPath": "/bin" }
  }
}
```

##### 2. Python stdio_bridge receives on stdin

- `stdio_server()` context manager reads from stdin
- MCP SDK parses JSON-RPC and converts to `CallToolRequest`
- Passes to registered handler: `call_tool(name, arguments)`

**Code:** `src/agentdecompile_cli/stdio_bridge.py` → `@self.server.call_tool()`

##### 3. Bridge handler calls Java backend

```python
async def _call_tool_operation():
    return await asyncio.wait_for(
        self.backend_session.call_tool(name, arguments),
        timeout=300.0
    )
```

The `ClientSession` (MCP SDK) converts to HTTP (streamable HTTP transport):

```
POST http://localhost:{port}/mcp/message HTTP/1.1
Content-Type: application/json
Connection: keep-alive

{
  "jsonrpc": "2.0",
  "id": ...,
  "method": "call_tool",
  "params": { ... }
}
```

**Code:** `src/agentdecompile_cli/stdio_bridge.py` → `streamablehttp_client()`. Bridge uses long timeouts (1 hour for tool calls and connections), concurrency limiting (semaphore, max 3 concurrent requests), retry with exponential backoff (max 3 retries), and a circuit breaker (5 consecutive failures → 10s backoff). Non-JSON log messages are wrapped via `JsonEnvelopeStream` as JSON-RPC notifications.

##### 4. Jetty receives HTTP request

```
POST /mcp/message
↓
[GlobalExceptionFilter]  (error handling)
↓
[ApiKeyAuthFilter]  (validates auth if enabled)
↓
[RequestLoggingFilter]  (logs if debug enabled)
↓
[KeepAliveFilter]  (adds Connection: keep-alive header)
↓
[HttpServletStreamableServerTransportProvider]
↓
[MCP Handler]
```

**Code:** `src/main/java/agentdecompile/server/McpServerManager.java` → `startServer()`

##### 5. MCP server routes to tool provider

```
MCP Server.callTool(name, arguments)
↓
Tool Registry lookup (finds matching tool)
↓
Call tool handler function
↓
Tool Provider (e.g., FunctionToolProvider)
↓
Execute Ghidra operation
```

**Code:** `src/main/java/agentdecompile/tools/*/` → `registerTools()`

##### 6. Tool provider executes Ghidra operation

```java
Tool.handle(CallToolRequest request) {
    // Validate inputs
    Program program = ProgramLookupUtil.getValidatedProgram(request.arguments.get("programPath"));
    
    // Execute Ghidra API
    List<Function> functions = program.getFunctionManager().getFunctions(true);
    
    // Format response
    List<Map<String, Object>> result = functions.stream()
        .map(f -> /* format function data */)
        .collect(toList());
    
    // Return as CallToolResult
    return CallToolResult.builder()
        .content(List.of(TextContent.of(gson.toJson(result))))
        .build();
}
```

**Code:** `src/main/java/agentdecompile/tools/` → tool providers

##### 7. Response flows back through HTTP

```
CallToolResult
↓
[MCP Server]
Encodes as JSON-RPC response:
{
  "jsonrpc": "2.0",
  "id": 123,
  "result": {
    "content": [{ "type": "text", "text": "[...]" }]
  }
}
↓
[Jetty servlet]
Sends HTTP 200 with JSON body
↓
[Python ClientSession]
Receives HTTP response
```

##### 8. Python bridge converts to stdio

```python
result = await self._call_with_reconnect("call_tool(...)", _call_tool_operation)
##result.content is list of TextContent objects

##Bridge handler returns directly to stdio_server
return result.content  # List[TextContent]
```

The MCP SDK converts back to JSON-RPC and writes to stdout.

##### 9. Client receives response on stdout

```json
{
  "jsonrpc": "2.0",
  "id": 123,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"address\":\"0x1000\",\"name\":\"main\"},...]"
      }
    ]
  }
}
```

#### Connection Handling

**Timeout Configuration:**

- **Python bridge:** 1 hour for tool calls and for connection/read timeouts (long-running Ghidra operations).
- **Jetty:** `idleTimeout=86400000` (24 hours) on thread pool, HTTP config, and connector.
- **HTTP Headers:** `Keep-Alive` allows long-lived connections.
- **MCP Keep-Alive:** `keepAliveInterval=30s` (sends periodic pings).

**Why so long?** Ghidra operations (decompilation, analysis) can be slow. 24 hours and 1-hour client timeouts ensure long-running tasks complete without "Session terminated" errors.

---

### Threading and Concurrency

#### Java Thread Hierarchy

```
Main Thread (gradle/IDE/Ghidra launch)
├── Jetty Server Thread
│   ├── Jetty Worker Thread 1 [request handler]
│   ├── Jetty Worker Thread 2 [request handler]
│   └── ... (up to 200 threads)
└── Ghidra Initialization Thread
    └── Ghidra Application (shared for all tools/programs)
```

#### Jetty Thread Pool Configuration

**File:** `src/main/java/agentdecompile/server/McpServerManager.java` → `startServer()`

```java
QueuedThreadPool jettyThreadPool = new QueuedThreadPool();
jettyThreadPool.setIdleTimeout(86400000);  // 24 hours
jettyThreadPool.setMaxThreads(200);        // Max concurrent requests
jettyThreadPool.setMinThreads(8);          // Threads to keep alive
jettyThreadPool.setName("AgentDecompile-Jetty");     // For debugging
```

**Why explicit configuration?**

Default Jetty thread pool has `idleTimeout ~60 seconds`, causing threads to be removed after short idle periods. With default config, a server idle for 5+ minutes would exhaust its thread pool, leading to failures.

**Diagram:**
```
Request arrives
↓
Jetty assigns from thread pool (min 8 available)
↓
Tool provider executes Ghidra operation (may block)
↓
Response sent
↓
Thread returns to pool (stays alive for 24 hours if unused)
↓
Another request reuses thread
```

#### Python Async Model

**File:** `src/agentdecompile_cli/stdio_bridge.py` → `run()`

```python
##Main event loop (single-threaded)
asyncio.run(self.run())

##Inside run():
async def run(self):
    # Async context: can await without blocking
    async with streamablehttp_client(...) as (read_stream, write_stream, get_session_id):
        # Non-blocking HTTP client
        self.backend_session = ClientSession(read_stream, write_stream)
        
        async with stdio_server() as (stdio_read, stdio_write):
            # Non-blocking stdio reader
            await self.server.run(stdio_read, stdio_write, ...)
            # Concurrently handles multiple MCP requests
```

**Concurrency model:**
- **Python:** Single event loop, async/await, non-blocking I/O
- **Java:** Thread pool, blocking I/O, synchronous execution
- **Bridge:** Async Python wraps sync Java; `ClientSession` manages HTTP serialization

**Implication:** Multiple concurrent client requests can hit the bridge, but each is individually serialized through HTTP to Java. Python doesn't block on long Ghidra operations.

---

### Configuration Management

#### ConfigManager (Java)

**File:** `src/main/java/agentdecompile/plugin/ConfigManager.java`

```java
public class ConfigManager {
    // Configuration keys
    public static final String SERVER_OPTIONS = "Server";
    public static final String SERVER_HOST = "host";
    public static final String SERVER_PORT = "port";
    public static final String API_KEY_ENABLED = "apiKeyEnabled";
    public static final String API_KEY = "apiKey";
    
    // Retrieve settings
    public String getServerHost() { ... }
    public int getServerPort() { ... }
    public boolean isApiKeyEnabled() { ... }
    
    // Listen for changes
    public void onConfigChanged(...) {
        // Restart server if port/host changes
    }
}
```

**Modes:**

1. **GUI Mode:** Uses Ghidra ToolOptions (persistent user preferences)
   ```java
   new ConfigManager(pluginTool)  // Reads from Ghidra settings UI
   ```

2. **Headless Mode:** Uses file or in-memory config
   ```java
   new ConfigManager()  // In-memory defaults
   new ConfigManager(configFile)  // Load from .properties file
   ```

**Environment Variables:**

Environment variables override file config (checked by launcher):

```bash
##Python reads these and passes to Java
AGENT_DECOMPILE_SERVER_HOST=0.0.0.0
AGENT_DECOMPILE_SERVER_PORT=9999
AGENT_DECOMPILE_API_KEY_ENABLED=true
AGENT_DECOMPILE_API_KEY=secret123
```

**Code:** `src/agentdecompile_cli/launcher.py` → `start()`

---

### Program Lifecycle

#### GUI Mode: Tool ↔ Program ↔ Server

```
Ghidra GUI
├── Tool 1
│   ├── Program A (decompiler open)
│   └── Program B (closed)
├── Tool 2
│   └── Program A (different view)
└── AgentDecompileApplicationPlugin (application-level)
    └── McpServerManager
        ├── tracks: Tool1 ↔ ProgramA
        ├── tracks: Tool1 ↔ ProgramB
        └── tracks: Tool2 ↔ ProgramA
```

**Flow:**

1. User opens Program A in Tool 1
2. Tool 1 calls `AgentDecompileMcpService.programOpened(program, tool)`
3. Service notifies `McpServerManager`
4. Server stores mapping: `Program A → {Tool 1, Tool 2}`
5. Tool providers query: `getActiveProgram()` → returns A
6. Decompiler tool uses Program A for requests

**Code:** `src/main/java/agentdecompile/plugin/AgentDecompileApplicationPlugin.java` → `programOpened()`

#### Headless Mode: Single Project

```
Python Launcher
├── Creates Ghidra headless instance
├── Opens Project (from AGENT_DECOMPILE_PROJECT_PATH or temp)
└── McpServerManager
    └── Program from project (if imported)
```

**Flow:**

1. Python launcher checks `AGENT_DECOMPILE_PROJECT_PATH` environment variable
2. If set, opens that project
3. If not set, creates ephemeral project in temp directory
4. Server sees single project; tools query it
5. On exit, temp project deleted

**Code:** `src/agentdecompile_cli/launcher.py` → `start()`

---

### Tool Provider Pattern

#### Template Pattern: AbstractToolProvider

**File:** `src/main/java/agentdecompile/tools/AbstractToolProvider.java`

```java
public abstract class AbstractToolProvider {
    protected final McpSyncServer server;
    protected final String toolPrefix;
    
    // Subclasses implement:
    public abstract void registerTools();
    
    // Helper methods:
    protected void registerTool(McpSchema.Tool toolDef, ToolHandler handler) {
        server.addTool(toolDef, handler);
    }
    
    protected String getString(Map<String, Object> args, String key) {
        // Validated retrieval with error handling
    }
    
    protected Program getProgram(Map<String, Object> args) {
        // Resolve program path to Program object
    }
    
    // Lifecycle:
    public void programOpened(Program program) { ... }
    public void programClosed(Program program) { ... }
    public void cleanup() { ... }
}
```

#### Concrete Example: FunctionToolProvider

**File:** `src/main/java/agentdecompile/tools/functions/FunctionToolProvider.java`

```java
public class FunctionToolProvider extends AbstractToolProvider {
    public FunctionToolProvider(McpSyncServer server) {
        super(server, "function");
    }
    
    @Override
    public void registerTools() {
        // Tool 1: list_functions
        registerTool(
            McpSchema.Tool.builder()
                .name("list_functions")
                .description("List all functions in a program")
                .inputSchema(new McpSchema.JsonSchema(
                    "object",
                    Map.of(
                        "programPath", Map.of("type", "string")
                    ),
                    List.of("programPath"),
                    true, null, null
                ))
                .build(),
            (request) -> handleListFunctions(request)
        );
        
        // Tool 2: get_function_info
        // ...
    }
    
    private CallToolResult handleListFunctions(CallToolRequest request) {
        try {
            Program program = getProgram(request.params);
            FunctionManager fm = program.getFunctionManager();
            
            List<Map<String, Object>> functions = new ArrayList<>();
            for (Function func : fm.getFunctions(true)) {
                functions.add(Map.of(
                    "address", AddressUtil.formatAddress(func.getEntryPoint()),
                    "name", func.getName(),
                    "size", func.getBody().getNumAddresses()
                ));
            }
            
            return CallToolResult.builder()
                .content(List.of(TextContent.of(gson.toJson(functions))))
                .build();
        } catch (ProgramValidationException e) {
            return errorResult(e.getMessage());
        }
    }
}
```

#### Registration Flow

```
McpServerManager.initializeToolProviders()
├── new FunctionToolProvider(server)
├── new SymbolToolProvider(server)
├── new DecompilerToolProvider(server)
├── ...
└── for each provider:
    └── provider.registerTools()
        └── provider.registerTool(toolDef, handler)
            └── server.addTool(toolDef, handler)
                └── MCP Server stores tool + handler
```

When a client calls `list_functions`, MCP server dispatches to the handler registered during init.

---

### Error Handling

#### Error Propagation Path

```
Java Tool Provider
├── catches ProgramValidationException
│   └── returns CallToolResult with error content
├── catches IllegalArgumentException
│   └── converted to ProgramValidationException
└── uncaught Exception
    └── MCP SDK wraps as error response

MCP Server
├── error response sent to Python
└── Python bridge
    └── client receives error as JSON-RPC error
```

#### Validation

**Program Validation:**
```java
Program program = ProgramLookupUtil.getValidatedProgram(programPath);
// Throws ProgramValidationException if:
// - Path is null/empty
// - Program not found
// - Program not valid
```

**Tool Registration Error Handling:**
```java
// AbstractToolProvider wraps handlers
registerTool(toolDef, (request) -> {
    try {
        return handler(request);
    } catch (IllegalArgumentException e) {
        throw new ProgramValidationException("Invalid argument: " + e.getMessage());
    } catch (Exception e) {
        return errorResult("Tool failed: " + e.getMessage());
    }
});
```

#### Logging

**Ghidra Log:** Used for critical/warning/debug messages
```java
Msg.info(this, "Message to Ghidra log");
Msg.error(this, "Error with stack trace", exception);
```

**MCP Protocol Log:** Used for HTTP request/response logging (if enabled)
```
##In agentdecompile-tools.log (if RequestLoggingFilter enabled):
[AgentDecompile:req-12345] HTTP POST /mcp/message
Request: {...}
Response (200): {...}
Duration: 123ms
```

---

### Performance Considerations

#### Bottlenecks

1. **Ghidra Operations** (decompilation, analysis) → slow, blocking
2. **Network Latency** (stdio ↔ HTTP) → minimal impact, single roundtrip per request
3. **JSON Serialization** (for large results) → GsonUtil, can be large

#### Optimization Strategies

**1. Result Pagination**

Tools return large result sets in chunks:
```java
// Instead of returning 10,000 functions at once:
return CallToolResult.builder()
    .content(List.of(
        TextContent.of(gson.toJson(functions.subList(0, 100))),
        TextContent.of("(showing 100 of 10,000)")
    ))
    .build();
```

**2. Lazy Loading**

Defer expensive operations:
```java
// Don't decompile all functions immediately
// Decompile only on request
if (request.arguments.containsKey("decompile")) {
    decompile();  // expensive
}
```

**3. Caching**

Cache results where appropriate:
```java
// Example: cache function list for same program
private Map<Program, List<Function>> functionCache = new HashMap<>();
```

**4. Streaming Results**

For very large results, stream incrementally (future enhancement):
```
// Not currently implemented, but possible with MCP resource subscriptions
```

#### Memory Usage

- **Ghidra VM:** Configured by JVM heap (usually 2-4GB)
- **Python Process:** Minimal (mostly just event loop)
- **HTTP Connections:** One per client; long-lived

---

### Recommended Reading

- [Architecture](#architecture) - System overview
- [Development Setup](#development-setup) - Setup and building
- [MCP Protocol](#mcp-protocol) - MCP specifics

*Part 5 — MCP protocol: tool and resource definitions, request/response format, and adding new tools.*

---

## MCP Protocol

This document explains how AgentDecompile implements the Model Context Protocol (MCP) and how to work with MCP concepts.

### Table of Contents

- [MCP Overview](#mcp-overview)
- [AgentDecompile's MCP Implementation](#agentdecompiles-mcp-implementation)
- [Tool Definitions](#tool-definitions)
- [Resource Definitions](#resource-definitions)
- [Request/Response Examples](#requestresponse-examples)
- [Error Handling](#error-handling)
- [Protocol Compatibility](#protocol-compatibility)

### MCP Overview

The Model Context Protocol (MCP) is a standardized way for AI models to interact with external tools and data sources.

**Key Concepts:**

- **Tools:** Functions the AI can call with parameters and receive results
- **Resources:** Read-only data (files, databases, APIs) the AI can query
- **Prompts:** Templates or guidelines the AI can request
- **Notifications:** Server can send updates to clients

**Transport:**
- MCP SDK supports Stdio (stdin/stdout) and HTTP transports
- Messages are JSON-RPC 2.0 format
- Stateful: connection persists for multiple requests

**Spec:** https://modelcontextprotocol.io/

---

### AgentDecompile's MCP Implementation

#### Architecture

- **CLI path:** MCP client talks JSON-RPC over stdio to the Python bridge (`mcp-agentdecompile`). The bridge connects to the Java backend at `http://localhost:{port}/mcp/message` using streamable HTTP and proxies all MCP operations (list_tools, call_tool, list_resources, read_resource, list_prompts).
- **Direct HTTP path:** MCP client can connect directly to the Java server at `http://localhost:8080/mcp/message` (POST; streamable HTTP, not SSE) when running in GUI mode.

```
MCP Client (Claude CLI, VSCode, etc.)
  ↓ stdio JSON-RPC (CLI) or HTTP (direct)
AgentDecompile Stdio Bridge (Python, CLI only)
  ↓ HTTP POST /mcp/message (streamable HTTP)
AgentDecompile MCP Server (Java/Jetty)
  ↓ Java method calls
Ghidra Framework
```

#### Server Configuration

**Java Side:** `McpServerManager.java`

```java
// Define server info and capabilities
McpSchema.ServerCapabilities capabilities = McpSchema.ServerCapabilities.builder()
    .prompts(true)                  // Server provides prompts
    .resources(true, true)          // Server provides resources with subscriptions
    .tools(true)                    // Server provides tools
    .build();

// Create MCP server
server = McpServer.sync(currentTransportProvider)
    .serverInfo("AgentDecompile", "<semver version>")
    .capabilities(capabilities)
    .build();
```

**Python Side:** `stdio_bridge.py`

```python
##Create MCP server that proxies to Java backend
self.server = Server("AgentDecompile")

##Register handlers (proxies to Java)
@self.server.list_tools()
async def list_tools() -> list[Tool]:
    # Forward to Java backend
    result = await self.backend_session.list_tools()
    return result.tools
```

#### Initialization Handshake

When a client connects:

```
Client                           AgentDecompile Server
  │                                 │
  ├─ {"method":"initialize", ...─→ │
  │                            Process client capabilities
  │                                 │
  │ ←── {"result": {"serverInfo", "capabilities"}} ──┤
  │                                 │
  ├─ {"method":"initialized"}  ────→ │
  │                            Server now ready
  │                                 │
  ├─ {"method":"list_tools"}   ────→ │
  │ ←── {"result": {"tools": [...]}} │
  │                                 │
  ├─ {"method":"call_tool", ...─→ │
  │ ←── {"result": {"content": [...]}} │
```

---

### Tool Definitions

#### Anatomy of a Tool

A tool is defined by:

1. **Name:** Unique identifier (snake_case)
2. **Description:** Human-readable explanation
3. **Input Schema:** JSON Schema defining parameters
4. **Handler:** Function that executes the tool

#### Example: list_functions Tool

**Definition (Java):**

```java
McpSchema.Tool tool = McpSchema.Tool.builder()
    .name("list_functions")
    .description("List all functions in a program, with addresses and sizes. " +
                 "Returns a JSON array of function objects.")
    .inputSchema(new McpSchema.JsonSchema(
        "object",                          // Schema type
        Map.of(
            "programPath", Map.of(         // Required parameter
                "type", "string",
                "description", "Path to program (e.g., '/bin' or 'C:\\\\bin.exe')"
            )
        ),
        List.of("programPath"),            // Required parameters
        true,                              // Additional properties not allowed
        null, null
    ))
    .build();
```

**Handler (Java):**

```java
(CallToolRequest request) -> {
    // Extract parameters
    String programPath = getString(request.params, "programPath");
    Program program = getProgram(Map.of("programPath", programPath));
    
    // Execute
    List<Map<String, Object>> functions = new ArrayList<>();
    for (Function func : program.getFunctionManager().getFunctions(true)) {
        functions.add(Map.of(
            "address", AddressUtil.formatAddress(func.getEntryPoint()),
            "name", func.getName(),
            "size", func.getBody().getNumAddresses()
        ));
    }
    
    // Return
    return CallToolResult.builder()
        .content(List.of(TextContent.of(gson.toJson(functions))))
        .build();
}
```

#### Tool Categories in AgentDecompile

| Provider | Tools |
|----------|-------|
| **SymbolToolProvider** | `list_symbols`, `rename_symbol`, `demangle_symbol`, etc. |
| **FunctionToolProvider** | `list_functions`, `get_function_info`, `analyze_function` |
| **DecompilerToolProvider** | `decompile_function`, `get_decompiled_code`, `analyze_decompilation` |
| **StringToolProvider** | `search_strings`, `list_strings`, `find_string_xrefs` |
| **DataToolProvider** | `read_bytes`, `write_bytes`, `search_bytes` |
| **MemoryToolProvider** | `get_memory_map`, `inspect_memory` |
| **CrossReferencesToolProvider** | `find_xrefs_to`, `find_xrefs_from`, `trace_data_flow` |
| **StructureToolProvider** | `list_structures`, `create_structure`, `apply_structure` |
| **ProjectToolProvider** | `list_programs`, `open_program`, `import_binary` |

#### Input Schema Design

**Best Practices:**

1. **Keep it simple:** Minimalist schemas help AI models use tools correctly
2. **Use descriptions:** Explain what values are expected
3. **Validate in handler:** Don't rely on schema alone; validate in code
4. **Tolerate variation:** Accept multiple input formats when reasonable

**Example with description:**

```java
Map.of(
    "address", Map.of(
        "type", "string",
        "description", "Address in hex format (e.g., '0x1234' or '4660 decimal). " +
                       "The tool accepts both hex and decimal."
    ),
    "size", Map.of(
        "type", "integer",
        "description", "Number of bytes to read (default: 16)"
    ),
    "format", Map.of(
        "type", "string",
        "enum", List.of("hex", "ascii", "int32", "int64"),
        "description", "Display format for bytes (default: hex)"
    )
)
```

---

### Resource Definitions

Resources are **read-only** data the AI can query (unlike tools which are executable).

#### Example: Program List Resource

**Definition (Java):**

```java
public class ProgramListResource extends AbstractResourceProvider {
    
    @Override
    public void register() {
        server.addResource(
            McpSchema.Resource.builder()
                .uri("ghidra://programs")
                .name("Programs")
                .description("List of all open programs in the current project")
                .mimeType("application/json")
                .build(),
            this  // this implements read content handler
        );
    }
    
    @Override
    public Resource readResource(String uri) {
        if ("ghidra://programs".equals(uri)) {
            Program[] programs = getCurrentPrograms();
            List<Map<String, String>> list = Arrays.stream(programs)
                .map(p -> Map.of(
                    "name", p.getName(),
                    "path", p.getExecutablePath(),
                    "language", p.getLanguage().getLanguageID().getIdAsString()
                ))
                .collect(toList());
            
            return new Resource(
                "ghidra://programs",
                new TextContent("application/json", gson.toJson(list))
            );
        }
        throw new IllegalArgumentException("Unknown resource: " + uri);
    }
}
```

#### Resource Subscriptions

Resources can support subscriptions (clients get notified of changes):

```java
// Enable in server capabilities
McpSchema.ServerCapabilities.builder()
    .resources(true, true)  // Second param: subscriptions enabled
    .build()
```

Clients can subscribe:

```
{"method":"subscribe", "params":{"uri":"ghidra://programs"}}
```

Server can then send notifications:

```
{"method":"resources/updated", "params":{"resourceUri":"ghidra://programs"}}
```

**Current Resources in AgentDecompile:**

- `ghidra://programs` - List of open programs
- `ghidra://analysis-results` - Static analysis results
- `ghidra://debug-info` - Debug information (if enabled)

---

### Request/Response Examples

#### Example 1: List Functions

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call_tool",
  "params": {
    "name": "list_functions",
    "arguments": {
      "programPath": "/bin/ls"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"address\":\"0x401000\",\"name\":\"main\",\"size\":1234},{\"address\":\"0x401500\",\"name\":\"_start\",\"size\":567}]"
      }
    ]
  }
}
```

#### Example 2: Decompile Function

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "call_tool",
  "params": {
    "name": "decompile_function",
    "arguments": {
      "programPath": "/bin/ls",
      "address": "0x401000",
      "includeAssembly": true
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "undefined main(void)\n{\n  int local_10;\n  ...\n  return 0;\n}\n\n// Assembly:\n// 401000: 55              PUSH   RBP\n// 401001: 48 89 e5       MOV    RBP,RSP\n"
      }
    ]
  }
}
```

#### Example 3: Read Resource

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "read_resource",
  "params": {
    "uri": "ghidra://programs"
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "contents": [
      {
        "type": "text",
        "mimeType": "application/json",
        "text": "[{\"name\":\"bin/ls\",\"path\":\"/bin/ls\",\"language\":\"x86:LE:64:default\"}]"
      }
    ]
  }
}
```

#### Example 4: Error Response

**Request (invalid program path):**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "call_tool",
  "params": {
    "name": "list_functions",
    "arguments": {
      "programPath": "/nonexistent"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": {
      "details": "Program not found: /nonexistent"
    }
  }
}
```

---

### Error Handling

#### Error Codes

MCP uses JSON-RPC 2.0 error codes:

| Code | Meaning | AgentDecompile Use |
|------|---------|----------|
| -32700 | Parse error | Invalid JSON sent to server |
| -32600 | Invalid request | Malformed JSON-RPC |
| -32601 | Method not found | Unknown tool name |
| -32602 | Invalid params | Missing required parameter |
| -32603 | Internal error | Ghidra operation failed |

#### Error Handling in AgentDecompile

**Tool Provider Exception Handling:**

```java
private CallToolResult handleListFunctions(CallToolRequest request) {
    try {
        Program program = getProgram(request.params);
        // ... execute ...
        return result;
    } catch (ProgramValidationException e) {
        // Validation error → -32602 Invalid params
        return errorResult("Invalid argument: " + e.getMessage());
    } catch (Exception e) {
        // Unexpected error → -32603 Internal error
        Msg.error(this, "Unexpected error", e);
        return errorResult("Internal server error: " + e.getClass().getSimpleName());
    }
}

private CallToolResult errorResult(String message) {
    return CallToolResult.builder()
        .isError(true)
        .content(List.of(TextContent.of(message)))
        .build();
}
```

**Python Bridge Exception Handling:**

```python
try:
    result = await self._call_with_reconnect("call_tool(...)", operation)
    return result.content
except asyncio.TimeoutError:
    return [TextContent(type="text", text=f"Error: Tool '{name}' timed out")]
except Exception as e:
    return [TextContent(type="text", text=f"Error: {e.__class__.__name__}: {e}")]
```

---

### Protocol Compatibility

#### MCP Version Support

AgentDecompile uses **MCP SDK 0.17.0**, supporting:

- **Protocol Version:** 2024-11-25 (latest)
- **JSON-RPC:** 2.0
- **Transport:** Stdio and HTTP StreamableHTTP

#### Compatibility Notes

**Issue #724 (Unknown Properties):**

The MCP SDK doesn't gracefully handle unknown protocol fields from newer clients (e.g., VS Code uses protocol 2025-11-25). AgentDecompile works around this:

```java
// src/main/java/agentdecompile/server/McpServerManager.java
ObjectMapper objectMapper = new ObjectMapper();
objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(objectMapper);
```

This allows clients with newer protocol fields to work with AgentDecompile even if the SDK doesn't understand them.

#### Testing Compatibility

To test MCP compatibility:

```bash
##Start AgentDecompile CLI
python -m agentdecompile_cli

##Use Claude CLI to connect
claude mcp add AgentDecompile -- python -m agentdecompile_cli

##Verify tools are listed
##In Claude, ask to use AgentDecompile tools
```

---

### Adding a New Tool

#### Checklist

- [ ] Create `*ToolProvider.java` extending `AbstractToolProvider`
- [ ] Define tool schema (name, description, input schema)
- [ ] Implement handler function
- [ ] Register tool in `registerTools()` method
- [ ] Add provider instance to `McpServerManager.initializeToolProviders()`
- [ ] Write unit tests (test valid/invalid inputs, error cases)
- [ ] Write integration test (test with actual Ghidra operation)
- [ ] Document tool in tool list

#### Template

```java
public class MyToolProvider extends AbstractToolProvider {
    
    public MyToolProvider(McpSyncServer server) {
        super(server, "my-tool");
    }
    
    @Override
    public void registerTools() {
        // Register each tool
        registerTool(
            McpSchema.Tool.builder()
                .name("my_tool_name")
                .description("Human-readable description")
                .inputSchema(/* JSON schema */)
                .build(),
            this::handleMyTool
        );
    }
    
    private CallToolResult handleMyTool(CallToolRequest request) {
        try {
            // Validate inputs
            String param = getString(request.params, "param_name");
            Program program = getProgram(request.params);
            
            // Execute
            Object result = doSomething(program, param);
            
            // Return
            return CallToolResult.builder()
                .content(List.of(TextContent.of(gson.toJson(result))))
                .build();
        } catch (ProgramValidationException e) {
            return errorResult(e.getMessage());
        }
    }
}
```

---

### Debugging MCP Traffic

#### Enable Request Logging

**GUI Mode:**

1. Ghidra → File → Edit Tool Options
2. AgentDecompile → Debug → Enable Request Logging
3. Logs appear in `agentdecompile-tools.log`

**Headless Mode:**

Set environment variable before starting:

```bash
export AGENT_DECOMPILE_DEBUG=true
python -m agentdecompile_cli 2>&1 | grep "HTTP"
```

#### Inspect Messages

**Stdio (CLI):**

```bash
##Capture stdin/stdout for inspection
python -m agentdecompile_cli | tee mcp_output.jsonl
```

Each line in the output is a JSON-RPC message.

**HTTP (Java):**

The `RequestLoggingFilter` logs full HTTP bodies if enabled. Check logs for patterns:

```
[AgentDecompile:req-12345] HTTP POST /mcp/message
Request Headers: ...
Request Body: {...}
Response Status: 200
Response Body: {...}
```

---

### Further Reading

- [MCP Specification](https://modelcontextprotocol.io/)
- [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk)
- [Architecture](#architecture) - System design
- [Internals](#internals) - Implementation details

*Part 6 — Implementation guides: tool patterns (including manage-structures), disabled tools refactoring, Ghidra scripts, shared project API, authentication, and locking.*

---

## Batch Add Field Example

This section demonstrates how to use the batch `add_field` action in the `manage-structures` tool to add multiple fields to a structure in a single operation. For size preservation, `useReplace`, and `preserveSize`, see [Structure Size Preservation](#structure-size-preservation-in-manage-structures-tool).

### Problem

Previously, adding multiple fields to a structure required separate tool calls for each field:

```json
// Call 1
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "list04_active_ptr",
    "dataType": "void *",
    "offset": 56
  }
}

// Call 2
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "list04_active_count",
    "dataType": "int",
    "offset": 60
  }
}

// ... 4 more calls ...
```

### Solution

With batch mode, you can add all fields in a single call using the `fields` array parameter:

```json
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fields": [
      {
        "fieldName": "list04_active_ptr",
        "dataType": "void *",
        "offset": 56
      },
      {
        "fieldName": "list04_active_count",
        "dataType": "int",
        "offset": 60
      },
      {
        "fieldName": "list04_active_capacity",
        "dataType": "int",
        "offset": 64
      },
      {
        "fieldName": "list05_dynamic_ptr",
        "dataType": "void *",
        "offset": 68
      },
      {
        "fieldName": "list05_dynamic_count",
        "dataType": "int",
        "offset": 72
      },
      {
        "fieldName": "list05_dynamic_capacity",
        "dataType": "int",
        "offset": 76
      }
    ]
  }
}
```

### Benefits

1. **Performance**: All fields are added in a single transaction, reducing overhead
2. **Atomicity**: All fields are added together or none at all
3. **Better Error Handling**: Individual field errors are reported without failing the entire operation
4. **Network Efficiency**: Only one MCP call instead of multiple

### Response Format

The batch operation returns detailed results:

```json
{
  "success": true,
  "structureName": "LightManager",
  "total": 6,
  "succeeded": 6,
  "failed": 0,
  "results": [
    {
      "index": 0,
      "fieldName": "list04_active_ptr",
      "dataType": "void *",
      "offset": 56,
      "fieldOrdinal": 0
    },
    {
      "index": 1,
      "fieldName": "list04_active_count",
      "dataType": "int",
      "offset": 60,
      "fieldOrdinal": 1
    }
    // ... more results ...
  ],
  "message": "Successfully added 6 field(s) to structure: LightManager",
  "name": "LightManager",
  "size": 80,
  "originalSize": 56,
  "finalSize": 80,
  "displayName": "LightManager",
  "categoryPath": "/",
  "numComponents": 6
}
```

### Options

- **preserveSize** (optional): When `true`, the operation fails and rolls back if the structure size would grow.
- **useReplace** (optional, default: `true`): When `true`, uses `replaceAtOffset` so fields replace bytes at the given offset without shifting (recommended for explicit layouts).

When the structure size changes, the response may include `sizeGrew`, `sizeGrowth`, and `sizeWarning`. For full details and migration notes, see [Structure Size Preservation](#structure-size-preservation-in-manage-structures-tool).

### Field Object Properties

Each field object in the `fields` array must have:
- `fieldName` (required): Name of the field
- `dataType` (required): Data type (e.g., "int", "void *", "char[32]")
- `offset` (optional): Byte offset in the structure. Omit to append at the end.
- `comment` (optional): Comment for the field

### Backwards Compatibility

The single-field syntax still works for adding one field at a time:

```json
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "myField",
    "dataType": "int",
    "offset": 80,
    "comment": "My field comment"
  }
}
```

### Error Handling

If individual fields fail during batch mode, they are reported in the `errors` array:

```json
{
  "success": true,
  "structureName": "LightManager",
  "total": 6,
  "succeeded": 5,
  "failed": 1,
  "results": [ /* 5 successful fields */ ],
  "errors": [
    {
      "index": 3,
      "fieldName": "invalid_field",
      "error": "Failed to parse data type: UnknownType"
    }
  ],
  "message": "Successfully added 5 field(s) to structure: LightManager"
}
```

The operation continues adding other fields even if one fails.

---

## Structure Size Preservation in manage-structures Tool

### Problem

When using the `manage-structures` tool's `add_field` action with batch operations, structures can grow beyond their intended size. This is caused by Ghidra's `insertAtOffset()` method, which shifts existing components to avoid conflicts, potentially expanding the structure.

#### Example Scenario

```
1. Create structure with size=743 bytes
2. Add field "Gob" at offset 248 (size 464 bytes)
3. Expected end: 248 + 464 = 712, with 31 bytes padding = 743 bytes
4. Actual result: Structure grows to 1455 bytes due to automatic alignment and shifts
```

### Root Cause

Ghidra's `Structure.insertAtOffset()` behavior:

- Shifts conflicting components down to avoid overlap
- Adds automatic padding/alignment even with `packed=true` in some cases
- Recalculates structure size based on component placements
- Doesn't respect the original `size` parameter from `create` action

For user-facing options (`useReplace`, `preserveSize`), response format, comparison matrix, migration guide, and FAQ, see [README.md](README.md#structure-size-manage-structures).

### Technical Details

#### Ghidra API Methods

- **`insertAtOffset(offset, dataType, length, name, comment)`**
  - Behavior: Inserts field, shifts conflicting components down
  - Effect: Can grow structure beyond intended size
  - Use when: Inserting into packed structures or when shifting is desired

- **`replaceAtOffset(offset, dataType, length, name, comment)`**
  - Behavior: Replaces existing bytes at offset
  - Effect: Consumes undefined bytes, preserves structure layout
  - Use when: Non-packed structures with explicit byte layout

- **`setLength(length)`**
  - Behavior: Sets structure size (non-packed only)
  - Effect: Trims or grows structure
  - Note: Only affects non-packed structures

#### Why `parse_header` Works

The C parser:

1. Parses the entire structure definition in one operation
2. Respects `#pragma pack(push, 1)` directives
3. Calculates component offsets and padding atomically
4. Creates structure with exact layout in single transaction

### Implementation Notes

For developers maintaining this code:

1. **Size tracking**: Original size is recorded at start of transaction
2. **Validation**: `preserveSize` checks size before committing transaction
3. **Method selection**: `useReplace` switches from `insertAtOffset()` to `replaceAtOffset()`
4. **Warning messages**: All operations return size tracking info in response
5. **Rollback**: Failed `preserveSize` validation rolls back entire transaction

See `StructureToolProvider.handleBatchAddFields()` for implementation details.

---

## Disabled Tools Refactoring

This section tracks the refactoring of disabled tool logic to ensure active tools reuse the original tool handlers, benefiting from upstream updates.

### Overview

Several tools were disabled/merged but their handlers are kept for upstream compatibility. To ensure we benefit from upstream improvements, we've extracted the handler logic into reusable protected methods that active tools can call directly.

### Refactoring Strategy

1. **Extract Handler Logic**: Move tool handler logic from disabled `register*Tool()` methods into protected handler methods
2. **Make Methods Protected**: Change visibility from `private` to `protected` so other tool providers can access them (or `public` for cross-package delegation)
3. **Delegate from Active Tools**: Have active tools call the extracted handler methods instead of duplicating logic
4. **Document Dependencies**: Add comments noting that methods should be kept in sync with upstream disabled tool handlers

### Completed Refactorings

#### 1. ImportExportToolProvider → SymbolToolProvider

**Disabled Tools:**
- `registerListImportsTool()` → Merged into `manage-symbols` with `mode='imports'`
- `registerListExportsTool()` → Merged into `manage-symbols` with `mode='exports'`
- `registerFindImportReferencesTool()` → Disabled (functionality may be available elsewhere)
- `registerResolveThunkTool()` → Disabled (functionality may be available elsewhere)

**Extracted Methods (public or protected):**
- `collectImports(Program, String)` (public) - Used by SymbolToolProvider.handleImportsMode()
- `collectExports(Program)` (public) - Used by SymbolToolProvider.handleExportsMode()
- `findImportsByName(Program, String, String)` - Used by handleFindImportReferences()
- `buildThunkMap(Program)` - Used by handleFindImportReferences()
- `collectImportReferences(...)` - Used by handleFindImportReferences()
- `buildThunkChain(Function)` (public) - Used by CrossReferencesToolProvider and handleResolveThunk()
- `buildImportInfo(Function)` - Used by handleFindImportReferences()
- `groupImportsByLibrary(List)` (public) - Used by SymbolToolProvider.handleImportsMode()
- `paginate(List, int, int)` (public) - Used by SymbolToolProvider
- `clamp(int, int, int)` - Used by disabled tool handlers

**Extracted Handler Methods (protected):**
- `handleFindImportReferences(CallToolRequest)` - Extracted from registerFindImportReferencesTool()
- `handleResolveThunk(CallToolRequest)` - Extracted from registerResolveThunkTool()

**Active Tool Integration:**
- `SymbolToolProvider` creates `ImportExportToolProvider` helper instance
- `handleImportsMode()` delegates to `importExportHelper.collectImports()`
- `handleExportsMode()` delegates to `importExportHelper.collectExports()`
- `handleImportsMode()` delegates to `importExportHelper.paginate()` and `importExportHelper.groupImportsByLibrary()`

#### 2. ImportExportToolProvider → CrossReferencesToolProvider

**Extracted Method:**
- `buildThunkChain(Function)` - Used by CrossReferencesToolProvider.handleThunkMode()

**Active Tool Integration:**
- `CrossReferencesToolProvider` creates `ImportExportToolProvider` helper instance
- `handleThunkMode()` delegates to `importExportHelper.buildThunkChain()`
- Removed duplicate `buildThunkChain()` method from CrossReferencesToolProvider

#### 3. ProjectToolProvider

**Disabled Tools:**
- `registerOpenProjectTool()` → Merged into `open` (detects .gpr files)
- `registerOpenProgramTool()` → Merged into `open` (detects program files)
- `registerOpenAllProgramsInCodeBrowserTool()` → Merged into `open` (with extensions parameter)

**Extracted Methods (protected):**
- `handleOpenProject(Map, String, ToolLogCollector)` - Used by active `open` tool and disabled `registerOpenProjectTool()`
- `handleOpenProgram(Map, String)` - Used by active `open` tool and disabled `registerOpenProgramTool()`
- `handleOpenAllProgramsByExtension(String, String)` - Used by active `open` tool and disabled `registerOpenAllProgramsInCodeBrowserTool()`

**Active Tool Integration:**
- Active `open` tool calls:
  - `handleOpenProject()` for .gpr files
  - `handleOpenProgram()` for program files
  - `handleOpenAllProgramsByExtension()` when extensions parameter is provided
- Disabled tools call the same handler methods

#### 4. DataToolProvider

**Disabled Tools:**
- `registerGetDataTool()` → Disabled (functionality may be available elsewhere)
- `registerApplyDataTypeTool()` → Disabled (functionality may be available elsewhere)
- `registerCreateLabelTool()` → Disabled (functionality may be available elsewhere)

**Extracted Methods (protected):**
- `getDataAtAddressResult(Program, Address)` - Extracted from registerGetDataTool()
- `applyDataTypeAtAddress(Program, Address, String, String)` - Extracted from registerApplyDataTypeTool()
- `createLabelAtAddress(Program, Address, String, boolean)` - Extracted from registerCreateLabelTool()

**Status:**
- Methods are extracted and protected for future use
- Not currently used by active tools, but available if needed

### Verification Checklist

- [x] All disabled tool handlers call extracted handler methods
- [x] All extracted handler methods are protected (or public for cross-package use)
- [x] Active tools delegate to disabled tool provider methods where applicable
- [x] Duplicate logic removed from active tools
- [x] Documentation added noting upstream sync requirements
- [x] Helper instances created where needed (SymbolToolProvider, CrossReferencesToolProvider)

### Upstream Sync Process

When upstream updates disabled tool handlers:

1. **Identify the change**: Check what was updated in the disabled tool handler
2. **Update extracted method**: Modify the corresponding protected handler/helper method
3. **Test active tools**: Verify that active tools using the method still work correctly
4. **Update documentation**: Note the change in this section if significant

### Files Modified

- `src/main/java/agentdecompile/tools/imports/ImportExportToolProvider.java`
  - Made helper methods protected (or public for cross-package use)
  - Extracted handler methods: `handleFindImportReferences()`, `handleResolveThunk()`
  - Updated disabled tool handlers to call extracted methods

- `src/main/java/agentdecompile/tools/symbols/SymbolToolProvider.java`
  - Added `ImportExportToolProvider` helper instance
  - Removed duplicate `collectImports()` and `collectExports()` methods
  - Removed duplicate `paginate()` and `groupImportsByLibrary()` methods
  - Updated to delegate to `importExportHelper` methods

- `src/main/java/agentdecompile/tools/xrefs/CrossReferencesToolProvider.java`
  - Added `ImportExportToolProvider` helper instance
  - Removed duplicate `buildThunkChain()` method
  - Updated to delegate to `importExportHelper.buildThunkChain()`

- `src/main/java/agentdecompile/tools/project/ProjectToolProvider.java`
  - Made `handleOpenProject()` and `handleOpenProgram()` protected
  - Made `handleOpenAllProgramsByExtension()` protected
  - Added documentation noting upstream sync requirements

- `src/main/java/agentdecompile/tools/data/DataToolProvider.java`
  - Uncommented and made helper methods protected
  - Added documentation for future use

### Benefits

1. **Upstream Updates**: When upstream improves disabled tool handlers, we can update the extracted methods and all active tools benefit automatically
2. **No Duplication**: Active tools don't duplicate logic - they delegate to the source
3. **Maintainability**: Single source of truth for shared logic
4. **Future-Proof**: Helper methods are available if needed later

### Notes

- Helper instances are created in constructors to access protected methods
- All extracted methods are documented with notes about upstream compatibility
- Linter warnings about unused methods are expected (disabled tool registration methods)

---

## Ghidra Scripts Analysis and Coverage

This document analyzes all Ghidra scripts to ensure AgentDecompile tools provide complete coverage.

### Script Categories

#### 1. Program Import/Export
- `ImportProgramScript.java` - Import program ✅ (covered by `open` tool)
- `ImportAllProgramsFromADirectoryScript.java` - Batch import ✅ (covered by `manage-files` operation='import')
- `ExportProgramScript.java` - Export program ✅ (covered by `manage-files` operation='export' export_type='program')
- `ExportFunctionInfoScript.java` - Export function info ✅ (covered by `manage-files` operation='export' export_type='function_info')
- `ExportImagesScript.java` - Export images ❌ **MISSING** (low priority - specialized)
- `CreateExportFileForDLL.java` - Create export file ❌ **MISSING** (low priority - specialized)

#### 2. Function Management
- `CreateFunctionAfterTerminals.java` - Create functions ✅ (covered by `manage-function` action='create')
- `CreateFunctionsFromSelection.java` - Create from selection ❌ **MISSING** (could add to manage-function)
- `MakeFunctionsScript.java` - Make functions ✅ (covered by `manage-function` action='create')
- `MakeFunctionsInlineVoidScript.java` - Make inline void ❌ **MISSING**
- `ClearOrphanFunctions.java` - Clear orphan functions ❌ **MISSING**
- `FindUndefinedFunctionsScript.java` - Find undefined ✅ (covered by `list-functions` mode='undefined')
- `FindUndefinedFunctionsFollowUpScript.java` - Follow-up undefined ❌ **MISSING**
- `FindSharedReturnFunctionsScript.java` - Find shared returns ❌ **MISSING**
- `FindInstructionsNotInsideFunctionScript.java` - Find orphan instructions ❌ **MISSING**

#### 3. Symbol/Label Management
- `AutoRenameLabelsScript.java` - Auto rename labels ❌ **MISSING** (no dedicated auto_rename mode; use `manage-symbols` mode='rename_data' for manual renames)
- `AutoRenameSimpleLabels.java` - Auto rename simple ❌ **MISSING** (same as above)
- `BatchRename.java` - Batch rename ✅ (covered by `manage-symbols` mode='rename_data' with address/newName arrays)
- `DemangleAllScript.java` - Demangle all symbols ✅ (covered by `manage-symbols` mode='demangle' demangleAll=true)
- `DemangleSymbolScript.java` - Demangle single symbol ✅ (covered by `manage-symbols` mode='demangle')
- `ConvertDotToDashInAutoAnalysisLabels.java` - Convert labels ❌ **MISSING** (low priority - formatting)
- `RemoveSymbolQuotesScript.java` - Remove quotes ❌ **MISSING** (low priority - formatting)
- `RenameStructMembers.java` - Rename struct members ❌ **MISSING** (could add to manage-structures)

#### 4. Comment Management
- `AddCommentToProgramScript.java` - Add comment ✅ (covered by `manage-comments` action='set')
- `FindAndReplaceCommentScript.java` - Find/replace comments ❌ **MISSING** (could add to manage-comments)
- `ReplaceInComments.java` - Replace in comments ❌ **MISSING**
- `DeleteDeadDefaultPlatesScript.java` - Delete dead plates ❌ **MISSING**
- `DeleteEmptyPlateCommentsScript.java` - Delete empty plates ❌ **MISSING**
- `DeleteExitCommentsScript.java` - Delete exit comments ❌ **MISSING**
- `DeleteFunctionDefaultPlatesScript.java` - Delete function plates ❌ **MISSING**

#### 5. Data Type Management
- `ChooseDataTypeScript.java` - Choose data type ✅ (covered by `manage-data-types` action='apply')
- `FindDataTypeScript.java` - Find data type ✅ (covered by `manage-data-types` action='by_string')
- `FindDataTypeConflictCauseScript.java` - Find conflicts ❌ **MISSING**
- `FixupCompositeDataTypesScript.java` - Fixup composites ❌ **MISSING**
- `FixupGolangFuncParamStorageScript.java` - Fixup Golang ❌ **MISSING**
- `FixupNoReturnFunctionsScript.java` - Fixup no-return ❌ **MISSING**
- `FixupNoReturnFunctionsNoRepairScript.java` - Fixup no-return (no repair) ❌ **MISSING**
- `RenameVariable.java` - Rename variable ✅ (covered by `manage-function` action='rename_variable')
- `FixOldSTVariableStorageScript.java` - Fix old storage ❌ **MISSING**

#### 6. Structure Management
- `PrintStructureScript.java` - Print structure ✅ (covered by `manage-structures` action='info')
- `RenameStructMembers.java` - Rename members ❌ **MISSING** (could add to manage-structures)

#### 7. Memory/Data Operations
- `EditBytesScript.java` - Edit bytes ❌ **MISSING** (could add to inspect-memory)
- `ReadMemoryScript.java` - Read memory ✅ (covered by `inspect-memory` mode='read')
- `LabelDataScript.java` - Label data ✅ (covered by `manage-symbols` mode='create_label')
- `CreateStringScript.java` - Create string ❌ **MISSING** (could add to manage-strings)
- `IterateDataScript.java` - Iterate data ✅ (covered by `inspect-memory` mode='data_items')
- `CondenseRepeatingBytes.java` - Condense bytes ❌ **MISSING**
- `CondenseAllRepeatingBytes.java` - Condense all ❌ **MISSING**
- `CondenseFillerBytes.java` - Condense filler ❌ **MISSING**
- `CondenseRepeatingBytesAtEndOfMemory.java` - Condense end ❌ **MISSING**
- `XorMemoryScript.java` - XOR memory ❌ **MISSING**

#### 8. String Operations
- `CountAndSaveStrings.java` - Count strings ✅ (covered by `manage-strings` mode='count')
- `SearchMemoryForStringsRegExScript.java` - Search strings ✅ (covered by `manage-strings` mode='regex')
- `NameStringPointersPlus.java` - Name string pointers ❌ **MISSING**
- `LabelIndirectStringReferencesScript.java` - Label string refs ❌ **MISSING**
- `BinaryToAsciiScript.java` - Binary to ASCII ❌ **MISSING**
- `AsciiToBinaryScript.java` - ASCII to binary ❌ **MISSING**

#### 9. Reference Management
- `CreateOperandReferencesInSelectionScript.java` - Create refs ❌ **MISSING** (could add to get-references)
- `CreateRelocationBasedOperandReferences.java` - Create relocation refs ❌ **MISSING**
- `LabelDirectFunctionReferencesScript.java` - Label direct refs ❌ **MISSING**
- `LabelIndirectReferencesScript.java` - Label indirect refs ❌ **MISSING**
- `PropagateConstantReferences.java` - Propagate constants ❌ **MISSING**
- `PropagateX86ConstantReferences.java` - Propagate x86 constants ❌ **MISSING**
- `PropagateExternalParametersScript.java` - Propagate externals ❌ **MISSING**
- `ResolveExternalReferences.java` - Resolve externals ❌ **MISSING**
- `RemoveDeletedOverlayReferences.java` - Remove overlay refs ❌ **MISSING**

#### 10. Analysis Operations
- `GetAndSetAnalysisOptionsScript.java` - Analysis options ❌ **MISSING**
- `CompareAnalysisScript.java` - Compare analysis ❌ **MISSING**
- `TurnOffStackAnalysis.java` - Turn off stack ❌ **MISSING**
- `ReportDisassemblyErrors.java` - Report errors ❌ **MISSING**
- `ReportPercentDisassembled.java` - Report percent ❌ **MISSING**

#### 11. Search Operations
- `FindTextScript.java` - Find text ❌ **MISSING** (could add to manage-strings or new search tool)
- `InstructionSearchScript.java` - Search instructions ❌ **MISSING**
- `SearchMnemonicsOpsConstScript.java` - Search mnemonics ❌ **MISSING**
- `SearchMnemonicsOpsNoConstScript.java` - Search mnemonics (no const) ❌ **MISSING**
- `SearchMnemonicsNoOpsNoConstScript.java` - Search mnemonics (no ops) ❌ **MISSING**
- `SearchBaseExtended.java` - Search base extended ❌ **MISSING**
- `SearchForImageBaseOffsets.java` - Search image base ❌ **MISSING**
- `SearchForImageBaseOffsetsScript.java` - Search image base (alt) ❌ **MISSING**
- `FindRunsOfPointersScript.java` - Find pointer runs ❌ **MISSING**
- `FindOverlappingCodeUnitsScript.java` - Find overlapping ❌ **MISSING**
- `FindAudioInProgramScript.java` - Find audio ❌ **MISSING**
- `FindImagesScript.java` - Find images ❌ **MISSING**

#### 12. Disassembly Operations
- `RepairDisassemblyScript.java` - Repair disassembly ❌ **MISSING**
- `FixOffcutInstructionScript.java` - Fix offcut ❌ **MISSING**
- `DoARMDisassemble.java` - ARM disassemble ❌ **MISSING**
- `DoThumbDisassemble.java` - Thumb disassemble ❌ **MISSING**
- `AssembleScript.java` - Assemble ❌ **MISSING**
- `AssembleBlockScript.java` - Assemble block ❌ **MISSING**
- `AssembleCheckDevScript.java` - Assemble check ❌ **MISSING**

#### 13. Binary Format Specific
- `PE_script.java` - PE operations ❌ **MISSING**
- `PEF_script.java` - PEF operations ❌ **MISSING**
- `COFF_Script.java` - COFF operations ❌ **MISSING**
- `COFF_ArchiveScript.java` - COFF archive ❌ **MISSING**
- `MachO_Script.java` - Mach-O operations ❌ **MISSING**
- `AppleSingleDoubleScript.java` - Apple formats ❌ **MISSING**
- `SplitUniversalBinariesScript.java` - Split universal ❌ **MISSING**
- `SplitMultiplePefContainersScript.java` - Split PEF ❌ **MISSING**
- `PortableExecutableRichPrintScript.java` - PE rich header ❌ **MISSING**
- `FindFunctionsUsingTOCinPEFScript.java` - Find TOC functions ❌ **MISSING**

#### 14. ELF Specific
- `ExtractELFDebugFilesScript.java` - Extract debug files ❌ **MISSING**

#### 15. DWARF Debug Info
- `DWARFLineInfoCommentScript.java` - DWARF line comments ❌ **MISSING**
- `DWARFLineInfoSourceMapScript.java` - DWARF source map ❌ **MISSING**
- `DWARFMacroScript.java` - DWARF macros ❌ **MISSING**
- `DWARFSetExternalDebugFilesLocationPrescript.java` - DWARF debug location ❌ **MISSING**

#### 16. Source Mapping
- `AddSourceFileScript.java` - Add source file ❌ **MISSING**
- `AddSourceMapEntryScript.java` - Add source map ❌ **MISSING**
- `RemoveSourceMapEntryScript.java` - Remove source map ❌ **MISSING**
- `ShowSourceMapEntryStartsScript.java` - Show source map ❌ **MISSING**
- `SelectAddressesMappedToSourceFileScript.java` - Select mapped addresses ❌ **MISSING**
- `OpenSourceFileAtLineInEclipseScript.java` - Open in Eclipse ❌ **MISSING** (external tool)
- `OpenSourceFileAtLineInVSCodeScript.java` - Open in VSCode ❌ **MISSING** (external tool)

#### 17. Version Control
- `VersionControl_AddAll.java` - VC add all ✅ (covered by `manage-files` operation='import' with versionControl, or `open` when importing)
- `VersionControl_ResetAll.java` - VC reset all ❌ **MISSING**
- `VersionControl_UndoAllCheckout.java` - VC undo checkout ❌ **MISSING**
- `VersionControl_VersionSummary.java` - VC summary ❌ **MISSING**
- `RemoveUserCheckoutsScript.java` - Remove checkouts ❌ **MISSING**

#### 18. Project Management
- `RenameProgramsInProjectScript.java` - Rename programs ❌ **MISSING**
- `CreateEmptyProgramScript.java` - Create empty program ❌ **MISSING**
- `GenerateLotsOfProgramsScript.java` - Generate programs ❌ **MISSING** (test utility)

#### 19. Processor/Language Operations
- `ChangeProcessorScript.java` - Change processor ✅ (covered by `change-processor` tool)
- `ReloadSleighLanguage.java` - Reload Sleigh ❌ **MISSING**
- `Fix_ARM_Call_JumpsScript.java` - Fix ARM calls ❌ **MISSING**
- `Override_ARM_Call_JumpsScript.java` - Override ARM calls ❌ **MISSING**
- `Mips_Fix_T9_PositionIndependentCode.java` - Fix MIPS T9 ❌ **MISSING**

#### 20. Equate Operations
- `SetEquateScript.java` - Set equate ❌ **MISSING**
- `ShowEquatesInSelectionScript.java` - Show equates ❌ **MISSING**

#### 21. Switch Table Operations
- `AddReferencesInSwitchTable.java` - Add switch refs ❌ **MISSING**
- `AddSingleReferenceInSwitchTable.java` - Add single switch ref ❌ **MISSING**
- `FindUnrecoveredSwitchesScript.java` - Find unrecovered switches ❌ **MISSING**

#### 22. Stack Operations
- `MakeStackRefs.java` - Make stack refs ❌ **MISSING**

#### 23. Pcode Operations
- `MarkCallOtherPcode.java` - Mark call other ❌ **MISSING**
- `MarkUnimplementedPcode.java` - Mark unimplemented ❌ **MISSING**

#### 24. Function Analysis
- `ComputeCyclomaticComplexity.java` - Compute complexity ❌ **MISSING**
- `PrintFunctionCallTreesScript.java` - Print call trees ✅ (covered by `get-call-graph` mode='tree')
- `IterateFunctionsScript.java` - Iterate functions ✅ (covered by `list-functions`)
- `IterateFunctionsByAddressScript.java` - Iterate by address ✅ (covered by `list-functions`)
- `SelectFunctionsScript.java` - Select functions ❌ **MISSING** (UI operation)
- `IterateInstructionsScript.java` - Iterate instructions ❌ **MISSING** (could add to get-function view='disassemble')

#### 25. Data Flow / References
- `MultiInstructionMemReference.java` - Multi instruction refs ❌ **MISSING**

#### 26. External Library Operations
- `AssociateExternalPELibrariesScript.java` - Associate PE libs ❌ **MISSING**

#### 27. System Map Import
- `LinuxSystemMapImportScript.java` - Import system map ❌ **MISSING**

#### 28. PDB Operations
- `CreatePdbXmlFilesScript.java` - Create PDB XML ❌ **MISSING**

#### 29. GDT Operations
- `CreateDefaultGDTArchivesScript.java` - Create GDT archives ❌ **MISSING**
- `CreateExampleGDTArchiveScript.java` - Create example GDT ❌ **MISSING**
- `CreateUEFIGDTArchivesScript.java` - Create UEFI GDT ❌ **MISSING**
- `CompareGDTs.java` - Compare GDTs ❌ **MISSING**
- `SynchronizeGDTCategoryPaths.java` - Sync GDT paths ❌ **MISSING**

#### 30. Repository Operations
- `RepositoryFileUpgradeScript.java` - Upgrade repository ❌ **MISSING**

#### 31. Memory Block Operations
- `LocateMemoryAddressesForFileOffset.java` - Locate addresses ❌ **MISSING**
- `LocateMemoryAddressesForFileOffset.py` - Locate addresses (Python) ❌ **MISSING**

#### 32. Architecture-Specific Fixes
- `FixArrayStructReferencesScript.java` - Fix array/struct refs ❌ **MISSING**
- `FixElfExternalOffsetDataRelocationScript.java` - Fix ELF relocations ❌ **MISSING**
- `FixupCompositeDataTypesScript.java` - Fixup composites ❌ **MISSING**

#### 33. Utility Scripts
- `HelloWorldScript.java` - Hello world ❌ **MISSING** (example script)
- `HelloWorldPopupScript.java` - Hello popup ❌ **MISSING** (example script)
- `CallAnotherScript.java` - Call script ❌ **MISSING** (script execution)
- `CallAnotherScriptForAllPrograms.java` - Call for all ❌ **MISSING** (script execution)
- `CallotherCensusScript.java` - Call other census ❌ **MISSING**
- `FormatExampleScript.java` - Format example ❌ **MISSING** (example)
- `ProgressExampleScript.java` - Progress example ❌ **MISSING** (example)
- `ExampleColorScript.java` - Color example ❌ **MISSING** (UI example)
- `ExampleGraphServiceScript.java` - Graph example ❌ **MISSING** (UI example)
- `InnerClassScript.java` - Inner class example ❌ **MISSING** (example)
- `LanguagesAPIDemoScript.java` - Languages API demo ❌ **MISSING** (example)
- `BuildGhidraJarScript.java` - Build jar ❌ **MISSING** (build utility)
- `CreateHelpTemplateScript.java` - Create help template ❌ **MISSING** (utility)

#### 34. YARA Integration
- `RunYARAFromGhidra.py` - Run YARA ❌ **MISSING**
- `YaraGhidraGUIScript.java` - YARA GUI ❌ **MISSING**

#### 35. Embedded Finder
- `EmbeddedFinderScript.java` - Find embedded files ❌ **MISSING**

#### 36. Miscellaneous
- `FFsBeGoneScript.java` - Remove FFs ❌ **MISSING**
- `DeleteSpacePropertyScript.java` - Delete space property ❌ **MISSING**
- `SetHeadlessContinuationOptionScript.java` - Set headless option ❌ **MISSING**
- `ZapBCTRScript.java` - Zap BCTR ❌ **MISSING**
- `RegisterTouchesPerFunction.java` - Register touches ❌ **MISSING**
- `GenerateMaskedBitStringScript.java` - Generate bit string ❌ **MISSING**
- `GraphClassesScript.java` - Graph classes ❌ **MISSING**
- `SubsToFuncsScript.java` - Subs to funcs ❌ **MISSING**
- `BatchSegregate64bit.java` - Segregate 64-bit ❌ **MISSING**
- `FindX86RelativeCallsScript.java` - Find x86 relative calls ❌ **MISSING**
- `ResolveX86orX64LinuxSyscallsScript.java` - Resolve syscalls ❌ **MISSING**
- `RepairFuncDefinitionUsageScript.java` - Repair func def ❌ **MISSING**
- `ConvertDotDotDotScript.java` - Convert dots ❌ **MISSING**
- `PasteCopiedListingBytesScript.java` - Paste bytes ❌ **MISSING**
- `SearchGuiMulti.java` - Search GUI multi ❌ **MISSING** (UI)
- `SearchGuiSingle.java` - Search GUI single ❌ **MISSING** (UI)
- `AskScript.java` - Ask script ❌ **MISSING** (UI)
- `AskValuesExampleScript.java` - Ask values ❌ **MISSING** (UI example)
- `EmbeddedFinderScript.java` - Embedded finder ❌ **MISSING**
- `MarkupWallaceSrcScript.java` - Wallace markup ❌ **MISSING**

#### 37. Emulation
- `EmuX86DeobfuscateExampleScript.java` - X86 emulation ❌ **MISSING**
- `EmuX86GccDeobfuscateHookExampleScript.java` - X86 GCC emulation ❌ **MISSING**

#### 38. Python Scripts
- `mark_in_out.py` - Mark in/out ❌ **MISSING**
- `RecursiveStringFinder.py` - Recursive string finder ❌ **MISSING**

### Priority Gaps to Address

#### High Priority (Common Operations)
1. **Export functionality** - Export programs, function info, images
2. **Batch symbol rename** - Batch rename labels/symbols
3. **Find/replace in comments** - Search and replace comment text
4. **Instruction search** - Search for specific instructions/patterns
5. **Memory editing** - Edit bytes in memory
6. **Reference creation** - Create operand references
7. **Equate management** - Set/show equates
8. **Switch table operations** - Add references, find unrecovered switches

#### Medium Priority (Useful Features)
1. **Demangle symbols** - Demangle C++/Rust symbols
2. **Auto-rename labels** - Automatic label renaming
3. **Data type conflict detection** - Find and fix conflicts
4. **Source mapping** - Add/remove source file mappings
5. **Analysis options** - Get/set analysis options
6. **Disassembly repair** - Repair disassembly errors

#### Low Priority (Specialized/Niche)
1. **Format-specific operations** - PE/ELF/Mach-O specific features
2. **Architecture-specific fixes** - ARM/MIPS specific operations
3. **DWARF operations** - Debug info management
4. **Version control operations** - Advanced VC features
5. **Emulation** - Code emulation features

### Implementation Strategy

1. **Add to existing tools** where functionality fits naturally
2. **Create new unified tools** for major feature categories (e.g., `manage-references`, `search-code`)
3. **Keep intuitive naming** - tools should be guessable by AI agents
4. **Use mode/action enums** - consistent with existing tool patterns

---

## Ghidra Shared Project API

This section summarizes how to connect to and open a **shared project** (Ghidra Server repository) via the Ghidra API, using the same docs referenced across `src/main/java/agentdecompile/**/*.java`.

### Overview

- **Local projects**: Opened with `GhidraProject.openProject(projectDir, projectName, enableUpgrade)` — path and name only (what `ProjectUtil` does today).
- **Shared projects**: Live on a Ghidra Server. You must **connect to the server with credentials**, then **resolve the project via a Ghidra URL or repository handle**, and open it through the project manager. The batch-oriented `GhidraProject` class does **not** expose an overload that takes a server URL; shared-project flow uses the client/repository APIs and (for URL-based open) the Ghidra URL protocol.

### Environment variable configuration (AgentDecompile)

For the list of AgentDecompile environment variables used for shared projects, connection, and other end-user options, see [README.md](README.md#environment-variables). Authentication is applied at headless startup and when using the **open** tool; shared projects use a local `.gpr` that references the server, with credentials from env or tool parameters.

### 1. Connect to the Ghidra Repository Server

**API:** `ghidra.framework.client.ClientUtil`  
**Docs:** [ClientUtil](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html)

```java
import ghidra.framework.client.ClientUtil;

// Connect; may prompt for password (Swing) if no headless authenticator is set
RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port);
// port: 0 = use default Ghidra Server port

// Force reconnect if previously disconnected
RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port, true);
```

Alternatively, via **ProjectManager** (e.g. `DefaultProjectManager` from `GhidraProject.getProjectManager()`):

```java
RepositoryServerAdapter server = projectManager.getRepositoryServerAdapter(host, portNumber, forceConnect);
```

- Returns a **handle to the remote server** (list of shared repositories).
- If the server requires authentication and no headless authenticator is installed, the default behavior is to show a **Swing login dialog**. For headless/CLI you must set credentials first (see below).

### 2. Setting Credentials (Login) for Headless / API Use

For environments without a GUI (e.g. headless analyzer, scripts, or AgentDecompile CLI), you must install an authenticator or set credentials **before** connecting so that the server connection can succeed without a dialog.

#### Option A: Headless client authenticator (PKI/SSH or password prompt)

**API:** `ghidra.framework.client.HeadlessClientAuthenticator`  
**Docs:** [HeadlessClientAuthenticator](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/HeadlessClientAuthenticator.html)

```java
import ghidra.framework.client.HeadlessClientAuthenticator;

// Install before any server connection (e.g. at startup)
HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
    username,        // optional; null = use ClientUtil.getUserName()
    keystorePath,    // PKI/SSH keystore path, or resource path for SSH key
    allowPasswordPrompt  // if true, may prompt for passwords via console (echoed!)
);
```

- Used when "http/https connections require authentication" and no user info is provided.
- Supports **PKI/SSH** (keystore) and **password callbacks** (console prompt; Java console may echo input).
- Call **once** before calling `ClientUtil.getRepositoryServer(...)` or opening any shared project.

#### Option B: GhidraScript – fixed username/password

**API:** `ghidra.app.script.GhidraScript`  
**Docs:** [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)

```java
// In a Ghidra script; primarily for headless
setServerCredentials(username, password);
// Returns true if active project is private or shared project is connected to its server repo
```

- Establishes **fixed** login credentials for the Ghidra Server.
- Username can be null to use default.

#### Option C: Headless analyzer options (PKI/SSH)

**API:** `ghidra.app.util.headless.HeadlessOptions`  
**Docs:** [HeadlessOptions](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html)

```java
headlessOptions.setClientCredentials(userID, keystorePath, allowPasswordPrompt);
// Throws IOException if keystore cannot be opened
```

- Used by the headless analyzer for **Ghidra Server client credentials** (PKI/SSH, optional password prompt).

### 3. Get a Repository (Shared Project Container)

A **repository** on the server is the container for one or more projects/content. You need a `RepositoryAdapter` for that repository.

**From batch-style helper:**

**API:** `ghidra.base.project.GhidraProject`  
**Docs:** [GhidraProject](https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html)

```java
import ghidra.base.project.GhidraProject;

RepositoryAdapter repo = GhidraProject.getServerRepository(
    host,
    port,           // 0 = default
    repositoryName,
    createIfNeeded  // true to create repository if it doesn't exist
);
```

**From server adapter:**

**API:** `ghidra.framework.client.RepositoryServerAdapter`  
**Docs:** [RepositoryServerAdapter](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/RepositoryServerAdapter.html)

```java
RepositoryAdapter repo = server.getRepository(repositoryName);
// Returns null if not found; adapter may be disconnected until connect() or use
```

- Use the same **host/port** (and credentials) as in step 1 when using `GhidraProject.getServerRepository`.

### 4. Ghidra URL for Shared Content (Server Project Path)

**API:** `ghidra.framework.protocol.ghidra.GhidraURL`  
**Docs:** (Ghidra API – GhidraURL)

```java
URL url = GhidraURL.makeURL(host, port, repositoryName, repositoryPath);
// repositoryPath: absolute path within repository; folders should end with '/'
```

- Use this URL when the framework expects a **ghidra://** URL for a server project (e.g. open by URL, or when producing links to shared project content).
- `ProjectLocator.isTransient()` returns true for locators that "correspond to a transient project (e.g., corresponds to remote Ghidra URL)".

### 5. Opening a Project (Local vs Shared)

**Local project (current AgentDecompile pattern):**

- `GhidraProject.openProject(projectLocationPath, projectName, enableUpgrade)`  
- Or `ProjectManager.openProject(projectLocator, doRestore, resetOwner)` with a **local** `ProjectLocator(path, name)`.

**Shared project:**

- The **GUI** typically opens shared projects via a **ghidra://** URL. The protocol connector (`GhidraProtocolConnector` / `DefaultLocalGhidraProtocolConnector` and server variants) handles **connect(readOnlyAccess)** and resolves to the underlying project/repository.
- **Programmatic** opening with the **ProjectManager** still uses `openProject(ProjectLocator, doRestore, resetOwner)`. For shared projects, the `ProjectLocator` is expected to carry the **URL** (protected constructor `ProjectLocator(path, name, URL)`); the actual locator is often produced by the **Ghidra URL connector** after a successful `connect()`, rather than by constructing a `ProjectLocator` directly in application code.
- **Creating** a new **shared** project:  
  `ProjectManager.createProject(projectLocator, repAdapter, remember)` with a non-null **RepositoryAdapter** (`repAdapter`).

So in practice: **set credentials → connect to server → get repository (and/or build Ghidra URL) → use framework's URL/project open path** so that the correct `ProjectLocator` (with URL for shared) is produced and passed to `openProject`.

### 6. ProjectLocator and "Transient" (Remote) Projects

**API:** `ghidra.framework.model.ProjectLocator`  
**Docs:** [ProjectLocator](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html)

- **Local:** `new ProjectLocator(path, name)` — path = directory, name = project name.
- **Shared:** There is a **protected** constructor `ProjectLocator(String path, String name, URL url)`. For remote projects, `isTransient()` returns true and the URL is used (e.g. for "transient project" corresponding to a remote Ghidra URL). Application code usually does not construct this directly; it is produced by the Ghidra URL/protocol handling.

### 7. Error Handling (aligned with ProjectUtil)

Your existing `ProjectUtil` already maps **authentication-style** failures when opening a project to a clear message:

- `NotOwnerException`, `NotFoundException`, `IOException` with message containing "authentication", "password", "login", "unauthorized", "Access denied", "Invalid credentials" → wrap in a single "Authentication failed for shared project" message and suggest verifying username/password.

So when you add shared-project support, reusing that pattern for any `openProject` or `connect()` path will keep behavior consistent.

### 8. Summary Checklist for "Login and Use Shared Project" via API

1. **Set credentials** (before any connection):
   - **Headless:** `HeadlessClientAuthenticator.installHeadlessClientAuthenticator(username, keystorePath, allowPasswordPrompt)` and/or script `setServerCredentials(username, password)` if applicable.
   - **Headless analyzer:** `HeadlessOptions.setClientCredentials(...)`.
2. **Connect to server:**  
   `ClientUtil.getRepositoryServer(host, port)` or `ProjectManager.getRepositoryServerAdapter(host, port, forceConnect)`.
3. **Get repository:**  
   `GhidraProject.getServerRepository(host, port, repositoryName, createIfNeeded)` or `serverAdapter.getRepository(repositoryName)`.
4. **Open project:**  
   Use the framework's **Ghidra URL**–based open path (so that the correct transient `ProjectLocator` is produced) and then `ProjectManager.openProject(projectLocator, doRestore, resetOwner)`, or follow the same path the GUI uses for "Open shared project" (URL → connector → connect → open).
5. **Optional:** Build server URLs with `GhidraURL.makeURL(host, port, repositoryName, repositoryPath)` when you need to pass a ghidra:// URL.

### 9. References (same as in codebase)

| API | Doc link |
|-----|----------|
| GhidraProject | https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html |
| ProjectManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectManager.html |
| DefaultProjectManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/project/DefaultProjectManager.html |
| ProjectLocator | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html |
| ClientUtil | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html |
| HeadlessClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/HeadlessClientAuthenticator.html |
| RepositoryServerAdapter | (Ghidra API – RepositoryServerAdapter) |
| RepositoryAdapter | (Ghidra API – RepositoryAdapter) |
| Ghidra API overview | https://ghidra.re/ghidra_docs/api/ |

---

## Shared Project Authentication

For tool parameters, environment variables, examples, troubleshooting, and security, see [README.md](README.md#shared-project-authentication).

---

## Ghidra Project Authentication Implementation

This section describes how shared Ghidra project authentication is implemented in AgentDecompile. For end-user usage, see [README.md](README.md#shared-project-authentication) and [Ghidra Shared Project API](#ghidra-shared-project-api) below.

### Understanding the Problem

When opening a **shared Ghidra project** (connected to a Ghidra Server), authentication is required:

1. **Local projects** (`.gpr` files on disk, no server) – Work without authentication.
2. **Shared projects** (`.gpr` files connected to a Ghidra Server) – Require credentials; without them, opening fails or prompts for login in GUI mode.

AgentDecompile’s `open` tool and environment-based setup handle this so that shared projects can be opened in headless/CLI without prompts.

### How Ghidra Authentication Works

- **ClientAuthenticator**: Ghidra uses a global authenticator for server connections.
- **PasswordClientAuthenticator**: Username/password implementation.
- **ClientUtil.setClientAuthenticator()**: Sets the authenticator globally; must be called **before** opening projects.
- **Project types**: Local (on disk, no server) vs shared (connected to Ghidra Server, requires authentication).

Flow in AgentDecompile:

1. User calls `open` with a `.gpr` path (and optionally `serverUsername`/`serverPassword`) or has env vars set.
2. Credentials are resolved from request parameters first, then environment variables.
3. If credentials are present, `ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(...))` is called before opening.
4. `GhidraProject.openProject()` uses the configured authenticator.
5. After open, we check `project.getRepositoryAdapter()` for shared/connected status and return clear errors if auth was required but missing or failed.

### Where It Is Implemented

- **ProjectToolProvider** (`tools/project/ProjectToolProvider.java`):
  - `open` tool schema includes optional `serverUsername`, `serverPassword`, `serverHost`, `serverPort`.
  - `getServerCredentials(request)` returns credentials from request then env (`AGENT_DECOMPILE_SERVER_USERNAME`, `AGENT_DECOMPILE_SERVER_PASSWORD`).
  - `handleOpenProject()` applies env-based auth via `SharedProjectEnvConfig.applySharedProjectAuthFromEnv()` when env auth is set, then applies request/env credentials with `PasswordClientAuthenticator` and `ClientUtil.setClientAuthenticator()` before opening. Shared/connected status and auth errors are handled and mapped to user-facing messages (see also `ProjectUtil` for auth-style failure mapping).
- **SharedProjectEnvConfig** (`util/SharedProjectEnvConfig.java`):
  - `hasAuthFromEnv()` / `applySharedProjectAuthFromEnv()`: If `AGENT_DECOMPILE_SERVER_USERNAME` and `AGENT_DECOMPILE_SERVER_PASSWORD` are set, installs `PasswordClientAuthenticator`; if `AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH` is set, installs `HeadlessClientAuthenticator` for PKI/SSH.

See the [Ghidra Shared Project API](#ghidra-shared-project-api) section for environment variable names and headless credential setup.

### Security Considerations

See [README.md](README.md#shared-project-authentication) for security considerations and when authentication is needed.

### Testing

1. **Local project** – Open without credentials; should succeed.
2. **Shared project + valid credentials** – Should authenticate and connect.
3. **Shared project, no credentials** – Should return a clear error asking for credentials (tool params or env vars).
4. **Shared project, wrong credentials** – Should return an authentication-failure error (see `ProjectUtil` auth-style mapping).

### API Reference (project auth)

- `ghidra.framework.client.ClientAuthenticator` – Authentication interface.
- `ghidra.framework.client.PasswordClientAuthenticator` – Username/password implementation.
- `ghidra.framework.client.ClientUtil` – `setClientAuthenticator(ClientAuthenticator)` (must be called before opening projects).
- `ghidra.base.project.GhidraProject` – Project opening.
- `ghidra.framework.model.Project` – `getRepositoryAdapter()` to detect shared/connected status.

```java
ClientUtil.setClientAuthenticator(ClientAuthenticator authenticator);
new PasswordClientAuthenticator(String username, String password);
// Shared: project.getRepositoryAdapter() != null
// Connected: project.getRepositoryAdapter().isConnected();
```

---

## Ghidra Project Locking Explained

### Overview

Ghidra projects use **file-based locking** to prevent multiple processes from opening the same project simultaneously. This is a **built-in Ghidra feature**, not something AgentDecompile controls.

### How Locking Works

#### Lock Files

When a Ghidra project is opened, Ghidra creates two lock files in the project directory:

- `<projectName>.lock` – Main lock file
- `<projectName>.lock~` – Backup lock file

These files prevent other processes (including other AgentDecompile CLI instances) from opening the same project.

#### Why Locking Exists

Ghidra enforces single-process access to prevent:

- **Data corruption** from concurrent writes
- **Transaction conflicts** when multiple processes modify the same project
- **Database inconsistencies** from simultaneous updates

### AgentDecompile's Behavior

**AgentDecompile does NOT create locks** – it uses Ghidra's standard APIs (`GhidraProject.openProject()`), which automatically create lock files.

#### Within the Same Process

If you try to open a project that's already open in the **same JVM process**, AgentDecompile will:

- Detect that the active project matches the requested one
- Reuse the existing project instance (no error)

This works because `ProjectUtil.handleLockedProject()` checks `AppInfo.getActiveProject()`.

#### Across Different Processes

If you try to open a project that's open in a **different process** (another AgentDecompile CLI instance, Ghidra GUI, etc.), you'll get a `LockException` because:

- Each process has its own JVM
- Lock files are checked at the filesystem level
- Ghidra blocks the second open attempt

For user-facing options (Ghidra Server, force ignore lock, single process), error messages, and warnings, see [README.md](README.md#project-locking).

### Technical Details

#### Lock File Location

Lock files are created in the project directory:

```
<projectDir>/
  <projectName>.lock
  <projectName>.lock~
  <projectName>.gpr
  <projectName>/
    (project data)
```

#### Lock File Deletion

When `AGENT_DECOMPILE_FORCE_IGNORE_LOCK=true` (or `forceIgnoreLock: true` on the `open` tool) is set, AgentDecompile attempts to delete lock files using:

1. **Direct deletion**: `File.delete()` / `Path.unlink()`
2. **Rename trick**: If direct deletion fails (file handle in use), rename the file first, then delete
3. **Force kill (Java, Windows only)**: If enabled, `ProjectUtil` can use Windows Restart Manager or handle.exe to find and terminate processes holding the lock, then delete

This is handled by:

- `ProjectUtil.deleteLockFiles()` (Java)
- `ProjectManager._delete_lock_files()` (Python, in `project_manager.py`)

#### Active Project Detection

AgentDecompile checks if a locked project is already the active project:

```java
Project activeProject = AppInfo.getActiveProject();
if (activeProject != null && matches(requestedProject)) {
    // Reuse active project - no error
    return new ProjectOpenResult(activeProject, null, true, false);
}
```

This only works within the same JVM process.

### Summary

- **Locking is Ghidra's feature**, not AgentDecompile's
- **Single-process access** is enforced to prevent corruption
- **Ghidra Server** is the proper solution for shared access
- **AGENT_DECOMPILE_FORCE_IGNORE_LOCK** or **forceIgnoreLock** on the `open` tool is a risky workaround
- **Error messages** explain the situation and options

---

## Intelligent Features in AgentDecompile

For end-user configuration (environment variables) and behavior summary, see [README.md](README.md#intelligent-features) and [CLAUDE.md](CLAUDE.md).

### Overview

AgentDecompile includes intelligent features (auto-bookmarking, auto-tagging, auto-labeling, auto-commenting) that use heuristics and program analysis to enhance the workflow. They are driven only by env vars; tool parameters are not used. Auto-bookmarking runs from `get-functions` and `manage-comments`; auto-tag/label/comment from `manage-function`, `manage-symbols`, and `manage-comments` when the caller does not provide values.

### Technical Details

#### Bookmarking Algorithm

1. Count references to address using `ReferenceManager.getReferencesTo()`
2. Check if count exceeds threshold
3. Determine bookmark type based on address context and reference types
4. Create bookmark in transaction if threshold exceeded
5. Update existing bookmarks if address already bookmarked

#### Tag Auto-Labeling Algorithm

1. Analyze function's API calls
2. Check imported libraries
3. Examine string references for patterns
4. Detect operation patterns (crypto, network, file I/O)
5. Score tags by confidence (0.0-1.0)
6. Return top suggestions sorted by confidence

#### Performance

- **Bookmarking**: Minimal overhead - only checks when addresses are accessed
- **Tag Suggestions**: Analyzes function on-demand, cached per function
- **Name Suggestions**: Fast heuristics-based analysis

*Part 7 — Reference: API documentation URLs used across the codebase.*

---

## API Documentation Reference

This section provides **direct URLs** to all API documentation used by AgentDecompile. Use these links when adding Javadoc comments or understanding external dependencies.

**Inline documentation**: Java classes in `src/main/java/agentdecompile/` include Javadoc with `@see` tags and HTML links to relevant API docs. Documented files:
- **util**: AddressUtil, ProgramLookupUtil, MemoryUtil, DataTypeParserUtil, SchemaUtil, SymbolUtil, SmartSuggestionsUtil, ProjectUtil, DecompilationContextUtil, DebugLogger, DecompilationDiffUtil, FunctionFingerprintUtil, AgentDecompileInternalServiceRegistry, AgentDecompileToolLogger, EnvConfigUtil, IntelligentBookmarkUtil, DecompilationReadTracker, SimilarityComparator, ToolLogCollector, HeadlessProjectHolder, SharedProjectEnvConfig
- **tools**: ToolProvider, AbstractToolProvider, ProgramValidationException, DecompilerToolProvider, FunctionToolProvider, SymbolToolProvider, BookmarkToolProvider, CallGraphToolProvider, CommentToolProvider, ConstantSearchToolProvider, DataToolProvider, DataFlowToolProvider, DataTypeToolProvider, GetFunctionToolProvider, ImportExportToolProvider, MemoryToolProvider, ProjectToolProvider, StringToolProvider, StructureToolProvider, SuggestionToolProvider, VtableToolProvider, CrossReferencesToolProvider
- **plugin**: AgentDecompilePlugin, AgentDecompileApplicationPlugin, AgentDecompileProgramManager, ConfigManager, ConfigChangeListener
- **plugin/config**: ConfigurationBackend, ConfigurationBackendListener, FileBackend, InMemoryBackend, ToolOptionsBackend
- **server**: McpServerManager, GlobalExceptionFilter, ApiKeyAuthFilter, KeepAliveFilter, RequestLoggingFilter, CachingRequestWrapper, CachingResponseWrapper
- **resources**: ResourceProvider, AbstractResourceProvider
- **resources/impl**: ProgramListResource, StaticAnalysisResultsResource, AgentDecompileDebugInfoResource
- **services**: AgentDecompileMcpService
- **headless**: AgentDecompileHeadlessLauncher
- **ui**: AgentDecompileProvider, CaptureDebugAction
- **debug**: DebugCaptureService, DebugInfoCollector
- **root**: agentdecompileFileSystem, agentdecompileExporter, agentdecompileAnalyzer

---

### Quick Reference – Main Documentation URLs

| API | Base URL | Description |
|-----|----------|-------------|
| **Ghidra API** | https://ghidra.re/ghidra_docs/api/ | Official Ghidra Javadoc (reverse engineering framework) |
| **MCP Java SDK** | https://github.com/modelcontextprotocol/java-sdk | Model Context Protocol Java server/client SDK |
| **MCP Java Server Docs** | https://modelcontextprotocol.info/docs/sdk/java/mcp-server/ | MCP Server implementation guide |
| **MCP Protocol Spec** | https://modelcontextprotocol.io/ | Model Context Protocol specification |
| **Ghidra Main Site** | https://ghidra.re/ | Ghidra project home |

---

### Ghidra API – Package & Class URLs

AgentDecompile uses the Ghidra Java API extensively. The URL pattern is:
`https://ghidra.re/ghidra_docs/api/{package-path}/{ClassName}.html`  
(dots become slashes)

#### Core Program Model

| Class | Full URL |
|-------|----------|
| Program | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html |
| Listing | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html |
| Function | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html |
| FunctionManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html |
| FunctionIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html |
| FunctionTag | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionTag.html |
| FunctionTagManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionTagManager.html |
| Instruction | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html |
| CodeUnit | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html |
| CodeUnitIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnitIterator.html |
| Data | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html |
| DataIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/DataIterator.html |
| Parameter | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Parameter.html |
| Variable | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Variable.html |
| CommentType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CommentType.html |
| Bookmark | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Bookmark.html |
| BookmarkManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/BookmarkManager.html |

#### Address Model

| Class | Full URL |
|-------|----------|
| Address | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html |
| AddressSpace | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html |
| AddressSet | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSet.html |
| AddressSetView | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSetView.html |
| AddressIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressIterator.html |
| AddressOutOfBoundsException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressOutOfBoundsException.html |

#### Symbol Model

| Class | Full URL |
|-------|----------|
| Symbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html |
| SymbolTable | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html |
| SymbolIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolIterator.html |
| SymbolType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolType.html |
| Namespace | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html |
| Reference | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html |
| ReferenceManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html |
| ReferenceIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceIterator.html |
| ExternalLocation | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ExternalLocation.html |
| SourceType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SourceType.html |

#### Data Type Model

| Class | Full URL |
|-------|----------|
| DataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html |
| DataTypeManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html |
| DataTypeComponent | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeComponent.html |
| Structure | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html |
| StructureDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/StructureDataType.html |
| Union | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Union.html |
| UnionDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/UnionDataType.html |
| Composite | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Composite.html |
| Category | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Category.html |
| CategoryPath | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/CategoryPath.html |
| BitFieldDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/BitFieldDataType.html |
| FunctionDefinitionDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html |
| ParameterDefinition | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/ParameterDefinition.html |
| ParameterDefinitionImpl | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/ParameterDefinitionImpl.html |
| DataTypeConflictHandler | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeConflictHandler.html |
| InvalidDataTypeException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/InvalidDataTypeException.html |
| DataTypeDependencyException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeDependencyException.html |

#### Memory Model

| Class | Full URL |
|-------|----------|
| Memory | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html |
| MemoryBlock | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html |
| MemoryAccessException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryAccessException.html |

#### Decompiler

| Class | Full URL |
|-------|----------|
| DecompInterface | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html |
| DecompileResults | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html |
| DecompiledFunction | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html |
| ClangToken | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangToken.html |
| ClangTokenGroup | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangTokenGroup.html |
| ClangLine | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html |
| DecompilerUtils | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html |

#### PCode (High-Level IR)

| Class | Full URL |
|-------|----------|
| HighFunction | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html |
| HighSymbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html |
| HighFunctionDBUtil | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunctionDBUtil.html |

#### Framework & Plugin

| Class | Full URL |
|-------|----------|
| AppInfo | https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html |
| Project | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html |
| ProjectLocator | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html |
| DomainFile | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html |
| DomainFolder | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html |
| DomainObject | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html |
| ToolManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html |
| PluginTool | https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html |
| ProgramManager | https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html |
| CodeViewerService | https://ghidra.re/ghidra_docs/api/ghidra/app/services/CodeViewerService.html |
| ProgramLocation | https://ghidra.re/ghidra_docs/api/ghidra/program/util/ProgramLocation.html |
| AutoAnalysisManager | https://ghidra.re/ghidra_docs/api/ghidra/app/plugin/core/analysis/AutoAnalysisManager.html |

#### Language / Compiler Spec

| Class | Full URL |
|-------|----------|
| Language | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Language.html |
| LanguageID | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageID.html |
| LanguageService | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageService.html |
| DefaultLanguageService | https://ghidra.re/ghidra_docs/api/ghidra/program/util/DefaultLanguageService.html |
| CompilerSpec | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpec.html |
| CompilerSpecID | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecID.html |
| LanguageCompilerSpecPair | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageCompilerSpecPair.html |
| LanguageNotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageNotFoundException.html |
| CompilerSpecNotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecNotFoundException.html |

#### Utilities & Parsing

| Class | Full URL |
|-------|----------|
| Msg | https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html |
| TaskMonitor | https://ghidra.re/ghidra_docs/api/ghidra/util/task/TaskMonitor.html |
| TimeoutTaskMonitor | https://ghidra.re/ghidra_docs/api/ghidra/util/task/TimeoutTaskMonitor.html |
| DataTypeParser | https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html |
| CParser | https://ghidra.re/ghidra_docs/api/ghidra/app/util/cparser/C/CParser.html |
| FunctionSignatureParser | https://ghidra.re/ghidra_docs/api/ghidra/app/util/parser/FunctionSignatureParser.html |
| Demangler | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/Demangler.html |
| DemanglerUtil | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/DemanglerUtil.html |
| DemangledObject | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/DemangledObject.html |

#### Importer / Loader / Exporter

| Class | Full URL |
|-------|----------|
| Loader | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/Loader.html |
| LoadSpec | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/LoadSpec.html |
| LoadResults | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/LoadResults.html |
| Loaded | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/Loaded.html |
| ByteProvider | https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/ByteProvider.html |
| MessageLog | https://ghidra.re/ghidra_docs/api/ghidra/app/util/importer/MessageLog.html |
| ExporterException | https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/ExporterException.html |
| BatchGroup | https://ghidra.re/ghidra_docs/api/ghidra/plugins/importer/batch/BatchGroup.html |
| BatchInfo | https://ghidra.re/ghidra_docs/api/ghidra/plugins/importer/batch/BatchInfo.html |

#### Commands

| Class | Full URL |
|-------|----------|
| CreateFunctionCmd | https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/CreateFunctionCmd.html |

#### Exceptions

| Class | Full URL |
|-------|----------|
| CancelledException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/CancelledException.html |
| DuplicateNameException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/DuplicateNameException.html |
| InvalidInputException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/InvalidInputException.html |
| InvalidNameException | https://ghidra.re/ghidra_docs/api/ghidra/util/InvalidNameException.html |
| CodeUnitInsertionException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/util/CodeUnitInsertionException.html |
| VersionException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/VersionException.html |
| IncompatibleLanguageException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/IncompatibleLanguageException.html |
| OverlappingFunctionException | https://ghidra.re/ghidra_docs/api/ghidra/program/database/function/OverlappingFunctionException.html |

#### Other Ghidra Classes

| Class | Full URL |
|-------|----------|
| UndefinedFunction | https://ghidra.re/ghidra_docs/api/ghidra/util/UndefinedFunction.html |
| GhidraProject | https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html |
| DefaultCheckinHandler | https://ghidra.re/ghidra_docs/api/ghidra/framework/data/DefaultCheckinHandler.html |
| FileSystemService | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FileSystemService.html |
| FSRL | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FSRL.html |
| FSUtilities | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FSUtilities.html |
| LocalFileSystem | https://ghidra.re/ghidra_docs/api/ghidra/framework/store/local/LocalFileSystem.html |
| ClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientAuthenticator.html |
| ClientUtil | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html |
| PasswordClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/PasswordClientAuthenticator.html |
| LockException | https://ghidra.re/ghidra_docs/api/ghidra/framework/store/LockException.html |
| NotOwnerException | https://ghidra.re/ghidra_docs/api/ghidra/util/NotOwnerException.html |
| NotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/NotFoundException.html |

---

### MCP (Model Context Protocol) Java SDK

AgentDecompile uses `io.modelcontextprotocol.sdk:mcp` (BOM 0.17.0). The SDK provides server and client implementations.

#### Documentation URLs

| Resource | URL |
|----------|-----|
| **MCP Java SDK GitHub** | https://github.com/modelcontextprotocol/java-sdk |
| **MCP Java Server Docs** | https://modelcontextprotocol.info/docs/sdk/java/mcp-server/ |
| **MCP Protocol Spec** | https://modelcontextprotocol.io/ |
| **MCP SDK Package** | io.modelcontextprotocol.sdk (Maven Central) |

#### Key MCP Classes Used by AgentDecompile

- `io.modelcontextprotocol.server.McpSyncServer` – Synchronous MCP server
- `io.modelcontextprotocol.server.McpServer` – Base MCP server interface
- `io.modelcontextprotocol.spec.McpSchema` – MCP schema types (Tool, CallToolRequest, CallToolResult, Content, TextContent, JsonSchema, Resource, ReadResourceResult, etc.)
- `io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification` – Tool registration
- `io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification` – Resource registration
- `io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider` – HTTP transport
- `io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper` – JSON mapping

---

### How to Add API Documentation Links in Code

When documenting a method or class that uses Ghidra or MCP APIs:

1. Add a `@see` or inline link in the Javadoc:
   ```java
   /**
    * Parses an address string using the program's address factory.
    * @see ghidra.program.model.address.Address
    * @see <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html">Address API</a>
    */
   ```

2. Or use a concise reference block at the top of the class:
   ```java
   /**
    * Utility for address formatting and parsing.
    * <p>Ghidra APIs used: {@link ghidra.program.model.address.Address}, {@link ghidra.program.model.listing.Program}</p>
    * <p>API docs: <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API</a></p>
    */
   ```

---

### Package Summary Pages (Ghidra)

| Package | URL |
|---------|-----|
| ghidra.program.model.address | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/package-summary.html |
| ghidra.program.model.listing | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/package-summary.html |
| ghidra.program.model.symbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/package-summary.html |
| ghidra.program.model.data | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html |
| ghidra.program.model.mem | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/package-summary.html |
| ghidra.app.decompiler | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html |
| ghidra.app.decompiler.component | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/package-summary.html |
| ghidra.framework.model | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/package-summary.html |
| ghidra.framework.plugintool | https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/package-summary.html |
| ghidra.util.task | https://ghidra.re/ghidra_docs/api/ghidra/util/task/package-summary.html |

