# AgentDecompile Internals

This document provides a deep technical dive into the implementation details of AgentDecompile, including network flows, threading models, and design patterns.

## Table of Contents

- [Network Flow in Detail](#network-flow-in-detail)
- [Threading and Concurrency](#threading-and-concurrency)
- [Configuration Management](#configuration-management)
- [Program Lifecycle](#program-lifecycle)
- [Tool Provider Pattern](#tool-provider-pattern)
- [Error Handling](#error-handling)
- [Performance Considerations](#performance-considerations)

## Network Flow in Detail

### Complete Request Path: Client → Ghidra → Response

#### 1. Client sends JSON-RPC request over stdio

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

#### 2. Python stdio_bridge receives on stdin

- `stdio_server()` context manager reads from stdin
- MCP SDK parses JSON-RPC and converts to `CallToolRequest`
- Passes to registered handler: `call_tool(name, arguments)`

**Code:** `src/agentdecompile_cli/stdio_bridge.py` → `@self.server.call_tool()`

#### 3. Bridge handler calls Java backend

```python
async def _call_tool_operation():
    return await asyncio.wait_for(
        self.backend_session.call_tool(name, arguments),
        timeout=300.0
    )
```

The `ClientSession` (MCP SDK) converts to HTTP:

```
POST http://localhost:8080/mcp/message HTTP/1.1
Content-Type: application/json
Connection: keep-alive

{
  "jsonrpc": "2.0",
  "id": ...,
  "method": "call_tool",
  "params": { ... }
}
```

**Code:** `src/agentdecompile_cli/stdio_bridge.py` → `streamablehttp_client()`

#### 4. Jetty receives HTTP request

```
POST /mcp/message
↓
[HttpServletStreamableServerTransportProvider]
↓
[ApiKeyAuthFilter]  (validates auth if enabled)
↓
[RequestLoggingFilter]  (logs if debug enabled)
↓
[KeepAliveFilter]  (adds Connection: keep-alive header)
↓
[MCP Handler]
```

**Code:** `src/main/java/agentdecompile/server/McpServerManager.java` → `startServer()`

#### 5. MCP server routes to tool provider

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

#### 6. Tool provider executes Ghidra operation

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

#### 7. Response flows back through HTTP

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

#### 8. Python bridge converts to stdio

```python
result = await self._call_with_reconnect("call_tool(...)", _call_tool_operation)
# result.content is list of TextContent objects

# Bridge handler returns directly to stdio_server
return result.content  # List[TextContent]
```

The MCP SDK converts back to JSON-RPC and writes to stdout.

#### 9. Client receives response on stdout

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

### Connection Handling

**Timeout Configuration (24 hours):**

Multiple layers protect against premature disconnection:

1. **HTTP Client (Python):** `timeout=3600.0` (1 hour per request)
2. **Jetty Thread Pool:** `idleTimeout=86400000` (24 hours)
3. **Jetty HTTP Config:** `idleTimeout=86400000L` (24 hours)
4. **Jetty Connector:** `idleTimeout=86400000L` (24 hours)
5. **HTTP Headers:** `Keep-Alive: timeout=86400, max=10000`
6. **MCP Keep-Alive:** `keepAliveInterval=30s` (sends periodic pings)

**Why so long?** Ghidra operations (decompilation, analysis) can be slow. A 30-minute operation would timeout with 5-minute idleTimeout. 24 hours ensures long-running tasks complete without "Session terminated" errors.

---

## Threading and Concurrency

### Java Thread Hierarchy

```
Main Thread (gradle/IDE/Ghidra launch)
├── Jetty Server Thread
│   ├── Jetty Worker Thread 1 [request handler]
│   ├── Jetty Worker Thread 2 [request handler]
│   └── ... (up to 200 threads)
└── Ghidra Initialization Thread
    └── Ghidra Application (shared for all tools/programs)
```

### Jetty Thread Pool Configuration

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

### Python Async Model

**File:** `src/agentdecompile_cli/stdio_bridge.py` → `run()`

```python
# Main event loop (single-threaded)
asyncio.run(self.run())

# Inside run():
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

## Configuration Management

### ConfigManager (Java)

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
# Python reads these and passes to Java
AGENT_DECOMPILE_SERVER_HOST=0.0.0.0
AGENT_DECOMPILE_SERVER_PORT=9999
AGENT_DECOMPILE_API_KEY_ENABLED=true
AGENT_DECOMPILE_API_KEY=secret123
```

**Code:** `src/agentdecompile_cli/launcher.py` → `start()`

---

## Program Lifecycle

### GUI Mode: Tool ↔ Program ↔ Server

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

### Headless Mode: Single Project

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

## Tool Provider Pattern

### Template Pattern: AbstractToolProvider

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

### Concrete Example: FunctionToolProvider

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

### Registration Flow

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

## Error Handling

### Error Propagation Path

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

### Validation

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

### Logging

**Ghidra Log:** Used for critical/warning/debug messages
```java
Msg.info(this, "Message to Ghidra log");
Msg.error(this, "Error with stack trace", exception);
```

**MCP Protocol Log:** Used for HTTP request/response logging (if enabled)
```
# In agentdecompile-tools.log (if RequestLoggingFilter enabled):
[AgentDecompile:req-12345] HTTP POST /mcp/message
Request: {...}
Response (200): {...}
Duration: 123ms
```

---

## Performance Considerations

### Bottlenecks

1. **Ghidra Operations** (decompilation, analysis) → slow, blocking
2. **Network Latency** (stdio ↔ HTTP) → minimal impact, single roundtrip per request
3. **JSON Serialization** (for large results) → GsonUtil, can be large

### Optimization Strategies

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

### Memory Usage

- **Ghidra VM:** Configured by JVM heap (usually 2-4GB)
- **Python Process:** Minimal (mostly just event loop)
- **HTTP Connections:** One per client; long-lived

---

## Recommended Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) - System overview
- [DEVELOPMENT.md](DEVELOPMENT.md) - Setup and building
- [MCP_PROTOCOL.md](MCP_PROTOCOL.md) - MCP specifics

