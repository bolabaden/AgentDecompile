# MCP Protocol in AgentDecompile

This document explains how AgentDecompile implements the Model Context Protocol (MCP) and how to work with MCP concepts.

## Table of Contents

- [MCP Overview](#mcp-overview)
- [AgentDecompile's MCP Implementation](#agentdecompiles-mcp-implementation)
- [Tool Definitions](#tool-definitions)
- [Resource Definitions](#resource-definitions)
- [Request/Response Examples](#requestresponse-examples)
- [Error Handling](#error-handling)
- [Protocol Compatibility](#protocol-compatibility)

## MCP Overview

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

## AgentDecompile's MCP Implementation

### Architecture

```
MCP Client (Claude, etc.)
  ↓ (stdio JSON-RPC)
AgentDecompile Stdio Bridge (Python)
  ↓ (HTTP POST /mcp/message)
AgentDecompile MCP Server (Java/Jetty)
  ↓ (Java method calls)
Ghidra Framework
```

### Server Configuration

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
    .serverInfo("AgentDecompile", "1.0.0")
    .capabilities(capabilities)
    .build();
```

**Python Side:** `stdio_bridge.py`

```python
# Create MCP server that proxies to Java backend
self.server = Server("AgentDecompile")

# Register handlers (proxies to Java)
@self.server.list_tools()
async def list_tools() -> list[Tool]:
    # Forward to Java backend
    result = await self.backend_session.list_tools()
    return result.tools
```

### Initialization Handshake

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

## Tool Definitions

### Anatomy of a Tool

A tool is defined by:

1. **Name:** Unique identifier (snake_case)
2. **Description:** Human-readable explanation
3. **Input Schema:** JSON Schema defining parameters
4. **Handler:** Function that executes the tool

### Example: list_functions Tool

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

### Tool Categories in AgentDecompile

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

### Input Schema Design

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

## Resource Definitions

Resources are **read-only** data the AI can query (unlike tools which are executable).

### Example: Program List Resource

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

### Resource Subscriptions

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

## Request/Response Examples

### Example 1: List Functions

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

### Example 2: Decompile Function

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

### Example 3: Read Resource

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

### Example 4: Error Response

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

## Error Handling

### Error Codes

MCP uses JSON-RPC 2.0 error codes:

| Code | Meaning | AgentDecompile Use |
|------|---------|----------|
| -32700 | Parse error | Invalid JSON sent to server |
| -32600 | Invalid request | Malformed JSON-RPC |
| -32601 | Method not found | Unknown tool name |
| -32602 | Invalid params | Missing required parameter |
| -32603 | Internal error | Ghidra operation failed |

### Error Handling in AgentDecompile

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

## Protocol Compatibility

### MCP Version Support

AgentDecompile uses **MCP SDK 0.17.0**, supporting:

- **Protocol Version:** 2024-11-25 (latest)
- **JSON-RPC:** 2.0
- **Transport:** Stdio and HTTP StreamableHTTP

### Compatibility Notes

**Issue #724 (Unknown Properties):**

The MCP SDK doesn't gracefully handle unknown protocol fields from newer clients (e.g., VS Code uses protocol 2025-11-25). AgentDecompile works around this:

```java
// src/main/java/agentdecompile/server/McpServerManager.java
ObjectMapper objectMapper = new ObjectMapper();
objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(objectMapper);
```

This allows clients with newer protocol fields to work with AgentDecompile even if the SDK doesn't understand them.

### Testing Compatibility

To test MCP compatibility:

```bash
# Start AgentDecompile CLI
python -m agentdecompile_cli

# Use Claude CLI to connect
claude mcp add AgentDecompile -- python -m agentdecompile_cli

# Verify tools are listed
# In Claude, ask to use AgentDecompile tools
```

---

## Adding a New Tool

### Checklist

- [ ] Create `*ToolProvider.java` extending `AbstractToolProvider`
- [ ] Define tool schema (name, description, input schema)
- [ ] Implement handler function
- [ ] Register tool in `registerTools()` method
- [ ] Add provider instance to `McpServerManager.initializeToolProviders()`
- [ ] Write unit tests (test valid/invalid inputs, error cases)
- [ ] Write integration test (test with actual Ghidra operation)
- [ ] Document tool in tool list

### Template

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

## Debugging MCP Traffic

### Enable Request Logging

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

### Inspect Messages

**Stdio (CLI):**

```bash
# Capture stdin/stdout for inspection
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

## Further Reading

- [MCP Specification](https://modelcontextprotocol.io/)
- [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk)
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [INTERNALS.md](INTERNALS.md) - Implementation details

