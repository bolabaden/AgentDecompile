/* ###
 * IP: AgentDecompile
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package agentdecompile.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.EnvConfigUtil;
import agentdecompile.util.AgentDecompileToolLogger;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import agentdecompile.plugin.AgentDecompileProgramManager;
import agentdecompile.util.ProgramLookupUtil;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.JsonSchema;

/**
 * Base implementation of the ToolProvider interface.
 * Provides common functionality for all tool providers.
 * <p>
 * MCP Java SDK references:
 * <ul>
 *   <li>{@link io.modelcontextprotocol.server.McpSyncServer} - <a href="https://github.com/modelcontextprotocol/java-sdk">MCP Java SDK</a></li>
 *   <li>{@link io.modelcontextprotocol.spec.McpSchema} - Tool, CallToolRequest, CallToolResult, JsonSchema</li>
 *   <li>MCP Server docs: <a href="https://modelcontextprotocol.info/docs/sdk/java/mcp-server/">MCP Java Server</a></li>
 * </ul>
 * Ghidra API: {@link ghidra.program.model.listing.Program}, {@link ghidra.program.model.listing.Function},
 * {@link ghidra.program.model.symbol.SymbolTable} - <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API</a>
 * </p>
 */
public abstract class AbstractToolProvider implements ToolProvider {
    protected static final ObjectMapper JSON = new ObjectMapper();
    protected final McpSyncServer server;
    protected final List<Tool> registeredTools = new ArrayList<>();

    /**
     * Global concurrency limiter for tool executions.
     * Limits the number of concurrent tool calls across ALL tool providers to prevent
     * overwhelming Ghidra's resources (decompiler, program database, etc.).
     * 
     * This is critical for stability: Ghidra operations like decompilation, symbol table
     * lookups, and memory reads are not fully thread-safe when many run concurrently.
     * Without this limit, a burst of concurrent requests (common with AI clients sending
     * 10+ parallel tool calls) can cause internal errors, resource exhaustion, and server
     * crashes (HTTP 500).
     * 
     * The limit of 4 concurrent tool calls provides a balance between throughput and stability.
     * Requests beyond this limit will wait up to TOOL_ACQUIRE_TIMEOUT_SECONDS before timing out.
     */
    private static final Semaphore TOOL_CONCURRENCY_LIMITER = new Semaphore(4, true);

    /**
     * Maximum time (in seconds) to wait for a tool execution slot.
     * If a tool call cannot acquire a slot within this time, it returns an error
     * rather than blocking indefinitely.
     */
    private static final int TOOL_ACQUIRE_TIMEOUT_SECONDS = 120;

    /**
     * Constructor
     * @param server The MCP server to register tools with
     */
    public AbstractToolProvider(McpSyncServer server) {
        this.server = server;
    }

    @Override
    public void programOpened(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void programClosed(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void cleanup() {
        // Default implementation does nothing
    }

    /**
     * Create a JSON schema for a tool
     * @param properties The schema properties, with property name as key
     * @param required List of required property names
     * @return A JsonSchema object
     */
    protected JsonSchema createSchema(Map<String, Object> properties, List<String> required) {
        // Create a wrapper properties map that includes additionalProperties: true
        // This allows unknown parameters to be ignored rather than causing validation errors
        Map<String, Object> schemaProperties = new java.util.HashMap<>(properties);
        // NOTE: additionalProperties is a schema-level property in JSON Schema
        // The MCP SDK JsonSchema constructor may handle this differently, but we'll
        // try setting it in the properties map as well for compatibility
        return new JsonSchema("object", schemaProperties, required, true, null, null);
    }

    /**
     * Helper method to create an error result
     * @param errorMessage The error message
     * @return CallToolResult with error flag set
     */
    protected McpSchema.CallToolResult createErrorResult(String errorMessage) {
        return new McpSchema.CallToolResult(
            List.of(new TextContent(errorMessage)),
            true
        );
    }

    /**
     * Helper method to create a success result with JSON content
     * @param data The data to serialize as JSON
     * @return CallToolResult with success flag set
     */
    protected McpSchema.CallToolResult createJsonResult(Object data) {
        try {
            // If data is a Map, ensure it includes log messages if any were collected
            if (data instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> dataMap = (Map<String, Object>) data;
                // Log messages are added by log collector if active
                // This ensures logs are in JSON response, not stdout/stderr
            }
            return new McpSchema.CallToolResult(
                List.of(new TextContent(JSON.writeValueAsString(data))),
                false
            );
        } catch (JsonProcessingException e) {
            return createErrorResult("Error serializing result to JSON: " + e.getMessage());
        }
    }

    /**
     * Helper method to create a success result with multiple JSON contents
     * @param dataList List of objects to serialize as separate JSON contents
     * @return CallToolResult with success flag set
     */
    protected McpSchema.CallToolResult createMultiJsonResult(List<Object> dataList) {
        try {
            List<Content> contents = new ArrayList<>();
            for (Object data : dataList) {
                contents.add(new TextContent(JSON.writeValueAsString(data)));
            }
            return new McpSchema.CallToolResult(contents, false);
        } catch (JsonProcessingException e) {
            return createErrorResult("Error serializing results to JSON: " + e.getMessage());
        }
    }

    /**
     * Create an error message map for incorrect arguments that should be included in responses
     * @return Map with error message instructing not to call the tool again
     */
    protected Map<String, Object> createIncorrectArgsErrorMap() {
        Map<String, Object> errorMap = new HashMap<>();
        errorMap.put("error", "DO **NOT** CALL THIS TOOL AGAIN UNTIL YOU REFLECT ON WHY YOUR PARAMETERS WERE INCORRECT.");
        return errorMap;
    }

    /**
     * Helper method to extract text from Content object
     * @param content The Content object
     * @return The text content, or content.toString() if not TextContent
     */
    protected String extractTextFromContent(McpSchema.Content content) {
        if (content instanceof TextContent) {
            return ((TextContent) content).text();
        }
        return content.toString();
    }

    /**
     * Register a tool with the MCP server
     * @param tool The tool to register
     * @param handler The handler function for the tool
     */
    protected void registerTool(Tool tool, java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, CallToolRequest, McpSchema.CallToolResult> handler) {
        // Wrap the handler with safe execution, concurrency limiting, and logging
        java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, CallToolRequest, McpSchema.CallToolResult> safeHandler =
            (exchange, request) -> {
                String requestId = AgentDecompileToolLogger.generateRequestId();
                long startTime = System.currentTimeMillis();

                // Log request
                AgentDecompileToolLogger.logRequest(tool.name(), requestId, request.arguments());

                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(AbstractToolProvider.class, String.format("[AgentDecompile:%s] Tool call: %s (queued, %d/%d slots available)",
                    requestId, tool.name(), TOOL_CONCURRENCY_LIMITER.availablePermits(), 4));

                // Acquire a concurrency slot - limits concurrent Ghidra operations
                boolean acquired = false;
                try {
                    acquired = TOOL_CONCURRENCY_LIMITER.tryAcquire(TOOL_ACQUIRE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    long durationMs = System.currentTimeMillis() - startTime;
                    AgentDecompileToolLogger.logError(tool.name(), requestId, durationMs, "Interrupted while waiting for execution slot");
                    return createErrorResult("Tool execution interrupted while waiting for available slot. The server is under heavy load. Please retry.");
                }

                if (!acquired) {
                    long durationMs = System.currentTimeMillis() - startTime;
                    String timeoutMsg = String.format("Tool '%s' timed out waiting for execution slot after %ds. " +
                        "The server is processing too many concurrent requests. Please retry in a moment.", 
                        tool.name(), TOOL_ACQUIRE_TIMEOUT_SECONDS);
                    AgentDecompileToolLogger.logError(tool.name(), requestId, durationMs, timeoutMsg);
                    Msg.warn(AbstractToolProvider.class, String.format("[AgentDecompile:%s] %s", requestId, timeoutMsg));
                    return createErrorResult(timeoutMsg);
                }

                try {
                    Msg.debug(AbstractToolProvider.class, String.format("[AgentDecompile:%s] Tool executing: %s",
                        requestId, tool.name()));

                    McpSchema.CallToolResult result = handler.apply(exchange, request);

                    // Log response
                    long durationMs = System.currentTimeMillis() - startTime;
                    AgentDecompileToolLogger.logResponse(tool.name(), requestId, durationMs,
                        result != null && result.isError(), result);

                    // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AbstractToolProvider.class, String.format("[AgentDecompile:%s] Tool completed: %s (%dms)",
                        requestId, tool.name(), durationMs));

                    return result;
                } catch (IllegalArgumentException | ProgramValidationException e) {
                    long durationMs = System.currentTimeMillis() - startTime;
                    AgentDecompileToolLogger.logError(tool.name(), requestId, durationMs, e.getMessage());
                    // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AbstractToolProvider.class, String.format("[AgentDecompile:%s] Tool error: %s - %s (%dms)",
                        requestId, tool.name(), e.getMessage(), durationMs));
                    return createErrorResult(e.getMessage());
                } catch (Exception e) {
                    long durationMs = System.currentTimeMillis() - startTime;
                    AgentDecompileToolLogger.logError(tool.name(), requestId, durationMs, e.getMessage());
                    // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
                    Msg.error(AbstractToolProvider.class, String.format("[AgentDecompile:%s] Tool failed: %s (%dms)",
                        requestId, tool.name(), durationMs), e);
                    return createErrorResult("Tool execution failed: " + e.getMessage());
                } finally {
                    // Always release the concurrency slot
                    TOOL_CONCURRENCY_LIMITER.release();
                }
            };

        SyncToolSpecification toolSpec = SyncToolSpecification.builder()
            .tool(tool)
            .callHandler(safeHandler)
            .build();
        server.addTool(toolSpec);
        registeredTools.add(tool);
        logInfo("Registered tool: " + tool.name());
    }

    /**
     * Log an error message
     * @param message The message to log
     */
    protected void logError(String message) {
        // Ghidra API: Msg.error(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object)
        Msg.error(this, message);
    }

    /**
     * Log an error message with an exception
     * @param message The message to log
     * @param e The exception that caused the error
     */
    protected void logError(String message, Exception e) {
        // Ghidra API: Msg.error(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
        Msg.error(this, message, e);
    }

    /**
     * Log an informational message
     * @param message The message to log
     */
    protected void logInfo(String message) {
        // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
        Msg.info(this, message);
    }

    // ========================================================================
    // Dynamic Parameter Name Resolution (snake_case <-> camelCase)
    // ========================================================================

    /**
     * Convert camelCase to snake_case
     * @param camelCase The camelCase string
     * @return The snake_case equivalent
     */
    private String camelToSnake(String camelCase) {
        if (camelCase == null || camelCase.isEmpty()) {
            return camelCase;
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < camelCase.length(); i++) {
            char c = camelCase.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Convert snake_case to camelCase
     * @param snakeCase The snake_case string
     * @return The camelCase equivalent
     */
    private String snakeToCamel(String snakeCase) {
        if (snakeCase == null || snakeCase.isEmpty()) {
            return snakeCase;
        }
        StringBuilder result = new StringBuilder();
        boolean nextUpper = false;
        for (int i = 0; i < snakeCase.length(); i++) {
            char c = snakeCase.charAt(i);
            if (c == '_') {
                nextUpper = true;
            } else {
                if (nextUpper) {
                    result.append(Character.toUpperCase(c));
                    nextUpper = false;
                } else {
                    result.append(c);
                }
            }
        }
        return result.toString();
    }

    /**
     * Get a parameter value from arguments map, trying both the exact key and
     * its snake_case/camelCase variants. This allows tools to accept parameters
     * in either naming convention without hardcoding specific parameter names.
     *
     * @param args The arguments map
     * @param key The parameter key to look for (can be in either convention)
     * @return The value if found, null otherwise
     */
    protected Object getParameterValue(Map<String, Object> args, String key) {
        if (args == null || key == null) {
            return null;
        }

        // Try exact match first (most common case)
        Object value = args.get(key);
        if (value != null) {
            return value;
        }

        // Try snake_case variant if key looks like camelCase
        if (key.matches(".*[a-z][A-Z].*")) {
            String snakeKey = camelToSnake(key);
            value = args.get(snakeKey);
            if (value != null) {
                return value;
            }
        }

        // Try camelCase variant if key looks like snake_case
        if (key.contains("_")) {
            String camelKey = snakeToCamel(key);
            value = args.get(camelKey);
            if (value != null) {
                return value;
            }
        }

        return null;
    }

    /**
     * Check if a parameter exists in arguments map, trying both the exact key and
     * its snake_case/camelCase variants.
     *
     * @param args The arguments map
     * @param key The parameter key to check for
     * @return true if the parameter exists, false otherwise
     */
    private boolean hasParameter(Map<String, Object> args, String key) {
        return getParameterValue(args, key) != null;
    }

    /**
     * Get a required string parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @return The string value
     * @throws IllegalArgumentException if the parameter is missing
     */
    protected String getString(CallToolRequest request, String key) {
        return getString(request.arguments(), key);
    }

    /**
     * Check if a parameter value is an array (List)
     * @param value The value to check
     * @return true if the value is a List
     */
    protected boolean isArray(Object value) {
        return value instanceof List;
    }

    /**
     * Get a parameter value as a List, converting single values to single-item lists
     * @param args The arguments map
     * @param key The parameter key
     * @return List of values (may be empty if parameter not found)
     */
    @SuppressWarnings("unchecked")
    protected List<Object> getParameterAsList(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            return new ArrayList<>();
        }
        if (value instanceof List) {
            return (List<Object>) value;
        }
        // Single value - wrap in list
        List<Object> singleItem = new ArrayList<>();
        singleItem.add(value);
        return singleItem;
    }

    /**
     * Get a required string parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The string value
     * @throws IllegalArgumentException if the parameter is missing
     */
    protected String getString(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        // If it's an array, get the first item
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            if (list.isEmpty()) {
                throw new IllegalArgumentException("Missing required parameter: " + key);
            }
            return list.get(0).toString();
        }
        // Convert non-string values to string for flexibility
        return value.toString();
    }

    /**
     * Get an optional string parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The string value or default
     */
    protected String getOptionalString(CallToolRequest request, String key, String defaultValue) {
        return getOptionalString(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional string parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The string value or default
     */
    protected String getOptionalString(Map<String, Object> args, String key, String defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            // Check environment variable for default value
            return EnvConfigUtil.getStringDefault(key, defaultValue);
        }
        // Convert non-string values to string for flexibility
        return value.toString();
    }

    /**
     * Get a required integer parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @return The integer value
     * @throws IllegalArgumentException if the parameter is missing or not a number
     */
    protected int getInt(CallToolRequest request, String key) {
        return getInt(request.arguments(), key);
    }

    /**
     * Get a required integer parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The integer value
     * @throws IllegalArgumentException if the parameter is missing or not a number
     */
    protected int getInt(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get an optional integer parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The integer value or default
     */
    protected int getOptionalInt(CallToolRequest request, String key, int defaultValue) {
        return getOptionalInt(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional integer parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The integer value or default
     */
    protected int getOptionalInt(Map<String, Object> args, String key, int defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            // Check environment variable for default value
            return EnvConfigUtil.getIntDefault(key, defaultValue);
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get an optional integer parameter from arguments that can be null.
     * Unlike getOptionalInt(), this method can return null when the parameter is not provided
     * or when explicitly set to null, allowing distinction between "not provided" and "provided with default".
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present (can be null)
     * @return The Integer value, default, or null
     */
    protected Integer getOptionalInteger(Map<String, Object> args, String key, Integer defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        // Try to parse string representations of numbers
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }

    /**
     * Get a required boolean parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The boolean value
     * @throws IllegalArgumentException if the parameter is missing or not a valid boolean
     */
    protected boolean getBoolean(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Boolean aBoolean) {
            return aBoolean;
        }
        // Handle string representations of booleans
        if (value instanceof String string) {
            String strValue = string.toLowerCase();
            if ("true".equals(strValue)) {
                return true;
            } else if ("false".equals(strValue)) {
                return false;
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a boolean or 'true'/'false' string");
    }

    /**
     * Get an optional boolean parameter from CallToolRequest
     * @param request The CallToolRequest
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The boolean value or default
     */
    protected boolean getOptionalBoolean(CallToolRequest request, String key, boolean defaultValue) {
        return getOptionalBoolean(request.arguments(), key, defaultValue);
    }

    /**
     * Get an optional boolean parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The boolean value or default
     */
    protected boolean getOptionalBoolean(Map<String, Object> args, String key, boolean defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            // Check environment variable for default value
            return EnvConfigUtil.getBooleanDefault(key, defaultValue);
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        // Handle string representations of booleans
        if (value instanceof String) {
            String strValue = ((String) value).toLowerCase();
            if ("true".equals(strValue)) {
                return true;
            } else if ("false".equals(strValue)) {
                return false;
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a boolean or 'true'/'false' string");
    }

    /**
     * Get an optional map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The map value or default
     */
    @SuppressWarnings("unchecked")
    protected Map<String, Object> getOptionalMap(Map<String, Object> args, String key, Map<String, Object> defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get a required list parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The list value
     * @throws IllegalArgumentException if the parameter is missing or not a list
     */
    @SuppressWarnings("unchecked")
    protected List<String> getStringList(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof List) {
            return (List<String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a list");
    }

    /**
     * Get an optional list parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The list value or default
     */
    @SuppressWarnings("unchecked")
    protected List<String> getOptionalStringList(Map<String, Object> args, String key, List<String> defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof List) {
            return (List<String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a list");
    }

    /**
     * Get a required string map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @return The map value
     * @throws IllegalArgumentException if the parameter is missing or not a map
     */
    @SuppressWarnings("unchecked")
    protected Map<String, String> getStringMap(Map<String, Object> args, String key) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Map) {
            return (Map<String, String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get an optional string map parameter from arguments
     * @param args The arguments map
     * @param key The parameter key
     * @param defaultValue The default value if not present
     * @return The map value or default
     */
    @SuppressWarnings("unchecked")
    protected Map<String, String> getOptionalStringMap(Map<String, Object> args, String key, Map<String, String> defaultValue) {
        Object value = getParameterValue(args, key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Map) {
            return (Map<String, String>) value;
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be an object");
    }

    /**
     * Get a validated program by path. This method ensures the program exists and is in a valid state.
     * Uses ProgramLookupUtil for consistent error messages with helpful suggestions.
     * @param programPath The path to the program
     * @return A valid Program object
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getValidatedProgram(String programPath) throws ProgramValidationException {
        return ProgramLookupUtil.getValidatedProgram(programPath);
    }

    /**
     * Get a validated program from MCP CallToolRequest. Handles parameter extraction and validation in one call.
     * If programPath is not provided, attempts to use the current program from GUI (like GhidraMCP).
     * @param request The CallToolRequest from MCP tool call
     * @return A valid Program object
     * @throws IllegalArgumentException if programPath parameter is missing and no current program is available
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getProgramFromArgs(CallToolRequest request) throws IllegalArgumentException, ProgramValidationException {
        return getProgramFromArgs(request.arguments());
    }

    /**
     * Get a validated program from MCP arguments. Handles parameter extraction and validation in one call.
     * If programPath is not provided, attempts to find the most likely intended program.
     * <p>
     * Smart resolution logic:
     * 1. If path provided, use it.
     * 2. If path missing:
     *    a. If GUI active, use it.
     *    b. If multiple programs open, check 'address'/'addressOrSymbol'/'function' args to find a match.
     *    c. If still ambiguous, return the first available program (best effort).
     * 
     * @param args The arguments map from MCP tool call
     * @return A valid Program object
     * @throws IllegalArgumentException if programPath parameter is missing and no current program is available
     * @throws ProgramValidationException if the program is not found, invalid, or in an invalid state
     */
    protected Program getProgramFromArgs(Map<String, Object> args) throws IllegalArgumentException, ProgramValidationException {
        // Try to get programPath
        String programPath = getOptionalString(args, "programPath", null);
        
        // Use resolvePrograms to get candidates
        List<Program> candidates = ProgramLookupUtil.resolvePrograms(programPath);
        
        if (candidates.isEmpty()) {
            throw new ProgramValidationException("No programs are available in the current project");
        }
        
        // If only one candidate, use it
        if (candidates.size() == 1) {
            return candidates.get(0);
        }
        
        // Multiple candidates found and no specific path provided.
        // Try to disambiguate based on address/symbol arguments
        String addrStr = getOptionalString(args, "address", null);
        if (addrStr == null) addrStr = getOptionalString(args, "addressOrSymbol", null);
        if (addrStr == null) addrStr = getOptionalString(args, "function", null);
        
        if (addrStr != null) {
            for (Program p : candidates) {
                // Check if this program can resolve the address/symbol
                if (AddressUtil.resolveAddressOrSymbol(p, addrStr) != null) {
                    Msg.info(AbstractToolProvider.class, "Disambiguated program '" + p.getName() + "' containing symbol/address: " + addrStr);
                    return p;
                }
            }
        }
        
        // If still ambiguous, return the first one (best effort)
        Program first = candidates.get(0);
        Msg.info(AbstractToolProvider.class, "Multiple programs matched, auto-selecting first: " + first.getName());
        return first;
    }

    /**
     * Get all validated programs from MCP arguments.
     * Used for tools that can operate on multiple programs (e.g. search).
     * 
     * @param request The CallToolRequest from MCP tool call
     * @return List of valid Program objects (never empty)
     * @throws ProgramValidationException if no programs found
     */
    protected List<Program> getProgramsFromArgs(CallToolRequest request) throws ProgramValidationException {
        return getProgramsFromArgs(request.arguments());
    }

    /**
     * Get all validated programs from MCP arguments.
     * Used for tools that can operate on multiple programs (e.g. search).
     * 
     * @param args The arguments map from MCP tool call
     * @return List of valid Program objects (never empty)
     * @throws ProgramValidationException if no programs found
     */
    protected List<Program> getProgramsFromArgs(Map<String, Object> args) throws ProgramValidationException {
        String programPath = getOptionalString(args, "programPath", null);
        List<Program> programs = ProgramLookupUtil.resolvePrograms(programPath);
        
        if (programs.isEmpty()) {
            throw new ProgramValidationException("No programs are available in the current project");
        }
        
        return programs;
    }

    /**
     * Try to get a program safely without throwing exceptions. Used for default responses when arguments are incorrect.
     * First tries to get programPath from args, then tries current program from GUI, then tries any open program.
     * @param args The arguments map from MCP tool call
     * @return A Program object if available, null otherwise
     */
    protected Program tryGetProgramSafely(Map<String, Object> args) {
        try {
            return getProgramFromArgs(args);
        } catch (Exception e) {
            // Ignore all exceptions - return null if we can't get a program
            return null;
        }
    }


    /**
     * Simple record to hold pagination parameters
     */
    protected record PaginationParams(int startIndex, int maxCount) {}

    /**
     * Get pagination parameters from CallToolRequest with common defaults
     * @param request The CallToolRequest
     * @param defaultMaxCount Default maximum count (varies by tool type)
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(CallToolRequest request, int defaultMaxCount) {
        int startIndex = getOptionalInt(request, "startIndex", 0);
        int maxCount = getOptionalInt(request, "maxCount", defaultMaxCount);
        return new PaginationParams(startIndex, maxCount);
    }

    /**
     * Get pagination parameters from arguments with common defaults
     * @param args The arguments map
     * @param defaultMaxCount Default maximum count (varies by tool type)
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(Map<String, Object> args, int defaultMaxCount) {
        int startIndex = getOptionalInt(args, "startIndex", 0);
        int maxCount = getOptionalInt(args, "maxCount", defaultMaxCount);
        return new PaginationParams(startIndex, maxCount);
    }

    /**
     * Get pagination parameters from CallToolRequest with standard default (100)
     * @param request The CallToolRequest
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(CallToolRequest request) {
        return getPaginationParams(request, 100);
    }

    /**
     * Get pagination parameters from arguments with standard default (100)
     * @param args The arguments map
     * @return PaginationParams object
     */
    protected PaginationParams getPaginationParams(Map<String, Object> args) {
        return getPaginationParams(args, 100);
    }

    /**
     * Get and resolve an address from MCP CallToolRequest
     * @param request The CallToolRequest
     * @param program The program to resolve the address in
     * @param addressKey The key for the address parameter (usually "addressOrSymbol")
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(CallToolRequest request, Program program, String addressKey) throws IllegalArgumentException {
        return getAddressFromArgs(request.arguments(), program, addressKey);
    }

    /**
     * Get and resolve an address from MCP arguments
     * @param args The arguments map
     * @param program The program to resolve the address in
     * @param addressKey The key for the address parameter (usually "addressOrSymbol")
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(Map<String, Object> args, Program program, String addressKey) throws IllegalArgumentException {
        String addressString = getString(args, addressKey);
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressString);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address or symbol: " + addressString);
        }
        return address;
    }

    /**
     * Get and resolve an address from MCP arguments using standard "address" key
     * @param args The arguments map
     * @param program The program to resolve the address in
     * @return Resolved Address object
     * @throws IllegalArgumentException if address parameter is missing or address cannot be resolved
     */
    protected Address getAddressFromArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getAddressFromArgs(args, program, "address");
    }

    /**
     * Helper method to get a function from arguments by name or address
     * @param args The arguments map
     * @param program The program to search in
     * @param paramName The parameter name containing the function name or address
     * @return The resolved function
     * @throws IllegalArgumentException if the function cannot be found
     */
    protected Function getFunctionFromArgs(Map<String, Object> args, Program program, String paramName) throws IllegalArgumentException {
        String functionNameOrAddress = getString(args, paramName);
        if (functionNameOrAddress == null) {
            throw new IllegalArgumentException("No " + paramName + " provided");
        }

        Function function = null;

        // First try to resolve as address or symbol
        Address address = AddressUtil.resolveAddressOrSymbol(program, functionNameOrAddress);
        if (address != null) {
            // Get the containing function for this address
            function = AddressUtil.getContainingFunction(program, address);
        }

        // If not found by address, try by function name
        if (function == null) {
            // Ghidra API: Program.getFunctionManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
            FunctionManager functionManager = program.getFunctionManager();

            // Ghidra API: FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext()) {
                // Ghidra API: FunctionIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html#next()
                Function f = functions.next();
                // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
                if (f.getName().equals(functionNameOrAddress)) {
                    function = f;
                    break;
                }
            }

            if (function == null) {
                // Ghidra API: FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
                functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
                    if (f.getName().equalsIgnoreCase(functionNameOrAddress)) {
                        function = f;
                        break;
                    }
                }
            }
        }

        if (function == null) {
            throw new IllegalArgumentException("Function not found: " + functionNameOrAddress);
        }

        return function;
    }

    /**
     * Helper method to get a function from arguments by name or address (using default parameter name)
     * @param args The arguments map
     * @param program The program to search in
     * @return The resolved function
     * @throws IllegalArgumentException if the function cannot be found
     */
    protected Function getFunctionFromArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getFunctionFromArgs(args, program, "functionNameOrAddress");
    }

    /**
     * Helper method to resolve a symbol name to an address
     * @param args The arguments map
     * @param program The program to search in
     * @param paramName The parameter name containing the symbol name
     * @return The resolved address from the symbol
     * @throws IllegalArgumentException if the symbol cannot be found
     */
    protected Address getAddressFromSymbolArgs(Map<String, Object> args, Program program, String paramName) throws IllegalArgumentException {
        String symbolName = getString(args, paramName);
        if (symbolName == null) {
            throw new IllegalArgumentException("No " + paramName + " provided");
        }

        // Ghidra API: Program.getSymbolTable() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
        SymbolTable symbolTable = program.getSymbolTable();
        // Ghidra API: SymbolTable.getLabelOrFunctionSymbols(String, AddressSetView) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html#getLabelOrFunctionSymbols(java.lang.String,ghidra.program.model.address.AddressSetView)
        List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(symbolName, null);

        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("Symbol not found: " + symbolName);
        }

        // Ghidra API: Symbol.getAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html#getAddress()
        Symbol symbol = symbols.get(0);
        return symbol.getAddress();
    }

    /**
     * Helper method to resolve a symbol name to an address (using default parameter name)
     * @param args The arguments map
     * @param program The program to search in
     * @return The resolved address from the symbol
     * @throws IllegalArgumentException if the symbol cannot be found
     */
    protected Address getAddressFromSymbolArgs(Map<String, Object> args, Program program) throws IllegalArgumentException {
        return getAddressFromSymbolArgs(args, program, "symbolName");
    }

    /**
     * Automatically save a program after modifications.
     * This ensures changes are persisted to disk immediately after successful transactions.
     * For version-controlled programs, also automatically checks in changes to ensure full persistence.
     * Handles read-only programs gracefully and logs errors without failing the operation.
     * <p>
     * This is a workaround for MCP server crashes - all changes are immediately persisted
     * including version control checkin to prevent data loss.
     *
     * @param program The program to save
     * @param operationDescription Description of the operation that triggered the save (e.g., "Set comment")
     * @return true if the program was saved successfully, false otherwise
     */
    protected boolean autoSaveProgram(Program program, String operationDescription) {
        // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
        if (program == null || program.isClosed()) {
            return false;
        }

        try {
            // Ghidra API: Program.getDomainFile() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile()
            DomainFile domainFile = program.getDomainFile();

            // Ghidra API: DomainFile.isReadOnly() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isReadOnly()
            if (domainFile.isReadOnly()) {
                // Ghidra API: DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                logInfo("Skipping auto-save for read-only program: " + domainFile.getPathname());
                return false;
            }

            // Ghidra API: DomainFile.isChanged() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isChanged()
            if (!domainFile.isChanged()) {
                return false;
            }

            // Ghidra API: DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String programPath = domainFile.getPathname();
            String saveMessage = "Auto-save: " + operationDescription;

            // Ghidra API: Program.save(String, TaskMonitor) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#save(java.lang.String,ghidra.util.task.TaskMonitor)
            program.save(saveMessage, TaskMonitor.DUMMY);
            // Ghidra API: Program.flushEvents() (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#flushEvents()
            program.flushEvents();

            logInfo("Auto-saved program: " + programPath + " (" + operationDescription + ")");

            // For version-controlled programs, also check in changes automatically
            // Ghidra API: DomainFile.isVersioned() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isVersioned()
            // Ghidra API: DomainFile.canCheckin() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#canCheckin()
            if (domainFile.isVersioned() && domainFile.canCheckin()) {
                try {
                    boolean wasCached = AgentDecompileProgramManager.releaseProgramFromCache(program);
                    if (wasCached) {
                        // Ghidra API: Msg.debug(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                        Msg.debug(this, "Released program from cache for auto-checkin: " + programPath);
                    }

                    String checkinMessage = saveMessage + "\n💜🐉✨ (AgentDecompile auto-persist)";
                    DefaultCheckinHandler checkinHandler = new DefaultCheckinHandler(
                            checkinMessage, true, false);
                    // Ghidra API: DomainFile.checkin(CheckinHandler, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#checkin(ghidra.framework.model.CheckinHandler,ghidra.util.task.TaskMonitor)
                    domainFile.checkin(checkinHandler, TaskMonitor.DUMMY);

                    // Re-open program to cache if it was cached
                    if (wasCached) {
                        Program reopenedProgram = AgentDecompileProgramManager.reopenProgramToCache(programPath);
                        if (reopenedProgram != null) {
                            // Ghidra API: Msg.debug(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                            Msg.debug(this, "Re-opened program to cache after auto-checkin: " + programPath);
                        }
                    }

                    logInfo("Auto-checked in version-controlled program: " + programPath + " (" + operationDescription + ")");
                } catch (Exception e) {
                    // Log error but don't fail the operation - program was already saved
                    logError("Failed to auto-checkin version-controlled program after " + operationDescription + 
                            ": " + e.getMessage() + " (program was saved, but not checked in)", e);
                    // Return true because save succeeded even if checkin failed
                }
            }

            return true;
        } catch (Exception e) {
            // Log error but don't fail the operation - changes are still in memory
            logError("Failed to auto-save program after " + operationDescription + ": " + e.getMessage(), e);
            return false;
        }
    }
}
