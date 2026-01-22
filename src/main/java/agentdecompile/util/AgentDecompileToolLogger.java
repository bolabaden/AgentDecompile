/* ###
 * IP: AgentDecompile
 *
 * Licensed under the Business Source License 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Licensor: bolabaden
 * Software: AgentDecompile
 * Change Date: 2030-01-01
 * Change License: Apache License, Version 2.0
 *
 * Under this License, you are granted the right to copy, modify,
 * create derivative works, redistribute, and make non‑production
 * use of the Licensed Work. The Licensor may provide an Additional
 * Use Grant permitting limited production use.
 *
 * On the Change Date, the Licensed Work will be made available
 * under the Change License identified above.
 *
 * The License Grant does not permit any use of the Licensed Work
 * beyond what is expressly allowed.
 *
 * If you violate any term of this License, your rights under it
 * terminate immediately.
 *
 * THE LICENSED WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE LICENSED WORK OR THE
 * USE OR OTHER DEALINGS IN THE LICENSED WORK.
 */
package agentdecompile.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.Application;
import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.plugin.ConfigManager;

/**
 * Logger for MCP tool requests and responses.
 * Writes JSON Lines format to a separate log file (agentdecompile-tools.log) for debugging.
 *
 * Log format:
 * - REQUEST: {"timestamp":"...", "type":"REQUEST", "tool":"...", "requestId":"...", "params":{...}}
 * - RESPONSE: {"timestamp":"...", "type":"RESPONSE", "tool":"...", "requestId":"...", "durationMs":..., "isError":..., "content":{...}}
 *
 * NOTE: Content is decoded JSON (not escaped string) for easy parsing/grepping.
 */
public class AgentDecompileToolLogger {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ReentrantLock LOCK = new ReentrantLock();

    // Max log file size (10MB) and rotation count
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024;
    private static final int MAX_ROTATIONS = 5;

    private static File logFile = null;
    private static boolean initialized = false;

    /**
     * Generate a unique request ID for correlating request/response pairs.
     * @return 8-character UUID substring
     */
    public static String generateRequestId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Log a tool request.
     *
     * @param toolName The name of the tool being called
     * @param requestId The unique request ID for correlation
     * @param params The request parameters (already decoded Map from MCP SDK)
     */
    public static void logRequest(String toolName, String requestId, Map<String, Object> params) {
        if (!isRequestLoggingEnabled()) {
            return;
        }

        init();

        try {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("timestamp", Instant.now().toString());
            entry.put("type", "REQUEST");
            entry.put("tool", toolName);
            entry.put("requestId", requestId);
            entry.put("params", params != null ? params : Map.of());

            writeLogEntry(JSON.writeValueAsString(entry));
        } catch (Exception e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to log request: " + e.getMessage());
        }
    }

    /**
     * Log a tool response.
     *
     * @param toolName The name of the tool
     * @param requestId The unique request ID for correlation
     * @param durationMs How long the tool took to execute
     * @param isError Whether the response is an error
     * @param result The tool result (will be decoded from JSON string for clean nesting)
     */
    public static void logResponse(String toolName, String requestId, long durationMs,
                                   boolean isError, CallToolResult result) {
        if (!isRequestLoggingEnabled()) {
            return;
        }

        try {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("timestamp", Instant.now().toString());
            entry.put("type", "RESPONSE");
            entry.put("tool", toolName);
            entry.put("requestId", requestId);
            entry.put("durationMs", durationMs);
            entry.put("isError", isError);

            // Decode response content from JSON string back to object for clean nesting
            Object decodedContent = decodeResponseContent(result);
            if (decodedContent != null) {
                entry.put("content", decodedContent);
            }

            writeLogEntry(JSON.writeValueAsString(entry));
        } catch (Exception e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to log response: " + e.getMessage());
        }
    }

    /**
     * Log an error response when the tool threw an exception.
     *
     * @param toolName The name of the tool
     * @param requestId The unique request ID for correlation
     * @param durationMs How long the tool took before failing
     * @param errorMessage The error message
     */
    public static void logError(String toolName, String requestId, long durationMs, String errorMessage) {
        if (!isRequestLoggingEnabled()) {
            return;
        }

        try {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("timestamp", Instant.now().toString());
            entry.put("type", "RESPONSE");
            entry.put("tool", toolName);
            entry.put("requestId", requestId);
            entry.put("durationMs", durationMs);
            entry.put("isError", true);
            entry.put("error", errorMessage);

            writeLogEntry(JSON.writeValueAsString(entry));
        } catch (Exception e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to log error response: " + e.getMessage());
        }
    }

    /**
     * Log an HTTP request.
     *
     * @param requestId The unique request ID for correlation
     * @param method HTTP method (GET, POST, etc.)
     * @param uri Request URI
     * @param headers Request headers as a map
     * @param body Request body content (may be null or empty)
     */
    public static void logHttpRequest(String requestId, String method, String uri,
                                      Map<String, String> headers, String body) {
        if (!isRequestLoggingEnabled()) {
            return;
        }

        init();

        try {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("timestamp", Instant.now().toString());
            entry.put("type", "HTTP_REQUEST");
            entry.put("requestId", requestId);
            entry.put("method", method);
            entry.put("uri", uri);
            entry.put("headers", headers != null ? headers : Map.of());

            // Try to decode body as JSON for clean nesting
            if (body != null && !body.isEmpty()) {
                try {
                    JsonNode decoded = JSON.readTree(body);
                    entry.put("body", decoded);
                } catch (Exception e) {
                    entry.put("body", body); // Fallback to raw string
                }
            }

            writeLogEntry(JSON.writeValueAsString(entry));
        } catch (Exception e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to log HTTP request: " + e.getMessage());
        }
    }

    /**
     * Log an HTTP response.
     *
     * @param requestId The unique request ID for correlation
     * @param statusCode HTTP status code
     * @param durationMs How long the request took
     * @param headers Response headers as a map
     * @param body Response body content (may be null or empty)
     */
    public static void logHttpResponse(String requestId, int statusCode, long durationMs,
                                       Map<String, String> headers, String body) {
        if (!isRequestLoggingEnabled()) {
            return;
        }

        try {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("timestamp", Instant.now().toString());
            entry.put("type", "HTTP_RESPONSE");
            entry.put("requestId", requestId);
            entry.put("statusCode", statusCode);
            entry.put("durationMs", durationMs);
            if (headers != null && !headers.isEmpty()) {
                entry.put("headers", headers);
            }

            // Try to decode body as JSON for clean nesting
            if (body != null && !body.isEmpty()) {
                try {
                    JsonNode decoded = JSON.readTree(body);
                    entry.put("body", decoded);
                } catch (Exception e) {
                    entry.put("body", body); // Fallback to raw string
                }
            }

            writeLogEntry(JSON.writeValueAsString(entry));
        } catch (Exception e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to log HTTP response: " + e.getMessage());
        }
    }

    /**
     * Get the log file location.
     * @return The log file path, or null if not initialized
     */
    public static File getLogFile() {
        init();
        return logFile;
    }

    /**
     * Check if request logging is enabled via ConfigManager.
     */
    private static boolean isRequestLoggingEnabled() {
        ConfigManager config = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        return config != null && config.isRequestLoggingEnabled();
    }

    /**
     * Initialize the logger (idempotent).
     */
    private static void init() {
        if (initialized) {
            return;
        }

        LOCK.lock();
        try {
            if (initialized) {
                return;
            }

            // Create log directory in Ghidra user settings
            File userSettingsDir = Application.getUserSettingsDirectory();
            File agentdecompileDir = new File(userSettingsDir, "agentdecompile");
            if (!agentdecompileDir.exists()) {
                agentdecompileDir.mkdirs();
            }

            logFile = new File(agentdecompileDir, "agentdecompile-tools.log");
            initialized = true;

            Msg.debug(AgentDecompileToolLogger.class, "Tool logger initialized: " + logFile.getAbsolutePath());
        } catch (Exception e) {
            Msg.error(AgentDecompileToolLogger.class, "Failed to initialize tool logger", e);
        } finally {
            LOCK.unlock();
        }
    }

    /**
     * Write a log entry to the log file.
     * Handles log rotation if the file exceeds MAX_FILE_SIZE.
     */
    private static void writeLogEntry(String logLine) {
        if (logFile == null) {
            return;
        }

        LOCK.lock();
        try {
            // Check for rotation
            if (logFile.exists() && logFile.length() > MAX_FILE_SIZE) {
                rotateLogFiles();
            }

            // Append to log file
            try (PrintWriter writer = new PrintWriter(new FileWriter(logFile, true))) {
                writer.println(logLine);
            }
        } catch (IOException e) {
            Msg.debug(AgentDecompileToolLogger.class, "Failed to write log entry: " + e.getMessage());
        } finally {
            LOCK.unlock();
        }
    }

    /**
     * Rotate log files (agentdecompile-tools.log -> agentdecompile-tools.log.1 -> ... -> agentdecompile-tools.log.5).
     */
    private static void rotateLogFiles() {
        if (logFile == null || !logFile.exists()) {
            return;
        }

        // Delete oldest rotation
        File oldest = new File(logFile.getParent(), logFile.getName() + "." + MAX_ROTATIONS);
        if (oldest.exists()) {
            oldest.delete();
        }

        // Rotate existing files
        for (int i = MAX_ROTATIONS - 1; i >= 1; i--) {
            File from = new File(logFile.getParent(), logFile.getName() + "." + i);
            File to = new File(logFile.getParent(), logFile.getName() + "." + (i + 1));
            if (from.exists()) {
                if (!from.renameTo(to)) {
                    Msg.warn(AgentDecompileToolLogger.class, "Failed to rotate log file: " + from);
                }
            }
        }

        // Rotate current log
        File rotation1 = new File(logFile.getParent(), logFile.getName() + ".1");
        if (!logFile.renameTo(rotation1)) {
            Msg.warn(AgentDecompileToolLogger.class, "Failed to rotate current log file: " + logFile);
        }

        Msg.debug(AgentDecompileToolLogger.class, "Rotated log files");
    }

    /**
     * Decode the response content from CallToolResult.
     * The content is typically a JSON string inside TextContent - we parse it back
     * to a JsonNode for clean nesting in the log (not escaped string).
     */
    private static Object decodeResponseContent(CallToolResult result) {
        if (result == null) {
            return null;
        }

        List<Content> contents = result.content();
        if (contents == null || contents.isEmpty()) {
            return null;
        }

        Content firstContent = contents.get(0);
        if (firstContent instanceof TextContent) {
            TextContent textContent = (TextContent) firstContent;
            String text = textContent.text();

            if (text == null || text.isEmpty()) {
                return null;
            }

            // Try to parse as JSON for clean nesting
            try {
                JsonNode decoded = JSON.readTree(text);
                return decoded;
            } catch (Exception e) {
                // Not JSON - return as plain string
                return text;
            }
        }

        // Unknown content type
        return null;
    }
}
