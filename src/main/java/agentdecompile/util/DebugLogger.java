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
package agentdecompile.util;

import ghidra.util.Msg;
import agentdecompile.plugin.ConfigManager;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Debug logger utility that respects the debug configuration setting.
 * Provides specialized logging for connection debugging and performance monitoring.
 * <p>
 * Uses {@link ghidra.util.Msg} for output when debug is enabled -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html">Msg API</a>.
 * </p>
 */
public class DebugLogger {
    
    private static ConfigManager getConfigManager() {
        return AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
    }
    
    /**
     * Log a debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     */
    public static void debug(Object source, String message) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(source, "[DEBUG] " + message);
        }
    }
    
    /**
     * Log a debug message with an exception if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     * @param throwable The exception to include
     */
    public static void debug(Object source, String message, Throwable throwable) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            // Ghidra API: Msg.info(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.info(source, "[DEBUG] " + message, throwable);
        }
    }
    
    /**
     * Log a connection-related debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param message The message to log
     */
    public static void debugConnection(Object source, String message) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(source, "[DEBUG-CONNECTION] " + message);
        }
    }
    
    /**
     * Log a performance-related debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param operation The operation being timed
     * @param durationMs The duration in milliseconds
     */
    public static void debugPerformance(Object source, String operation, long durationMs) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(source, "[DEBUG-PERF] " + operation + " took " + durationMs + "ms");
        }
    }
    
    /**
     * Log a tool execution debug message if debug mode is enabled
     * @param source The source object for the log message
     * @param toolName The name of the tool being executed
     * @param status The status (START, END, ERROR, etc.)
     * @param details Additional details
     */
    public static void debugToolExecution(Object source, String toolName, String status, String details) {
        ConfigManager config = getConfigManager();
        if (config != null && config.isDebugMode()) {
            String message = "[DEBUG-TOOL] " + toolName + " - " + status;
            if (details != null && !details.isEmpty()) {
                message += ": " + details;
            }
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(source, message);
        }
    }
    
    /**
     * Check if debug mode is currently enabled
     * @return true if debug mode is enabled, false otherwise
     */
    public static boolean isDebugEnabled() {
        ConfigManager config = getConfigManager();
        return config != null && config.isDebugMode();
    }
}