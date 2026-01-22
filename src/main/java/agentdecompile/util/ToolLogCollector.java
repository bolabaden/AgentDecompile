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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Collects log messages during tool execution to include in JSON responses.
 * This prevents log messages from interfering with JSON parsing while preserving
 * full visibility of all log output.
 */
public class ToolLogCollector {
    private final List<Map<String, Object>> logs = new ArrayList<>();
    private final ThreadLocal<Boolean> isActive = ThreadLocal.withInitial(() -> false);

    /**
     * Check if any logs have been collected
     * @return true if logs list is not empty
     */
    public boolean hasLogs() {
        return !logs.isEmpty();
    }

    /**
     * Start collecting logs for the current thread
     */
    public void start() {
        isActive.set(true);
        logs.clear();
    }

    /**
     * Stop collecting logs and return collected messages
     * @return List of log entries with level, message, and timestamp
     */
    public List<Map<String, Object>> stop() {
        isActive.set(false);
        List<Map<String, Object>> result = new ArrayList<>(logs);
        logs.clear();
        return result;
    }

    /**
     * Check if log collection is active
     */
    public boolean isActive() {
        return isActive.get();
    }

    /**
     * Add a log message
     * @param level Log level (INFO, WARN, DEBUG, ERROR)
     * @param message Log message
     */
    public void addLog(String level, String message) {
        if (isActive.get()) {
            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("level", level);
            logEntry.put("message", message);
            logEntry.put("timestamp", System.currentTimeMillis());
            logs.add(logEntry);
        }
    }

    /**
     * Add logs to a result map if any were collected
     * @param result The result map to add logs to
     * @param collector The log collector that was used
     */
    public static void addLogsToResult(Map<String, Object> result, ToolLogCollector collector) {
        if (collector != null && !collector.logs.isEmpty()) {
            result.put("logs", new ArrayList<>(collector.logs));
        }
    }
}

