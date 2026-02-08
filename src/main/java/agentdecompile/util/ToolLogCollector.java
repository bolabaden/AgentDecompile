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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Collects log messages during tool execution to include in JSON responses.
 * Prevents log messages from interfering with JSON parsing while preserving full visibility of log output.
 * <p>
 * Internal utility; no Ghidra or MCP API.
 * </p>
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

