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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared tracker for tracking which functions have had their decompilations read.
 * Allows multiple tool providers (DecompilerToolProvider, CommentToolProvider, etc.)
 * to coordinate and know when a function's decompilation has been accessed.
 * <p>
 * Uses function keys "programPath:address" and timestamps for expiry-based validation.
 * Internal utility; no Ghidra or MCP API.
 * </p>
 */
public class DecompilationReadTracker {

    // Use 30 minutes to match DecompilerToolProvider's original expiry time
    // This is shorter than CommentToolProvider's 24 hours but ensures consistency
    // with the original read-before-modify enforcement pattern
    private static final long READ_TRACKING_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

    // Shared tracker instance - thread-safe ConcurrentHashMap
    private static final Map<String, Long> tracker = new ConcurrentHashMap<>();

    /**
     * Record that a function's decompilation has been read.
     * @param functionKey The function key (format: "programPath:address")
     */
    public static void markAsRead(String functionKey) {
        tracker.put(functionKey, System.currentTimeMillis());
    }

    /**
     * Check if a function's decompilation has been read recently (within expiry window).
     * @param functionKey The function key (format: "programPath:address")
     * @return true if decompilation has been read within the expiry window, false otherwise
     */
    public static boolean hasReadDecompilation(String functionKey) {
        Long lastReadTime = tracker.get(functionKey);
        if (lastReadTime == null) {
            return false;
        }

        // Consider decompilation "read" if it was accessed within the expiry window
        long expiryThreshold = System.currentTimeMillis() - READ_TRACKING_EXPIRY_MS;
        return lastReadTime > expiryThreshold;
    }

    /**
     * Clear tracking entries for a specific program.
     * Called when a program is closed to clean up tracking data.
     * @param programPath The program path to clear entries for
     * @return The number of entries removed
     */
    public static int clearProgramEntries(String programPath) {
        int beforeSize = tracker.size();
        tracker.entrySet().removeIf(entry -> entry.getKey().startsWith(programPath + ":"));
        return beforeSize - tracker.size();
    }

    /**
     * Clear all tracking entries (useful for testing or reset).
     */
    public static void clearAll() {
        tracker.clear();
    }
}
