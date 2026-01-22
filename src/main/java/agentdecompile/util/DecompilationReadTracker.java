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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared tracker for tracking which functions have had their decompilations read.
 * This allows multiple tool providers (DecompilerToolProvider, CommentToolProvider, etc.)
 * to coordinate and know when a function's decompilation has been accessed.
 *
 * The tracker uses function keys in the format: "programPath:address" (e.g., "/program.exe:0x401000")
 * and stores timestamps to support expiry-based validation.
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
