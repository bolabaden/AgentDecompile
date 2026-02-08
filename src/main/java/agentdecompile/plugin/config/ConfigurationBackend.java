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
package agentdecompile.plugin.config;

/**
 * Backend interface for configuration storage.
 * Allows ConfigManager to work with different storage mechanisms:
 * ToolOptions (GUI mode), files (headless mode), or in-memory (testing).
 * <p>
 * Internal abstraction; implementations may use
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html">Ghidra ToolOptions</a>.
 * </p>
 */
public interface ConfigurationBackend {

    /**
     * Get an integer configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param defaultValue The default value if not found
     * @return The configured value or default
     */
    int getInt(String category, String name, int defaultValue);

    /**
     * Set an integer configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param value The value to set
     */
    void setInt(String category, String name, int value);

    /**
     * Get a string configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param defaultValue The default value if not found
     * @return The configured value or default
     */
    String getString(String category, String name, String defaultValue);

    /**
     * Set a string configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param value The value to set
     */
    void setString(String category, String name, String value);

    /**
     * Get a boolean configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param defaultValue The default value if not found
     * @return The configured value or default
     */
    boolean getBoolean(String category, String name, boolean defaultValue);

    /**
     * Set a boolean configuration value
     * @param category The configuration category
     * @param name The configuration name
     * @param value The value to set
     */
    void setBoolean(String category, String name, boolean value);

    /**
     * Check if this backend supports change notifications
     * @return True if this backend can notify listeners of changes
     */
    boolean supportsChangeNotifications();

    /**
     * Register a listener for configuration changes (if supported)
     * @param listener The listener to register
     */
    void addChangeListener(ConfigurationBackendListener listener);

    /**
     * Unregister a configuration change listener
     * @param listener The listener to remove
     */
    void removeChangeListener(ConfigurationBackendListener listener);

    /**
     * Clean up resources when done with this backend
     */
    void dispose();
}
