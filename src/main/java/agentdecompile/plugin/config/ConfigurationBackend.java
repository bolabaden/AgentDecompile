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
package agentdecompile.plugin.config;

/**
 * Backend interface for configuration storage.
 * This abstraction allows ConfigManager to work with different storage
 * mechanisms: ToolOptions (GUI mode), files (headless mode), or in-memory (testing).
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
