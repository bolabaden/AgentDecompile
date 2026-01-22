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

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Configuration backend that uses Ghidra's ToolOptions.
 * This is used in GUI mode where configuration is persisted to Ghidra's tool options.
 */
public class ToolOptionsBackend implements ConfigurationBackend, OptionsChangeListener {

    private final ToolOptions toolOptions;
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();

    /**
     * Constructor
     * @param tool The plugin tool
     * @param category The options category (e.g., "AgentDecompile Server Options")
     */
    public ToolOptionsBackend(PluginTool tool, String category) {
        this.toolOptions = tool.getOptions(category);

        // Register as listener for Ghidra's option changes
        toolOptions.addOptionsChangeListener(this);
    }

    @Override
    public int getInt(String category, String name, int defaultValue) {
        return toolOptions.getInt(name, defaultValue);
    }

    @Override
    public void setInt(String category, String name, int value) {
        toolOptions.setInt(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        return toolOptions.getString(name, defaultValue);
    }

    @Override
    public void setString(String category, String name, String value) {
        toolOptions.setString(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        return toolOptions.getBoolean(name, defaultValue);
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        toolOptions.setBoolean(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public boolean supportsChangeNotifications() {
        return true;
    }

    @Override
    public void addChangeListener(ConfigurationBackendListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeChangeListener(ConfigurationBackendListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void dispose() {
        if (toolOptions != null) {
            toolOptions.removeOptionsChangeListener(this);
        }
        listeners.clear();
    }

    /**
     * Ghidra's options change callback
     */
    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue)
            throws OptionsVetoException {

        Msg.debug(this, "ToolOptions changed: " + optionName + " from " + oldValue + " to " + newValue);

        // Notify our listeners
        // NOTE: We pass empty string as category since ToolOptions doesn't provide it
        for (ConfigurationBackendListener listener : listeners) {
            try {
                listener.onConfigurationChanged("", optionName, oldValue, newValue);
            } catch (Exception e) {
                Msg.error(this, "Error notifying configuration listener", e);
            }
        }
    }

    /**
     * Get the underlying ToolOptions (for registering options)
     * @return The ToolOptions instance
     */
    public ToolOptions getToolOptions() {
        return toolOptions;
    }
}
