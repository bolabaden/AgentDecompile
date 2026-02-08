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

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Configuration backend that uses Ghidra's ToolOptions.
 * Used in GUI mode where configuration is persisted to Ghidra's tool options.
 * <p>
 * Ghidra API: {@link ghidra.framework.options.ToolOptions}, {@link ghidra.framework.options.OptionsChangeListener},
 * {@link ghidra.framework.plugintool.PluginTool} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html">ToolOptions API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
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
        // Ghidra API: PluginTool.getOptions(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getOptions(java.lang.String)
        this.toolOptions = tool.getOptions(category);

        // Register as listener for Ghidra's option changes
        // Ghidra API: ToolOptions.addOptionsChangeListener(OptionsChangeListener) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#addOptionsChangeListener(ghidra.framework.options.OptionsChangeListener)
        toolOptions.addOptionsChangeListener(this);
    }

    @Override
    public int getInt(String category, String name, int defaultValue) {
        // Ghidra API: ToolOptions.getInt(String, int) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#getInt(java.lang.String,int)
        return toolOptions.getInt(name, defaultValue);
    }

    @Override
    public void setInt(String category, String name, int value) {
        // Ghidra API: ToolOptions.setInt(String, int) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#setInt(java.lang.String,int)
        toolOptions.setInt(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        // Ghidra API: ToolOptions.getString(String, String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#getString(java.lang.String,java.lang.String)
        return toolOptions.getString(name, defaultValue);
    }

    @Override
    public void setString(String category, String name, String value) {
        // Ghidra API: ToolOptions.setString(String, String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#setString(java.lang.String,java.lang.String)
        toolOptions.setString(name, value);
        // optionsChanged() will be called automatically by Ghidra
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        // Ghidra API: ToolOptions.getBoolean(String, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#getBoolean(java.lang.String,boolean)
        return toolOptions.getBoolean(name, defaultValue);
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        // Ghidra API: ToolOptions.setBoolean(String, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#setBoolean(java.lang.String,boolean)
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
            // Ghidra API: ToolOptions.removeOptionsChangeListener(OptionsChangeListener) - https://ghidra.re/ghidra_docs/api/ghidra/framework/options/ToolOptions.html#removeOptionsChangeListener(ghidra.framework.options.OptionsChangeListener)
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

        // Ghidra API: Msg.debug(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
        Msg.debug(this, "ToolOptions changed: " + optionName + " from " + oldValue + " to " + newValue);

        // Notify our listeners
        // NOTE: We pass empty string as category since ToolOptions doesn't provide it
        for (ConfigurationBackendListener listener : listeners) {
            try {
                listener.onConfigurationChanged("", optionName, oldValue, newValue);
            } catch (Exception e) {
                // Ghidra API: Msg.error(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
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
