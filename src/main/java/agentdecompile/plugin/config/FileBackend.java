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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.util.Msg;

/**
 * Configuration backend that uses a properties file.
 * Used in headless mode where configuration is loaded from a file; changes can be persisted.
 * <p>
 * Ghidra API: {@link ghidra.util.Msg} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html">Msg API</a>.
 * </p>
 */
public class FileBackend implements ConfigurationBackend {

    private final File configFile;
    private final Properties properties;
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();
    private final boolean autoSave;

    /**
     * Constructor
     * @param configFile The configuration file to load/save
     * @param autoSave Whether to automatically save changes to the file
     * @throws IOException if the file cannot be read
     */
    public FileBackend(File configFile, boolean autoSave) throws IOException {
        this.configFile = configFile;
        this.autoSave = autoSave;
        this.properties = new Properties();

        // Load existing configuration if file exists
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
                // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
                Msg.info(this, "Loaded configuration from: " + configFile.getAbsolutePath());
            }
        } else {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(this, "Configuration file does not exist, using defaults: " + configFile.getAbsolutePath());
        }
    }

    /**
     * Constructor with autoSave disabled
     * @param configFile The configuration file to load
     * @throws IOException if the file cannot be read
     */
    public FileBackend(File configFile) throws IOException {
        this(configFile, false);
    }

    @Override
    public int getInt(String category, String name, int defaultValue) {
        String key = makeKey(category, name);
        String value = properties.getProperty(key);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Ghidra API: Msg.warn(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
                Msg.warn(this, "Invalid integer value for " + key + ": " + value);
            }
        }
        return defaultValue;
    }

    @Override
    public void setInt(String category, String name, int value) {
        String key = makeKey(category, name);
        String oldValueStr = properties.getProperty(key);
        Integer oldValue = null;
        if (oldValueStr != null) {
            try {
                oldValue = Integer.parseInt(oldValueStr);
            } catch (NumberFormatException e) {
                // Ignore parse error for old value
            }
        }

        properties.setProperty(key, String.valueOf(value));
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        String key = makeKey(category, name);
        return properties.getProperty(key, defaultValue);
    }

    @Override
    public void setString(String category, String name, String value) {
        String key = makeKey(category, name);
        String oldValue = properties.getProperty(key);
        properties.setProperty(key, value);
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        String key = makeKey(category, name);
        String value = properties.getProperty(key);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return defaultValue;
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        String key = makeKey(category, name);
        String oldValueStr = properties.getProperty(key);
        Boolean oldValue = null;
        if (oldValueStr != null) {
            oldValue = Boolean.parseBoolean(oldValueStr);
        }

        properties.setProperty(key, String.valueOf(value));
        if (autoSave) {
            save();
        }
        notifyListeners(category, name, oldValue, value);
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
        if (autoSave) {
            save();
        }
        listeners.clear();
        properties.clear();
    }

    /**
     * Save the current configuration to the file
     */
    public void save() {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            properties.store(fos, "AgentDecompile Configuration");
            // Ghidra API: Msg.debug(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(this, "Saved configuration to: " + configFile.getAbsolutePath());
        } catch (IOException e) {
            // Ghidra API: Msg.error(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(this, "Failed to save configuration to: " + configFile.getAbsolutePath(), e);
        }
    }

    /**
     * Create a property key from category and name
     * Format: category.name (e.g., "AgentDecompile Server Options.Server Port" -> "agentdecompile.server.options.server.port")
     */
    private String makeKey(String category, String name) {
        // Convert to lowercase and replace spaces with dots for property key format
        String catKey = category.toLowerCase().replace(" ", ".");
        String nameKey = name.toLowerCase().replace(" ", ".");
        return catKey + "." + nameKey;
    }

    /**
     * Notify all listeners of a configuration change
     */
    private void notifyListeners(String category, String name, Object oldValue, Object newValue) {
        for (ConfigurationBackendListener listener : listeners) {
            try {
                listener.onConfigurationChanged(category, name, oldValue, newValue);
            } catch (Exception e) {
                // Ghidra API: Msg.error(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
                Msg.error(this, "Error notifying configuration listener", e);
            }
        }
    }

    /**
     * Get the configuration file
     * @return The configuration file
     */
    public File getConfigFile() {
        return configFile;
    }
}
