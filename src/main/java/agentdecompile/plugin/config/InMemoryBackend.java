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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.util.Msg;

/**
 * In-memory configuration backend.
 * Stores configuration in memory with no persistence; used for headless defaults or testing.
 * <p>
 * Ghidra API: {@link ghidra.util.Msg} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html">Msg API</a>.
 * </p>
 */
public class InMemoryBackend implements ConfigurationBackend {

    private final Map<String, Object> storage = new ConcurrentHashMap<>();
    private final Set<ConfigurationBackendListener> listeners = ConcurrentHashMap.newKeySet();

    @Override
    public int getInt(String category, String name, int defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof Integer integer) {
            return integer;
        }
        return defaultValue;
    }

    @Override
    public void setInt(String category, String name, int value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public String getString(String category, String name, String defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof String string) {
            return string;
        }
        return defaultValue;
    }

    @Override
    public void setString(String category, String name, String value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
        notifyListeners(category, name, oldValue, value);
    }

    @Override
    public boolean getBoolean(String category, String name, boolean defaultValue) {
        String key = makeKey(category, name);
        Object value = storage.get(key);
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        return defaultValue;
    }

    @Override
    public void setBoolean(String category, String name, boolean value) {
        String key = makeKey(category, name);
        Object oldValue = storage.put(key, value);
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
        storage.clear();
        listeners.clear();
    }

    /**
     * Create a storage key from category and name
     */
    private String makeKey(String category, String name) {
        return category + ":" + name;
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
}
