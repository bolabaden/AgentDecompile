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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.util.Msg;

/**
 * In-memory configuration backend.
 * Stores configuration in memory with no persistence.
 * Used for headless mode with default settings or testing.
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
                Msg.error(this, "Error notifying configuration listener", e);
            }
        }
    }
}
