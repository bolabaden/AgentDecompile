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

import java.util.HashMap;
import java.util.Map;

/**
 * A simple service registry to allow components to locate each other at runtime.
 * This is a static registry that provides global access to core services.
 * <p>
 * Internal component; no Ghidra or MCP API. Used by tools to obtain
 * {@link agentdecompile.plugin.ConfigManager} and other plugin services.
 * </p>
 */
public class AgentDecompileInternalServiceRegistry {
    private static final Map<Class<?>, Object> services = new HashMap<>();

    /**
     * Register a service implementation
     * @param <T> The service type
     * @param serviceClass The service interface class
     * @param implementation The service implementation
     */
    public static <T> void registerService(Class<T> serviceClass, T implementation) {
        services.put(serviceClass, implementation);
    }

    /**
     * Get a registered service
     * @param <T> The service type
     * @param serviceClass The service interface class
     * @return The service implementation or null if not found
     */
    @SuppressWarnings("unchecked")
    public static <T> T getService(Class<T> serviceClass) {
        return (T) services.get(serviceClass);
    }

    /**
     * Remove a service from the registry
     * @param <T> The service type
     * @param serviceClass The service interface class
     */
    public static <T> void unregisterService(Class<T> serviceClass) {
        services.remove(serviceClass);
    }

    /**
     * Clear all registered services
     */
    public static void clearAllServices() {
        services.clear();
    }
}
