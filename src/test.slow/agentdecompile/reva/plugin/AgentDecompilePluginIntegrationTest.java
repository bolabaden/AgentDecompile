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
package agentdecompile.plugin;

import static org.junit.Assert.*;

import org.junit.Test;

import agentdecompile.plugin.AgentDecompilePlugin;
import agentdecompile.AgentDecompileIntegrationTestBase;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Integration tests for the AgentDecompilePlugin
 */
public class AgentDecompilePluginIntegrationTest extends AgentDecompileIntegrationTestBase {

    @Test
    public void testPluginLoadsSuccessfully() {
        assertNotNull("Plugin should be loaded", plugin);
        assertEquals("Plugin should have correct name", "AgentDecompilePlugin", plugin.getName());
    }

    @Test
    public void testPluginRegistersInServiceRegistry() {
        AgentDecompilePlugin registeredPlugin = AgentDecompileInternalServiceRegistry.getService(AgentDecompilePlugin.class);
        assertNotNull("Plugin should be registered in service registry", registeredPlugin);
        assertEquals("Registered plugin should be the same instance", plugin, registeredPlugin);
    }

    @Test
    public void testProgramCreation() {
        assertNotNull("Test program should be created", program);
        assertNotNull("Program memory should exist", program.getMemory());
        assertTrue("Program should have memory blocks", program.getMemory().getBlocks().length > 0);
    }
}