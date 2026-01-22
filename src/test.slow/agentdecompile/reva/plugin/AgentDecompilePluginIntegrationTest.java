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