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
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.PluginInfo;

/**
 * Unit tests for AgentDecompilePlugin metadata and structure
 */
public class AgentDecompilePluginUnitTest {

    @Test
    public void testPluginAnnotation() {
        // Get the plugin info annotation
        PluginInfo info = AgentDecompilePlugin.class.getAnnotation(PluginInfo.class);

        assertNotNull("Plugin should have @PluginInfo annotation", info);
        assertEquals("Plugin status should be RELEASED", PluginStatus.RELEASED, info.status());
        assertEquals("Plugin package name should be AgentDecompile", "AgentDecompile", info.packageName());
        assertEquals("Plugin category should be COMMON", PluginCategoryNames.COMMON, info.category());
        assertEquals("Plugin short description should match",
            "Agent Decompile (Tool)", info.shortDescription());
        assertEquals("Plugin description should match",
            "Tool-level AgentDecompile plugin that connects to the application-level MCP server",
            info.description());
    }

    @Test
    public void testPluginInheritance() {
        // Verify the plugin extends the correct base class
        assertTrue("AgentDecompilePlugin should extend ProgramPlugin",
            ghidra.app.plugin.ProgramPlugin.class.isAssignableFrom(AgentDecompilePlugin.class));
    }

    @Test
    public void testPluginMethods() throws NoSuchMethodException {
        // Check for required method overrides
        assertNotNull("Should have init method",
            AgentDecompilePlugin.class.getDeclaredMethod("init"));

        assertNotNull("Should have cleanup method",
            AgentDecompilePlugin.class.getDeclaredMethod("cleanup"));

        assertNotNull("Should have programOpened method",
            AgentDecompilePlugin.class.getDeclaredMethod("programOpened", ghidra.program.model.listing.Program.class));

        assertNotNull("Should have programClosed method",
            AgentDecompilePlugin.class.getDeclaredMethod("programClosed", ghidra.program.model.listing.Program.class));
    }

    @Test
    public void testPluginFields() throws NoSuchFieldException {
        // Check for expected fields
        assertNotNull("Should have provider field",
            AgentDecompilePlugin.class.getDeclaredField("provider"));

        assertNotNull("Should have mcpService field",
            AgentDecompilePlugin.class.getDeclaredField("mcpService"));
    }
}