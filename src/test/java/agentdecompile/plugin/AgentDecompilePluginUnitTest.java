/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
            "Reverse Engineering Assistant (Tool)", info.shortDescription());
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