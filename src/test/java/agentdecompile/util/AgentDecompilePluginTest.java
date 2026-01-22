package agentdecompile.util;

import static org.junit.Assert.*;

import org.junit.Test;

import agentdecompile.plugin.AgentDecompilePlugin;

public class AgentDecompilePluginTest {

    @Test
    public void testPluginClassExists() {
        // Basic test to ensure the AgentDecompilePlugin class exists and can be instantiated
        assertNotNull("AgentDecompilePlugin class should exist", AgentDecompilePlugin.class);
        assertEquals("Package should be correct", "agentdecompile.plugin", AgentDecompilePlugin.class.getPackage().getName());
    }

    @Test
    public void testPluginConstructorSignature() throws NoSuchMethodException {
        // Verify the plugin has the correct constructor signature for Ghidra plugins
        assertNotNull("AgentDecompilePlugin should have a constructor that takes PluginTool",
                     AgentDecompilePlugin.class.getConstructor(ghidra.framework.plugintool.PluginTool.class));
    }
}
