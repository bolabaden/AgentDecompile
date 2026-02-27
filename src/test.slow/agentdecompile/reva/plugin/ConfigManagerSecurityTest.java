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

import org.junit.Before;
import org.junit.Test;

import agentdecompile.plugin.ConfigManager;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Test class for ConfigManager security-related configuration options.
 */
public class ConfigManagerSecurityTest extends AgentDecompileIntegrationTestBase {

    @Override
    protected boolean shouldLoadPlugin() {
        // This test doesn't need the GUI plugin, just the tool for ToolOptions
        return false;
    }

    private ConfigManager configManager;

    @Before
    public void setUp() throws Exception {
        configManager = new ConfigManager(tool);
    }

    @Test
    public void testDefaultHostConfiguration() {
        // Test that the default host is localhost (secure by default)
        String defaultHost = configManager.getServerHost();
        assertEquals("Default host should be localhost for security", "127.0.0.1", defaultHost);
    }

    @Test
    public void testHostConfigurationUpdate() {
        // Test updating the host configuration
        String newHost = "0.0.0.0";
        configManager.setServerHost(newHost);
        assertEquals("Host should be updated", newHost, configManager.getServerHost());
    }

    @Test
    public void testConfigurationPersistence() {
        // Test that configuration changes are persisted through the options system
        ToolOptions options = tool.getOptions(ConfigManager.SERVER_OPTIONS);

        configManager.setServerHost("192.168.1.100");

        assertEquals("Host should be persisted in options",
                     "192.168.1.100", options.getString(ConfigManager.SERVER_HOST, null));
    }
}