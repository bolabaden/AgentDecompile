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
package agentdecompile.tools.datatypes;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for DataTypeToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 */
public class DataTypeToolProviderTest {
    
    @Mock
    private McpSyncServer mockServer;
    
    private DataTypeToolProvider toolProvider;
    
    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new DataTypeToolProvider(mockServer);
    }
    
    @Test
    public void testRegisterTools() throws McpError {
        // Test that tools can be registered without throwing exceptions
        try {
            toolProvider.registerTools();
        } catch (Exception e) {
            fail("Tool registration should not throw exception: " + e.getMessage());
        }
    }
    
    @Test
    public void testInheritance() {
        // Test that DataTypeToolProvider extends AbstractToolProvider
        assertTrue("DataTypeToolProvider should extend AbstractToolProvider",
            agentdecompile.tools.AbstractToolProvider.class.isAssignableFrom(DataTypeToolProvider.class));
    }
    
    @Test
    public void testToolProviderInterface() {
        // Test that DataTypeToolProvider implements ToolProvider interface
        assertTrue("DataTypeToolProvider should implement ToolProvider",
            agentdecompile.tools.ToolProvider.class.isAssignableFrom(DataTypeToolProvider.class));
    }
    
    @Test
    public void testConstructor() {
        assertNotNull("DataTypeToolProvider should be created", toolProvider);
    }
}
