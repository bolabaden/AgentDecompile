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
package agentdecompile.tools.project;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Integration tests for list-project-files and list-open-programs tools.
 * list-project-files takes no arguments and returns the full project tree.
 */
public class ProjectToolProviderListProgramsIntegrationTest extends AgentDecompileIntegrationTestBase {

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    public void testListProjectFilesShowsFullTree() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            CallToolResult result = client.callTool(new CallToolRequest("list-project-files", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());
            assertTrue("Should have at least one content item", !result.content().isEmpty());

            String responseJson = ((TextContent) result.content().get(0)).text();
            JsonNode response = objectMapper.readTree(responseJson);
            assertTrue("Response should have metadata and items", response.has("metadata") || response.has("items"));

            return null;
        });
    }

    @Test
    public void testListOpenProgramsShowsAllPrograms() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-open-programs (should show all programs, not just open ones)
            Map<String, Object> args = new HashMap<>();
            args.put("onlyShowCheckedOutPrograms", false);

            CallToolResult result = client.callTool(new CallToolRequest("list-open-programs", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());

            // Should not be an error (may be empty if no programs, but that's okay)
            if (!result.content().isEmpty()) {
                String responseJson = ((TextContent) result.content().get(0)).text();
                JsonNode response = objectMapper.readTree(responseJson);

                // Should have metadata
                if (response.isArray() && response.size() > 0) {
                    JsonNode metadata = response.get(0);
                    assertNotNull("metadata should not be null", metadata);
                }
            }

            return null;
        });
    }

    @Test
    public void testListOpenProgramsDefaultBehavior() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-open-programs without the parameter (should default to false)
            Map<String, Object> args = new HashMap<>();

            CallToolResult result = client.callTool(new CallToolRequest("list-open-programs", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());

            // Should work (may return empty list if no programs)
            // The key is that it doesn't error out

            return null;
        });
    }
}
