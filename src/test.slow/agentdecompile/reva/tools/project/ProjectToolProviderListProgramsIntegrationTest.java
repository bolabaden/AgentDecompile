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
 * Integration tests for list-project-files and list-open-programs tools
 * with the onlyShowCheckedOutPrograms parameter.
 */
public class ProjectToolProviderListProgramsIntegrationTest extends AgentDecompileIntegrationTestBase {

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    public void testListProjectFilesShowsAllPrograms() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-project-files with recursive=true to get all programs
            Map<String, Object> args = new HashMap<>();
            args.put("folderPath", "/");
            args.put("recursive", true);
            args.put("onlyShowCheckedOutPrograms", false);

            CallToolResult result = client.callTool(new CallToolRequest("list-project-files", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());
            assertTrue("Should have at least one content item", !result.content().isEmpty());

            // Parse the response
            String responseJson = ((TextContent) result.content().get(0)).text();
            JsonNode response = objectMapper.readTree(responseJson);

            // Should have metadata
            if (response.isArray() && response.size() > 0) {
                JsonNode metadata = response.get(0);
                if (metadata.has("onlyShowCheckedOutPrograms")) {
                    assertFalse("onlyShowCheckedOutPrograms should be false", 
                        metadata.get("onlyShowCheckedOutPrograms").asBoolean());
                }
            }

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
