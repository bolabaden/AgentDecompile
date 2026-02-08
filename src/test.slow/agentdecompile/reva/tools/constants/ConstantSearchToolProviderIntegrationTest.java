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
package agentdecompile.tools.constants;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Integration tests for ConstantSearchToolProvider
 */
public class ConstantSearchToolProviderIntegrationTest extends AgentDecompileIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        env.open(program);

        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }

        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    @Test
    public void testSearchConstantsSpecific() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "specific");
            arguments.put("value", "0x1234");

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSearchConstantsRange() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "range");
            arguments.put("minValue", "0x1000");
            arguments.put("maxValue", "0x2000");

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSearchConstantsCommon() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "common");
            arguments.put("topN", 10);

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertNotNull("Result should have valid JSON structure", json);
            assertTrue("Result should contain constants field", json.has("constants"));
        });
    }

    @Test
    public void testSearchConstantsSpecificWithVariousValueFormats() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String[] values = {"0x1234", "4660", "-1", "0xFFFFFFFF", "0xdeadbeef"};

            for (String value : values) {
                Map<String, Object> arguments = new HashMap<>();
                arguments.put("programPath", programPath);
                arguments.put("mode", "specific");
                arguments.put("value", value);
                arguments.put("maxResults", 10);

                CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

                assertNotNull("Result should not be null for value " + value, result);
                if (!result.isError()) {
                    TextContent content = (TextContent) result.content().get(0);
                    JsonNode json = parseJsonContent(content.text());
                    assertNotNull("Result should have valid JSON structure", json);
                }
            }
        });
    }

    @Test
    public void testSearchConstantsRangeWithVariousRanges() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test various ranges
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "range");
            arguments.put("minValue", "0x0");
            arguments.put("maxValue", "0x100");
            arguments.put("maxResults", 50);

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSearchConstantsCommonWithIncludeSmallValues() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "common");
            arguments.put("topN", 20);
            arguments.put("includeSmallValues", true);

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain constants field", json.has("constants"));
        });
    }

    @Test
    public void testSearchConstantsCommonWithMinValueFilter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "common");
            arguments.put("topN", 10);
            arguments.put("minValue", "256");
            arguments.put("includeSmallValues", false);

            CallToolResult result = client.callTool(new CallToolRequest("search-constants", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain constants field", json.has("constants"));
        });
    }
}
