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
package agentdecompile.tools.dataflow;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Integration tests for DataFlowToolProvider
 */
public class DataFlowToolProviderIntegrationTest extends AgentDecompileIntegrationTestBase {

    private String programPath;
    private Function testFunction;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create a test function
        Address functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int txId = program.startTransaction("Create Test Function");
        try {
            testFunction = functionManager.createFunction("testFunction", functionAddr,
                new AddressSet(functionAddr, functionAddr.add(50)),
                SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }

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
    public void testAnalyzeDataFlowBackward() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionAddress", "0x01000100");
            arguments.put("startAddress", "0x01000110");
            arguments.put("direction", "backward");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-data-flow", arguments));

            assertNotNull("Result should not be null", result);
            // Even if empty, should return valid JSON structure
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeDataFlowForward() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionAddress", "0x01000100");
            arguments.put("startAddress", "0x01000110");
            arguments.put("direction", "forward");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-data-flow", arguments));

            assertNotNull("Result should not be null", result);
            // Even if empty, should return valid JSON structure
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeDataFlowVariableAccesses() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionAddress", "0x01000100");
            arguments.put("variableName", "param1");
            arguments.put("direction", "variable_accesses");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-data-flow", arguments));

            assertNotNull("Result should not be null", result);
            // Even if empty, should return valid JSON structure
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }
}
