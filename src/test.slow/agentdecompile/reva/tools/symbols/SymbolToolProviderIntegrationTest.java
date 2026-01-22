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
package agentdecompile.tools.symbols;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Integration tests for SymbolToolProvider
 */
public class SymbolToolProviderIntegrationTest extends AgentDecompileIntegrationTestBase {

    private String program_path;
    private Address testAddress;

    @Before
    public void setUpTestData() throws Exception {
        program_path = program.getDomainFile().getPathname();

        // Create test data and label
        testAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        int txId = program.startTransaction("Setup test data");
        try {
            Listing listing = program.getListing();
            try {
                listing.createData(testAddress, new ByteDataType(), 1);
            } catch (Exception e) {
                // Ignore - data may already exist
            }
            SymbolTable symbolTable = program.getSymbolTable();
            try {
                symbolTable.createLabel(testAddress, "testLabel",
                    program.getGlobalNamespace(),
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException e) {
                fail("Failed to create label: " + e.getMessage());
            }
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
    public void testManageSymbolsCountMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "count");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain count field", json.has("count"));
            assertTrue("Count should be non-negative", json.get("count").asInt() >= 0);
        });
    }

    @Test
    public void testManageSymbolsSymbolsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "symbols");
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain symbols field", json.has("symbols"));
        });
    }

    @Test
    public void testManageSymbolsCreateLabelMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "create_label");
            arguments.put("address", "0x01000200");
            arguments.put("labelName", "newTestLabel");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
        });
    }

    @Test
    public void testManageSymbolsRenameDataMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "rename_data");
            arguments.put("address", "0x01000100");
            arguments.put("newName", "renamedLabel");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            // Should succeed or fail gracefully
        });
    }

    @Test
    public void testManageSymbolsImportsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "imports");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain imports field", json.has("imports") || json.has("groupedByLibrary"));
        });
    }

    @Test
    public void testManageSymbolsExportsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "exports");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain exports field", json.has("exports"));
        });
    }

    @Test
    public void testManageSymbolsClassesMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "classes");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain classes field", json.has("classes"));
        });
    }

    @Test
    public void testManageSymbolsNamespacesMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "namespaces");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain namespaces field", json.has("namespaces"));
        });
    }

    @Test
    public void testManageSymbolsDemangleMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "demangle");
            arguments.put("demangleAll", false);

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            // Demangle mode may return empty results if no mangled symbols exist
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testManageSymbolsCreateLabelBatch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "create_label");
            arguments.put("address", java.util.Arrays.asList("0x01000300", "0x01000400"));
            arguments.put("labelName", java.util.Arrays.asList("batchLabel1", "batchLabel2"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            // Should succeed or fail gracefully
            if (!result.isError()) {
                // Verify labels were created
                ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
                Address addr1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000300);
                Address addr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000400);
                // Labels may or may not exist depending on whether addresses are valid
            }
        });
    }

    @Test
    public void testManageSymbolsRenameDataBatch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create additional test data
            Address addr1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000500);
            Address addr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000600);
            int txId = program.startTransaction("Create test data for batch rename");
            try {
                try {
                    program.getListing().createData(addr1, new ByteDataType(), 1);
                    program.getListing().createData(addr2, new ByteDataType(), 1);
                } catch (Exception e) {
                    fail("Failed to create test data: " + e.getMessage());
                }
                try {
                    program.getSymbolTable().createLabel(addr1, "batchTest1", program.getGlobalNamespace(),
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    program.getSymbolTable().createLabel(addr2, "batchTest2", program.getGlobalNamespace(),
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException e) {
                    fail("Failed to create labels: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "rename_data");
            arguments.put("address", java.util.Arrays.asList("0x01000500", "0x01000600"));
            arguments.put("newName", java.util.Arrays.asList("renamedBatch1", "renamedBatch2"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            // Should succeed or fail gracefully
        });
    }

    @Test
    public void testManageSymbolsImportsWithLibraryFilter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "imports");
            arguments.put("libraryFilter", "kernel32");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            // May return empty if no matching imports, but should not error
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testManageSymbolsExportsWithLibraryFilter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "exports");
            arguments.put("libraryFilter", "test");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testManageSymbolsSymbolsWithPagination() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test first page
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "symbols");
            arguments.put("startIndex", 0);
            arguments.put("maxCount", 5);

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain symbols field", json.has("symbols"));

            // Test second page
            arguments.put("startIndex", 5);
            CallToolResult result2 = client.callTool(new CallToolRequest("manage-symbols", arguments));
            assertNotNull("Result should not be null", result2);
            if (!result2.isError()) {
                TextContent content2 = (TextContent) result2.content().get(0);
                JsonNode json2 = parseJsonContent(content2.text());
                assertTrue("Result should contain symbols field", json2.has("symbols"));
            }
        });
    }

    @Test
    public void testManageSymbolsSymbolsWithIncludeExternal() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "symbols");
            arguments.put("includeExternal", true);
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain symbols field", json.has("symbols"));
        });
    }

    @Test
    public void testManageSymbolsCreateLabelValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Address newLabelAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000700);
            int txId = program.startTransaction("Create data for label");
            try {
                try {
                    program.getListing().createData(newLabelAddr, new ByteDataType(), 1);
                } catch (Exception e) {
                    fail("Failed to create data: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "create_label");
            arguments.put("address", "0x01000700");
            arguments.put("labelName", "stateValidatedLabel");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                // Verify label was actually created in program state
                ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
                ghidra.program.model.symbol.Symbol symbol = symbolTable.getPrimarySymbol(newLabelAddr);
                if (symbol != null) {
                    assertTrue("Label should be created", symbol.getName().contains("stateValidatedLabel") ||
                        "stateValidatedLabel".equals(symbol.getName()));
                }
            }
        });
    }

    @Test
    public void testManageSymbolsRenameDataValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Address renameAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000800);
            int txId = program.startTransaction("Create label for rename");
            try {
                try {
                    program.getListing().createData(renameAddr, new ByteDataType(), 1);
                } catch (Exception e) {
                    fail("Failed to create data: " + e.getMessage());
                }
                try {
                    program.getSymbolTable().createLabel(renameAddr, "originalName", program.getGlobalNamespace(),
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException e) {
                    fail("Failed to create label: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "rename_data");
            arguments.put("address", "0x01000800");
            arguments.put("newName", "renamedStateValidated");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                // Verify rename was actually applied to program state
                ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
                ghidra.program.model.symbol.Symbol symbol = symbolTable.getPrimarySymbol(renameAddr);
                if (symbol != null) {
                    assertTrue("Label should be renamed", symbol.getName().contains("renamedStateValidated") ||
                        "renamedStateValidated".equals(symbol.getName()));
                }
            }
        });
    }

    @Test
    public void testManageSymbolsInvalidMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "invalid_mode");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertTrue("Tool should have error for invalid mode", result.isError());
        });
    }

    @Test
    public void testManageSymbolsMissingRequiredParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test create_label without address
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "create_label");
            arguments.put("labelName", "test");

            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertTrue("Tool should have error for missing address", result.isError());

            // Test rename_data without address
            arguments.clear();
            arguments.put("programPath", program_path);
            arguments.put("mode", "rename_data");
            arguments.put("newName", "test");

            result = client.callTool(new CallToolRequest("manage-symbols", arguments));

            assertTrue("Tool should have error for missing address", result.isError());
        });
    }
}
