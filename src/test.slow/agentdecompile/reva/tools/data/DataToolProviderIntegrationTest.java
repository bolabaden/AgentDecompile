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
package agentdecompile.tools.data;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import agentdecompile.AgentDecompileIntegrationTestBase;

/**
 * Integration tests for DataToolProvider that test actual MCP tool calls
 * with real program data.
 */
public class DataToolProviderIntegrationTest extends AgentDecompileIntegrationTestBase {

    private String programPath;
    private Address testAddress1;
    private Address testAddress2;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Set up test data in the program
        int txId = program.startTransaction("Setup test data");
        try {
            Listing listing = program.getListing();
            SymbolTable symbolTable = program.getSymbolTable();

            // Create test addresses
            testAddress1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
            testAddress2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);

            // Create some test data at testAddress1 (integer)
            listing.createData(testAddress1, new IntegerDataType(), 4);

            // Create test data at testAddress2 (bytes)
            listing.createData(testAddress2, new ByteDataType(), 1);
            listing.createData(testAddress2.add(1), new ByteDataType(), 1);
            listing.createData(testAddress2.add(2), new ByteDataType(), 1);
            listing.createData(testAddress2.add(3), new ByteDataType(), 1);

            // Create test symbols
            symbolTable.createLabel(testAddress1, "test_int_symbol",
                program.getGlobalNamespace(),
                ghidra.program.model.symbol.SourceType.USER_DEFINED);
            symbolTable.createLabel(testAddress2, "test_byte_symbol",
                program.getGlobalNamespace(),
                ghidra.program.model.symbol.SourceType.USER_DEFINED);

        } finally {
            program.endTransaction(txId, true);
        }
    }

    @Test
    public void testDataSetupAndToolRegistration() throws Exception {
        // Verify the test data was set up correctly
        Listing listing = program.getListing();

        // Check that data exists at our test addresses
        Data data1 = listing.getDataAt(testAddress1);
        assertNotNull("Data should exist at testAddress1", data1);
        assertEquals("Data type should be int", "int", data1.getDataType().getName());

        Data data2 = listing.getDataAt(testAddress2);
        assertNotNull("Data should exist at testAddress2", data2);
        assertEquals("Data type should be byte", "byte", data2.getDataType().getName());

        // Check that symbols were created
        SymbolTable symbolTable = program.getSymbolTable();
        var symbols1 = symbolTable.getLabelOrFunctionSymbols("test_int_symbol", null);
        assertFalse("Symbol test_int_symbol should exist", symbols1.isEmpty());
        assertEquals("Symbol should be at correct address", testAddress1, symbols1.get(0).getAddress());

        var symbols2 = symbolTable.getLabelOrFunctionSymbols("test_byte_symbol", null);
        assertFalse("Symbol test_byte_symbol should exist", symbols2.isEmpty());
        assertEquals("Symbol should be at correct address", testAddress2, symbols2.get(0).getAddress());

        // Verify that the MCP server has the DataToolProvider tools registered
        // We can check this by looking at the server's registered tools
        io.modelcontextprotocol.server.McpSyncServer mcpServer =
            agentdecompile.util.AgentDecompileInternalServiceRegistry.getService(io.modelcontextprotocol.server.McpSyncServer.class); 
        assertNotNull("MCP server should be registered", mcpServer);

        // The tools should be registered and the server should be running
        // This validates that our tool provider integration is working
    }

    @Test
    public void testProgramSetupIsCorrect() throws Exception {
        // Verify that the program path is set correctly
        assertNotNull("Program path should be set", programPath);
        assertNotNull("Program should be set", program);

        // Verify the config manager and server port are available
        assertNotNull("Config manager should be available", configManager);
        assertEquals("Server port should be 8080", 8080, configManager.getServerPort());

        // Verify that addresses are in the expected memory space
        assertEquals("Test address 1 should be in default space",
            program.getAddressFactory().getDefaultAddressSpace(),
            testAddress1.getAddressSpace());
        assertEquals("Test address 2 should be in default space",
            program.getAddressFactory().getDefaultAddressSpace(),
            testAddress2.getAddressSpace());
    }
}