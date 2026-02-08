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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.tools.ProgramValidationException;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.DataTypeParserUtil;

/**
 * Tool provider for accessing data at specific addresses or by symbol names in programs.
 *
 * NOTE: The tools in this provider were removed/consolidated but are kept here as disabled
 * for compatibility with the upstream repository.
 *
 * Helper methods are kept accessible (protected) so they can be reused by other tools
 * and benefit from upstream updates to the disabled tool handlers.
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Listing}, {@link ghidra.program.model.listing.Data} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html">Listing API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html">SymbolTable API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class DataToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DataToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        // DISABLED: Legacy tools - kept for compatibility with upstream repo
        // These tools were removed but kept here as disabled
        // registerGetDataTool();  // DISABLED - functionality may be available elsewhere
        // registerApplyDataTypeTool();  // DISABLED - functionality may be available elsewhere
        // registerCreateLabelTool();  // DISABLED - functionality may be available elsewhere
    }

    /**
     * DISABLED: Legacy tool - kept for compatibility with upstream repo.
     * Original tool: get-data
     */
    /*
    private void registerGetDataTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the data"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to get data from (e.g., '0x00400000' or 'main')"
        ));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-data")
            .title("Get Data")
            .description("Get data at a specific address or symbol in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and address using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");

            return getDataAtAddressResult(program, address);
        });
    }
    */

    /**
     * DISABLED: Legacy tool - kept for compatibility with upstream repo.
     * Original tool: apply-data-type
     */
    /*
    private void registerApplyDataTypeTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to apply the data type to (e.g., '0x00400000' or 'main')"
        ));
        properties.put("dataTypeString", Map.of(
            "type", "string",
            "description", "String representation of the data type (e.g., 'char**', 'int[10]')"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search in. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "dataTypeString");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("apply-data-type")
            .title("Apply Data Type")
            .description("Apply a data type to a specific address or symbol in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Address targetAddress = getAddressFromArgs(request, program, "addressOrSymbol");
            String dataTypeString = getString(request, "dataTypeString");
            String archiveName = getOptionalString(request, "archiveName", "");

            if (dataTypeString.trim().isEmpty()) {
                return createErrorResult("Data type string cannot be empty");
            }

            try {
                // Try to parse the data type from the string and get the actual DataType object
                DataType dataType;
                try {
                    dataType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
                    if (dataType == null) {
                        return createErrorResult("Could not find data type: " + dataTypeString +
                            ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                    }
                } catch (Exception e) {
                    return createErrorResult("Error parsing data type: " + e.getMessage() +
                        ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                }

                // Start a transaction to apply the data type
                int transactionID = program.startTransaction("Apply Data Type");
                boolean success = false;

                try {
                    // Get the listing and apply the data type at the symbol's address
                    Listing listing = program.getListing();

                    // Clear any existing data at the address
                    if (listing.getDataAt(targetAddress) != null) {
                        listing.clearCodeUnits(targetAddress, targetAddress.add(dataType.getLength() - 1), false);
                    }

                    // Create the data at the address with the specified data type
                    Data createdData = listing.createData(targetAddress, dataType);

                    if (createdData == null) {
                        throw new Exception("Failed to create data at address: " + targetAddress);
                    }

                    success = true;

                    // Create result data
                    Map<String, Object> resultData = new HashMap<>();
                    resultData.put("success", true);
                    resultData.put("address", "0x" + targetAddress.toString());
                    resultData.put("dataType", dataType.getName());
                    resultData.put("dataTypeDisplayName", dataType.getDisplayName());
                    resultData.put("length", dataType.getLength());

                    return createJsonResult(resultData);
                } finally {
                    // End transaction
                    program.endTransaction(transactionID, success);
                }
            } catch (Exception e) {
                return createErrorResult("Error applying data type to symbol: " + e.getMessage());
            }
        });
    }
    */

    /**
     * DISABLED: Legacy tool - kept for compatibility with upstream repo.
     * Original tool: create-label
     */
    /*
    private void registerCreateLabelTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the address"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to create label at (e.g., '0x00400000' or 'main')"
        ));
        properties.put("labelName", Map.of(
            "type", "string",
            "description", "Name for the label to create"
        ));
        properties.put("setAsPrimary", Map.of(
            "type", "boolean",
            "description", "Whether to set this label as primary if other labels exist at the address",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "labelName");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-label")
            .title("Create Label")
            .description("Create a label at a specific address in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program;
            String labelName;
            Address address;
            try {
                program = getProgramFromArgs(request);
                labelName = getString(request, "labelName");
                address = getAddressFromArgs(request, program, "addressOrSymbol");
            } catch (IllegalArgumentException | ProgramValidationException e) {
                // Try to return default response with error message
                Program program = tryGetProgramSafely(request.arguments());
                if (program != null) {
                    // Return empty result with error message
                    Map<String, Object> errorInfo = createIncorrectArgsErrorMap();
                    Map<String, Object> result = new HashMap<>();
                    result.put("error", errorInfo.get("error"));
                    result.put("programPath", program.getDomainFile().getPathname());
                    return createJsonResult(result);
                }
                // If we can't get a default response, return error with message
                return createErrorResult(e.getMessage() + " " + createIncorrectArgsErrorMap().get("error"));
            }
            boolean setAsPrimary = getOptionalBoolean(request, "setAsPrimary", true);

            if (labelName.trim().isEmpty()) {
                return createErrorResult("Label name cannot be empty");
            }

            // Start a transaction to create the label
            int transactionID = program.startTransaction("Create Label");
            boolean success = false;

            try {
                // Get the symbol table
                SymbolTable symbolTable = program.getSymbolTable();

                // Create the label
                Symbol symbol = symbolTable.createLabel(address, labelName,
                    program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

                if (symbol == null) {
                    throw new Exception("Failed to create label at address: " + address);
                }

                // Set the label as primary if requested
                if (setAsPrimary && !symbol.isPrimary()) {
                    symbol.setPrimary();
                }

                success = true;

                // Create result data
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("success", true);
                resultData.put("labelName", labelName);
                resultData.put("address", "0x" + address.toString());
                resultData.put("isPrimary", symbol.isPrimary());

                return createJsonResult(resultData);
            } catch (Exception e) {
                return createErrorResult("Error creating label: " + e.getMessage());
            } finally {
                // End transaction
                program.endTransaction(transactionID, success);
            }
        });
    }
    */

    /**
     * Helper method to get data at a specific address and format the result.
     *
     * NOTE: This method is kept for upstream compatibility and future use.
     * When upstream updates the disabled get-data tool handler, update this method accordingly.
     *
     * @param program The program to look up data in
     * @param address The address where to find data
     * @return Call tool result with data information
     */
    protected CallToolResult getDataAtAddressResult(Program program, Address address) {
        // Get data at or containing the address
        Data data = AddressUtil.getContainingData(program, address);
        if (data == null) {
            return createErrorResult("No data found at address: " + AddressUtil.formatAddress(address));
        }

        // Create result data
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("address", AddressUtil.formatAddress(data.getAddress()));
        resultData.put("dataType", data.getDataType().getName());
        resultData.put("length", data.getLength());

        // Check if the address is for a symbol
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
        if (primarySymbol != null) {
            resultData.put("symbolName", primarySymbol.getName());
            resultData.put("symbolNamespace", primarySymbol.getParentNamespace().getName());
        }

        // Get the bytes and convert to hex
        StringBuilder hexString = new StringBuilder();
        try {
            byte[] bytes = data.getBytes();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            resultData.put("hexBytes", hexString.toString());
        } catch (MemoryAccessException e) {
            resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
        }

        // Get the string representation that would be shown in the listing
        String representation = data.getDefaultValueRepresentation();
        resultData.put("representation", representation);

        // Get the value object
        Object value = data.getValue();
        if (value != null) {
            resultData.put("valueType", value.getClass().getSimpleName());
            resultData.put("value", value.toString());
        } else {
            resultData.put("value", null);
        }

        try {
            List<Content> contents = new ArrayList<>();
            contents.add(new TextContent(JSON.writeValueAsString(resultData)));
            return new CallToolResult(contents, false);
        } catch (JsonProcessingException e) {
            return createErrorResult("Error converting data to JSON: " + e.getMessage());
        }
    }

    /**
     * Helper method to apply a data type at a specific address.
     *
     * NOTE: This method is kept for upstream compatibility and future use.
     * When upstream updates the disabled apply-data-type tool handler, update this method accordingly.
     *
     * @param program The program
     * @param targetAddress The address to apply the data type to
     * @param dataTypeString String representation of the data type
     * @param archiveName Optional archive name to search in
     * @return Call tool result with success status and data type information
     */
    protected McpSchema.CallToolResult applyDataTypeAtAddress(Program program, Address targetAddress, String dataTypeString, String archiveName) {
        if (dataTypeString.trim().isEmpty()) {
            return createErrorResult("Data type string cannot be empty");
        }

        try {
            // Try to parse the data type from the string and get the actual DataType object
            DataType dataType;
            try {
                dataType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
                if (dataType == null) {
                    return createErrorResult("Could not find data type: " + dataTypeString +
                        ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                }
            } catch (Exception e) {
                return createErrorResult("Error parsing data type: " + e.getMessage() +
                    ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
            }

            // Start a transaction to apply the data type
            // Ghidra API: Program.startTransaction(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int transactionID = program.startTransaction("Apply Data Type");
            boolean success = false;

            try {
                // Get the listing and apply the data type at the symbol's address
                // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
                Listing listing = program.getListing();

                // Clear any existing data at the address
                // Ghidra API: Listing.getDataAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getDataAt(ghidra.program.model.address.Address)
                if (listing.getDataAt(targetAddress) != null) {
                    // Ghidra API: Listing.clearCodeUnits(Address, Address, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#clearCodeUnits(ghidra.program.model.address.Address,ghidra.program.model.address.Address,boolean)
                    listing.clearCodeUnits(targetAddress, targetAddress.add(dataType.getLength() - 1), false);
                }

                // Create the data at the address with the specified data type
                // Ghidra API: Listing.createData(Address, DataType) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#createData(ghidra.program.model.address.Address,ghidra.program.model.data.DataType)
                Data createdData = listing.createData(targetAddress, dataType);

                if (createdData == null) {
                    throw new Exception("Failed to create data at address: " + targetAddress);
                }

                success = true;

                // Create result data
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("success", true);
                resultData.put("address", AddressUtil.formatAddress(targetAddress));
                resultData.put("dataType", dataType.getName());
                resultData.put("dataTypeDisplayName", dataType.getDisplayName());
                resultData.put("length", dataType.getLength());

                return createJsonResult(resultData);
            } finally {
                // End transaction
                // Ghidra API: Program.endTransaction(int, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionID, success);
            }
        } catch (Exception e) {
            return createErrorResult("Error applying data type to symbol: " + e.getMessage());
        }
    }

    /**
     * Helper method to create a label at a specific address.
     *
     * NOTE: This method is kept for upstream compatibility and future use.
     * When upstream updates the disabled create-label tool handler, update this method accordingly.
     *
     * @param program The program
     * @param address The address to create the label at
     * @param labelName The name for the label
     * @param setAsPrimary Whether to set the label as primary
     * @return Call tool result with success status and label information
     */
    protected McpSchema.CallToolResult createLabelAtAddress(Program program, Address address, String labelName, boolean setAsPrimary) {
        if (labelName.trim().isEmpty()) {
            return createErrorResult("Label name cannot be empty");
        }

        // Start a transaction to create the label
        // Ghidra API: Program.startTransaction(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
        int transactionID = program.startTransaction("Create Label");
        boolean success = false;

        try {
            // Get the symbol table
            // Ghidra API: Program.getSymbolTable() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
            SymbolTable symbolTable = program.getSymbolTable();

            // Create the label
            // Ghidra API: SymbolTable.createLabel(Address, String, Namespace, SourceType), Program.getGlobalNamespace() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html#createLabel(ghidra.program.model.address.Address,java.lang.String,ghidra.program.model.symbol.Namespace,ghidra.program.model.symbol.SourceType)
            Symbol symbol = symbolTable.createLabel(address, labelName,
                program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

            if (symbol == null) {
                throw new Exception("Failed to create label at address: " + address);
            }

            // Set the label as primary if requested
            // Ghidra API: Symbol.isPrimary(), Symbol.setPrimary() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html#isPrimary()
            if (setAsPrimary && !symbol.isPrimary()) {
                symbol.setPrimary();
            }

            success = true;

            // Create result data
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("labelName", labelName);
            resultData.put("address", AddressUtil.formatAddress(address));
            // Ghidra API: Symbol.isPrimary() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html#isPrimary()
            resultData.put("isPrimary", symbol.isPrimary());

            return createJsonResult(resultData);
        } catch (Exception e) {
            return createErrorResult("Error creating label: " + e.getMessage());
        } finally {
            // End transaction
            // Ghidra API: Program.endTransaction(int, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
            program.endTransaction(transactionID, success);
        }
    }
}
