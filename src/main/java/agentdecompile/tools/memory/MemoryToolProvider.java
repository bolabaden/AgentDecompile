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
package agentdecompile.tools.memory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.MemoryUtil;
import agentdecompile.util.SchemaUtil;

/**
 * Tool provider for memory-related operations.
 * Provides tools to list memory blocks and read memory content.
 * <p>
 * Ghidra API: {@link ghidra.program.model.mem.Memory}, {@link ghidra.program.model.mem.MemoryBlock} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html">Memory API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html">MemoryBlock API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class MemoryToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public MemoryToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerInspectMemoryTool();
    }

    private void registerInspectMemoryTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Inspection mode: 'blocks', 'read', 'data_at', 'data_items', or 'segments'",
            "enum", List.of("blocks", "read", "data_at", "data_items", "segments")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)"));
        properties.put("length", SchemaUtil.integerPropertyWithDefault("Number of bytes to read when mode='read'", 16));
        properties.put("offset", SchemaUtil.integerPropertyWithDefault("Pagination offset when mode='data_items' or 'segments'", 0));
        properties.put("limit", SchemaUtil.integerPropertyWithDefault("Maximum number of items to return when mode='data_items' or 'segments'", 100));

        List<String> required = List.of("programPath", "mode");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("inspect-memory")
            .title("Inspect Memory")
            .description("Inspect memory blocks, read memory, get data information, list data items, or list memory segments.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getString(request, "mode");

                switch (mode) {
                    case "blocks":
                        return handleBlocksMode(program);
                    case "read":
                        return handleReadMode(program, request);
                    case "data_at":
                        return handleDataAtMode(program, request);
                    case "data_items":
                        return handleDataItemsMode(program, request);
                    case "segments":
                        return handleSegmentsMode(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: blocks, read, data_at, data_items, segments");
                }
            } catch (IllegalArgumentException e) {
                // Try to return default response with error message
                Program program = tryGetProgramSafely(request.arguments());
                if (program != null) {
                    // Return "blocks" mode as default with error message
                    Map<String, Object> errorInfo = createIncorrectArgsErrorMap();
                    McpSchema.CallToolResult defaultResult = handleBlocksMode(program);
                    // Prepend error message to result
                    if (defaultResult.content() != null && !defaultResult.content().isEmpty()) {
                        try {
                            String jsonText = extractTextFromContent(defaultResult.content().get(0));
                            @SuppressWarnings("unchecked")
                            Map<String, Object> data = JSON.readValue(jsonText, Map.class);
                            data.put("error", errorInfo.get("error"));
                            return createJsonResult(data);
                        } catch (JsonProcessingException ex) {
                            // If we can't modify, return error with default response
                            List<Object> resultData = new ArrayList<>();
                            resultData.add(errorInfo);
                            resultData.add(extractTextFromContent(defaultResult.content().get(0)));
                            return createMultiJsonResult(resultData);
                        }
                    }
                    return defaultResult;
                }
                // If we can't get a default response, return error with message
                return createErrorResult(e.getMessage() + " " + createIncorrectArgsErrorMap().get("error"));
            } catch (Exception e) {
                logError("Error in inspect-memory", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleBlocksMode(Program program) {
        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        List<Map<String, Object>> blockData = new ArrayList<>();

        // Ghidra API: Memory.getBlocks() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBlocks()
        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> blockInfo = new HashMap<>();
            // Ghidra API: MemoryBlock.getName(), getStart(), getEnd(), getSize(), isRead(), isWrite(), isExecute(), isInitialized(), isVolatile(), isMapped(), isOverlay() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html
            blockInfo.put("name", block.getName());
            blockInfo.put("start", AddressUtil.formatAddress(block.getStart()));
            blockInfo.put("end", AddressUtil.formatAddress(block.getEnd()));
            blockInfo.put("size", block.getSize());
            blockInfo.put("readable", block.isRead());
            blockInfo.put("writable", block.isWrite());
            blockInfo.put("executable", block.isExecute());
            blockInfo.put("initialized", block.isInitialized());
            blockInfo.put("volatile", block.isVolatile());
            blockInfo.put("mapped", block.isMapped());
            blockInfo.put("overlay", block.isOverlay());
            blockData.add(blockInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("blocks", blockData);
        result.put("count", blockData.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleReadMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='read'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        int length = getOptionalInt(request, "length", 16);
        if (length <= 0) {
            return createErrorResult("Invalid length: " + length);
        }
        if (length > 10000) {
            length = 10000; // Limit to prevent huge responses
        }

        byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
        if (bytes == null) {
            return createErrorResult("Memory access error at address: " + AddressUtil.formatAddress(address));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("address", AddressUtil.formatAddress(address));
        result.put("length", bytes.length);
        String hexString = MemoryUtil.formatHexString(bytes);
        result.put("hex", hexString);
        result.put("hexDump", hexString);
        result.put("data", hexString);
        result.put("ascii", MemoryUtil.formatAsciiString(bytes));
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleDataAtMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='data_at'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        Data data = AddressUtil.getContainingData(program, address);
        if (data == null) {
            return createErrorResult("No data found at address: " + AddressUtil.formatAddress(address));
        }

        Map<String, Object> resultData = new HashMap<>();
        // Ghidra API: Data.getAddress(), getDataType(), getName(), getLength() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Data.html
        resultData.put("address", AddressUtil.formatAddress(data.getAddress()));
        resultData.put("dataType", data.getDataType().getName());
        resultData.put("length", data.getLength());

        // Ghidra API: Program.getSymbolTable() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
        SymbolTable symbolTable = program.getSymbolTable();
        // Ghidra API: SymbolTable.getPrimarySymbol(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html#getPrimarySymbol(ghidra.program.model.address.Address)
        Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
        if (primarySymbol != null) {
            // Ghidra API: Symbol.getName(), Symbol.getParentNamespace(), Namespace.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html#getName()
            resultData.put("symbolName", primarySymbol.getName());
            resultData.put("symbolNamespace", primarySymbol.getParentNamespace().getName());
        }

        StringBuilder hexString = new StringBuilder();
        try {
            // Ghidra API: Data.getBytes() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Data.html#getBytes()
            byte[] bytes = data.getBytes();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            resultData.put("hexBytes", hexString.toString());
        } catch (MemoryAccessException e) {
            resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
        }

        // Ghidra API: Data.getDefaultValueRepresentation() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html#getDefaultValueRepresentation()
        String representation = data.getDefaultValueRepresentation();
        resultData.put("representation", representation);

        // Ghidra API: Data.getValue() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html#getValue()
        Object value = data.getValue();
        if (value != null) {
            resultData.put("valueType", value.getClass().getSimpleName());
            resultData.put("value", value.toString());
        } else {
            resultData.put("value", null);
        }

        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleDataItemsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();
        List<Map<String, Object>> dataItems = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        // Ghidra API: Listing.getDefinedData(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getDefinedData(boolean)
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && dataItems.size() < limit) {
            // Ghidra API: DataIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/DataIterator.html#next()
            Data data = dataIter.next();
            count++;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            Map<String, Object> item = new HashMap<>();
            // Ghidra API: Data.getAddress(), getDataType(), getName(), getLength(), getDefaultValueRepresentation() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Data.html
            item.put("address", AddressUtil.formatAddress(data.getAddress()));
            item.put("dataType", data.getDataType().getName());
            item.put("length", data.getLength());
            item.put("representation", data.getDefaultValueRepresentation());

            // Ghidra API: Program.getSymbolTable() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
            SymbolTable symbolTable = program.getSymbolTable();
            // Ghidra API: SymbolTable.getPrimarySymbol(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html#getPrimarySymbol(ghidra.program.model.address.Address)
            Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
            if (primarySymbol != null) {
                item.put("label", primarySymbol.getName());
            }

            // Ghidra API: Data.getValue() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html#getValue() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Data.html#getValue()
            Object value = data.getValue();
            if (value != null) {
                item.put("value", value.toString());
            }

            dataItems.add(item);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("dataItems", dataItems);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("returned", dataItems.size());
        result.put("hasMore", dataIter.hasNext());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSegmentsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        List<MemoryBlock> allBlocks = new ArrayList<>();
        // Ghidra API: Memory.getBlocks() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBlocks()
        for (MemoryBlock block : memory.getBlocks()) {
            allBlocks.add(block);
        }

        List<Map<String, Object>> segments = new ArrayList<>();
        int endIndex = Math.min(offset + limit, allBlocks.size());
        for (int i = offset; i < endIndex; i++) {
            MemoryBlock block = allBlocks.get(i);
            Map<String, Object> segmentInfo = new HashMap<>();
            // Ghidra API: MemoryBlock.getName(), getStart(), getEnd(), getSize(), isRead(), isWrite(), isExecute() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html
            segmentInfo.put("name", block.getName());
            segmentInfo.put("start", AddressUtil.formatAddress(block.getStart()));
            segmentInfo.put("end", AddressUtil.formatAddress(block.getEnd()));
            segmentInfo.put("size", block.getSize());
            segmentInfo.put("readable", block.isRead());
            segmentInfo.put("writable", block.isWrite());
            segmentInfo.put("executable", block.isExecute());
            segments.add(segmentInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("segments", segments);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("totalCount", allBlocks.size());
        result.put("hasMore", endIndex < allBlocks.size());
        return createJsonResult(result);
    }


}
