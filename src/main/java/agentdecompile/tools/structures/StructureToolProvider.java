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
package agentdecompile.tools.structures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.tools.ProgramValidationException;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.DataTypeParserUtil;
import agentdecompile.util.SchemaUtil;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;

/**
 * Tool provider for structure definition and manipulation operations.
 * Provides tools to create, modify, and apply structures in Ghidra programs.
 * <p>
 * Ghidra API: {@link ghidra.program.model.data.Structure}, {@link ghidra.program.model.data.DataTypeManager},
 * {@link ghidra.app.util.cparser.C.CParser}, {@link ghidra.util.data.DataTypeParser} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html">Structure API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html">Listing API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class StructureToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public StructureToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageStructuresTool();
    }

    private void registerManageStructuresTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', 'parse_header'",
            "enum", List.of("parse", "validate", "create", "add_field", "modify_field", "modify_from_c", "info", "list", "apply", "delete", "parse_header")
        ));
        properties.put("cDefinition", SchemaUtil.stringProperty("C-style structure definition when action='parse', 'validate', or 'modify_from_c' (single structure mode)"));
        properties.put("cDefinitions", Map.of(
            "type", "array",
            "description", "Array of C-style structure definitions for batch parse operation when action='parse'",
            "items", Map.of("type", "string")
        ));
        properties.put("headerContent", SchemaUtil.stringProperty("C header file content when action='parse_header'"));
        properties.put("structureName", SchemaUtil.stringProperty("Name of the structure"));
        properties.put("name", SchemaUtil.stringProperty("Name of the structure when action='create' (single structure mode)"));
        properties.put("size", SchemaUtil.integerPropertyWithDefault("Initial size when action='create'", 0));
        properties.put("type", Map.of(
            "type", "string",
            "description", "Structure type when action='create'",
            "enum", List.of("structure", "union"),
            "default", "structure"
        ));
        
        // Add structures array for batch create operations
        Map<String, Object> structureObjectSchema = new HashMap<>();
        structureObjectSchema.put("type", "object");
        structureObjectSchema.put("description", "Structure definition with name, size, type, category, packed, description, and optional fields array");
        Map<String, Object> structureObjectProperties = new HashMap<>();
        structureObjectProperties.put("name", SchemaUtil.stringProperty("Name of the structure"));
        structureObjectProperties.put("size", SchemaUtil.integerProperty("Initial size (optional, default: 0)"));
        structureObjectProperties.put("type", SchemaUtil.stringProperty("Structure type: 'structure' or 'union' (optional, default: 'structure')"));
        structureObjectProperties.put("category", SchemaUtil.stringProperty("Category path (optional, default: '/')"));
        structureObjectProperties.put("packed", SchemaUtil.booleanProperty("Whether structure should be packed (optional, default: false)"));
        structureObjectProperties.put("description", SchemaUtil.stringProperty("Description of the structure (optional)"));
        structureObjectProperties.put("fields", Map.of(
            "type", "array",
            "description", "Array of fields to add during creation (optional)",
            "items", Map.of(
                "type", "object",
                "properties", Map.of(
                    "fieldName", Map.of("type", "string"),
                    "dataType", Map.of("type", "string"),
                    "offset", Map.of("type", "integer"),
                    "comment", Map.of("type", "string")
                ),
                "required", List.of("fieldName", "dataType")
            )
        ));
        structureObjectSchema.put("properties", structureObjectProperties);
        structureObjectSchema.put("required", List.of("name"));
        
        Map<String, Object> structuresArrayProperty = new HashMap<>();
        structuresArrayProperty.put("type", "array");
        structuresArrayProperty.put("description", "Array of structure definitions for batch create operations. Each structure object must have a name property.");
        structuresArrayProperty.put("items", structureObjectSchema);
        properties.put("structures", structuresArrayProperty);
        properties.put("category", SchemaUtil.stringPropertyWithDefault("Category path", "/"));
        properties.put("packed", SchemaUtil.booleanPropertyWithDefault("Whether structure should be packed when action='create'", false));
        properties.put("description", SchemaUtil.stringProperty("Description of the structure when action='create'"));
        properties.put("fieldName", SchemaUtil.stringProperty("Name of the field when action='add_field' or 'modify_field' (single field mode)"));
        properties.put("dataType", SchemaUtil.stringProperty("Data type when action='add_field' (single field mode)"));
        properties.put("offset", SchemaUtil.integerProperty("Field offset when action='add_field' or 'modify_field'"));
        properties.put("comment", SchemaUtil.stringProperty("Field comment when action='add_field'"));
        
        // Add fields array for batch add_field operations
        Map<String, Object> fieldObjectSchema = new HashMap<>();
        fieldObjectSchema.put("type", "object");
        fieldObjectSchema.put("description", "Field definition with fieldName, dataType, offset (optional), and comment (optional)");
        Map<String, Object> fieldObjectProperties = new HashMap<>();
        fieldObjectProperties.put("fieldName", SchemaUtil.stringProperty("Name of the field"));
        fieldObjectProperties.put("dataType", SchemaUtil.stringProperty("Data type of the field"));
        fieldObjectProperties.put("offset", SchemaUtil.integerProperty("Field offset (optional, omit to append)"));
        fieldObjectProperties.put("comment", SchemaUtil.stringProperty("Field comment (optional)"));
        fieldObjectSchema.put("properties", fieldObjectProperties);
        fieldObjectSchema.put("required", List.of("fieldName", "dataType"));
        
        Map<String, Object> fieldsArrayProperty = new HashMap<>();
        fieldsArrayProperty.put("type", "array");
        fieldsArrayProperty.put("description", "Array of field definitions for batch add_field operations. Each field object must have fieldName and dataType properties.");
        fieldsArrayProperty.put("items", fieldObjectSchema);
        properties.put("fields", fieldsArrayProperty);
        
        properties.put("newDataType", SchemaUtil.stringProperty("New data type for the field when action='modify_field'"));
        properties.put("newFieldName", SchemaUtil.stringProperty("New name for the field when action='modify_field'"));
        properties.put("newComment", SchemaUtil.stringProperty("New comment for the field when action='modify_field'"));
        properties.put("newLength", SchemaUtil.integerProperty("New length for the field when action='modify_field'"));
        Map<String, Object> addressOrSymbolProperty = new HashMap<>();
        addressOrSymbolProperty.put("type", "string");
        addressOrSymbolProperty.put("description", "Address or symbol name to apply structure to. Can be a single string or an array of strings for batch operations when action='apply'.");
        Map<String, Object> addressOrSymbolArraySchema = new HashMap<>();
        addressOrSymbolArraySchema.put("type", "array");
        addressOrSymbolArraySchema.put("items", Map.of("type", "string"));
        addressOrSymbolArraySchema.put("description", "Array of addresses or symbol names for batch operations");
        addressOrSymbolProperty.put("oneOf", List.of(
            Map.of("type", "string"),
            addressOrSymbolArraySchema
        ));
        properties.put("addressOrSymbol", addressOrSymbolProperty);
        properties.put("clearExisting", SchemaUtil.booleanPropertyWithDefault("Clear existing data when action='apply'", true));
        properties.put("force", SchemaUtil.booleanPropertyWithDefault("Force deletion even if structure is referenced when action='delete'", false));
        properties.put("nameFilter", SchemaUtil.stringProperty("Filter by name (substring match) when action='list'"));
        properties.put("includeBuiltIn", SchemaUtil.booleanPropertyWithDefault("Include built-in types when action='list'", false));
        properties.put("maxCount", SchemaUtil.integerPropertyWithDefault("Maximum number of data types to return when action='list'", 50));
        properties.put("startIndex", SchemaUtil.integerPropertyWithDefault("Starting index for pagination when action='list'", 0));
        properties.put("preserveSize", SchemaUtil.booleanPropertyWithDefault("When true, fails if batch add_field would grow structure beyond original size. Use with structures created with explicit size parameter.", false));
        properties.put("useReplace", SchemaUtil.booleanPropertyWithDefault("When true with add_field, use replaceAtOffset instead of insertAtOffset to avoid shifting/growing. Recommended for non-packed structures with explicit offsets.", true));

        List<String> required = List.of("programPath", "action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-structures")
            .title("Manage Structures")
            .description("Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String action = getString(request, "action");
                return switch (action) {
                    case "parse" -> {
                        // Check if cDefinitions array is provided (batch mode)
                        List<Object> cDefinitionsList = getParameterAsList(request.arguments(), "cDefinitions");
                        if (cDefinitionsList.size() > 1 || (!cDefinitionsList.isEmpty() && cDefinitionsList.get(0) instanceof List)) {
                            List<?> batchList = cDefinitionsList.size() > 1 ? cDefinitionsList : (List<?>) cDefinitionsList.get(0);
                            yield handleBatchParseStructures(request, batchList);
                        }
                        yield handleParseAction(request);
                    }
                    case "validate" -> handleValidateAction(request);
                    case "create" -> {
                        // Check if structures array is provided (batch mode)
                        List<Object> structuresList = getParameterAsList(request.arguments(), "structures");
                        if (structuresList.size() > 1 || (!structuresList.isEmpty() && structuresList.get(0) instanceof Map)) {
                            yield handleBatchCreateStructures(request, structuresList);
                        }
                        yield handleCreateAction(request);
                    }
                    case "add_field" -> handleAddFieldAction(request);
                    case "modify_field" -> handleModifyFieldAction(request);
                    case "modify_from_c" -> handleModifyFromCAction(request);
                    case "info" -> handleInfoAction(request);
                    case "list" -> handleListAction(request);
                    case "apply" -> handleApplyAction(request);
                    case "delete" -> {
                        // Check if structureNames array is provided (batch mode)
                        List<Object> structureNamesList = getParameterAsList(request.arguments(), "structureNames");
                        if (structureNamesList.size() > 1 || (!structureNamesList.isEmpty() && structureNamesList.get(0) instanceof List)) {
                            List<?> batchList = structureNamesList.size() > 1 ? structureNamesList : (List<?>) structureNamesList.get(0);
                            yield handleBatchDeleteStructures(request, batchList);
                        }
                        yield handleDeleteAction(request);
                    }
                    case "parse_header" -> handleParseHeaderAction(request);
                    default -> createErrorResult("Invalid action: " + action);
                };
            } catch (Exception e) {
                logError("Error in manage-structures", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleParseAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='parse'");
        }
        String category = getOptionalString(request, "category", "/");

        // Ghidra API: Program.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getDataTypeManager()
        DataTypeManager dtm = program.getDataTypeManager();
        CParser parser = new CParser(dtm);

        // Ghidra API: Program.startTransaction(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
        int txId = program.startTransaction("Parse C Structure");
        try {
            DataType dt = parser.parse(cDefinition);
            if (dt == null) {
                throw new Exception("Failed to parse structure definition");
            }

            CategoryPath catPath = new CategoryPath(category);
            // Ghidra API: DataTypeManager.createCategory(CategoryPath) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#createCategory(ghidra.program.model.data.CategoryPath)
            Category cat = dtm.createCategory(catPath);

            // Ghidra API: DataTypeManager.resolve(DataType, DataTypeConflictHandler) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#resolve(ghidra.program.model.data.DataType,ghidra.program.model.data.DataTypeConflictHandler)
            DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
            if (cat != null && resolved.getCategoryPath() != catPath) {
                resolved.setName(resolved.getName());
                cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
            }

            // Ghidra API: Program.endTransaction(int, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Parse C structure");

            Map<String, Object> result = createStructureInfo(resolved);
            result.put("message", "Successfully created structure: " + resolved.getName());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            // Ghidra API: Msg.error(Object, Object, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(this, "Failed to parse C structure", e);
            return createErrorResult("Failed to parse: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleValidateAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='validate'");
        }

        try {
            Program program = getProgramFromArgs(request);
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm);
            DataType dt = parser.parse(cDefinition);

            Map<String, Object> result = new HashMap<>();
            if (dt != null) {
                result.put("valid", true);
                result.put("parsedType", dt.getName());
                result.put("type", dt.getClass().getSimpleName());
            } else {
                result.put("valid", false);
                result.put("error", "Failed to parse structure definition");
            }
            return createJsonResult(result);
        } catch (ProgramValidationException | ParseException | IllegalArgumentException e) {
            Map<String, Object> result = new HashMap<>();
            result.put("valid", false);
            result.put("error", e.getMessage());
            return createJsonResult(result);
        }
    }

    private McpSchema.CallToolResult handleCreateAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String name = getOptionalString(request, "name", null);
        if (name == null) {
            return createErrorResult("name is required for action='create'");
        }
        int size = getOptionalInt(request, "size", 0);
        String type = getOptionalString(request, "type", "structure");
        String category = getOptionalString(request, "category", "/");
        boolean packed = getOptionalBoolean(request, "packed", false);
        String description = getOptionalString(request, "description", null);

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(category);

        int txId = program.startTransaction("Create Structure");
        try {
            Category cat = dtm.createCategory(catPath);
            Composite composite;
            if ("union".equals(type)) {
                composite = new UnionDataType(catPath, name);
            } else {
                composite = new StructureDataType(catPath, name, size);
                if (packed) {
                    ((Structure) composite).setPackingEnabled(true);
                }
            }

            if (description != null && !description.trim().isEmpty()) {
                composite.setDescription(description);
            }

            DataType resolved = dtm.resolve(composite, DataTypeConflictHandler.REPLACE_HANDLER);
            if (cat != null && resolved.getCategoryPath() != catPath) {
                resolved.setName(resolved.getName());
                cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
            }

            program.endTransaction(txId, true);
            
            // Check if fields array is provided for inline field addition
            List<Object> fieldsList = getParameterAsList(request.arguments(), "fields");
            if (!fieldsList.isEmpty() && resolved instanceof Composite) {
                // Add fields in a separate transaction
                McpSchema.CallToolResult fieldsResult = addFieldsToStructure(program, (Composite) resolved, fieldsList);
                if (fieldsResult.isError()) {
                    return fieldsResult;
                }
            }
            
            autoSaveProgram(program, "Create structure");

            Map<String, Object> result = createStructureInfo(resolved);
            result.put("message", "Successfully created structure: " + resolved.getName());
            if (!fieldsList.isEmpty()) {
                result.put("fieldsAdded", fieldsList.size());
            }
            return createJsonResult(result);
        } catch (DataTypeDependencyException | InvalidNameException | DuplicateNameException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to create structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleAddFieldAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='add_field'");
        }
        
        // Check if fields array is present (batch mode)
        List<Object> fieldsList = getParameterAsList(request.arguments(), "fields");
        if (!fieldsList.isEmpty() && fieldsList.get(0) instanceof Map) {
            // Batch mode detected
            return handleBatchAddFields(program, request, structureName, fieldsList);
        }
        
        // Single field mode (backwards compatible)
        String fieldName = getOptionalString(request, "fieldName", null);
        if (fieldName == null) {
            return createErrorResult("fieldName is required for action='add_field'");
        }
        String dataTypeStr = getOptionalString(request, "dataType", null);
        if (dataTypeStr == null) {
            return createErrorResult("dataType is required for action='add_field'");
        }
        Integer offset = getOptionalInteger(request.arguments(), "offset", null);
        String comment = getOptionalString(request, "comment", null);
        
        // Get options for size preservation behavior
        boolean useReplace = getOptionalBoolean(request, "useReplace", true);

        DataTypeManager dtm = program.getDataTypeManager();
        // Ghidra API: DataTypeManager.getDataType(CategoryPath, String) / getDataType(String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getDataType(ghidra.program.model.data.CategoryPath,java.lang.String)
        DataType dt = dtm.getDataType(structureName);
        if (dt == null) {
            dt = findDataTypeByName(dtm, structureName);
        }
        if (dt == null) {
            return createErrorResult("Structure not found: " + structureName);
        }
        if (!(dt instanceof Composite)) {
            return createErrorResult("Data type is not a structure or union: " + structureName);
        }

        Composite composite = (Composite) dt;
        if (!(composite instanceof Structure)) {
            return createErrorResult("add_field is only supported for structures, not unions");
        }
        Structure struct = (Structure) composite;
        // Ghidra API: DataType.getLength() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getLength()
        int originalSize = struct.getLength();

        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        DataType fieldType;
        try {
            fieldType = parser.parse(dataTypeStr);
        } catch (InvalidDataTypeException | CancelledException e) {
            return createErrorResult("Failed to parse data type: " + e.getMessage());
        }
        if (fieldType == null) {
            return createErrorResult("Could not parse data type: " + dataTypeStr);
        }

        int txId = program.startTransaction("Add Structure Field");
        try {
            DataTypeComponent component;
            if (offset != null) {
                if (useReplace) {
                    // Ghidra API: Structure.replaceAtOffset(int, DataType, int, String, String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html#replaceAtOffset(int,ghidra.program.model.data.DataType,int,java.lang.String,java.lang.String)
                    component = struct.replaceAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                } else {
                    // Ghidra API: Structure.insertAtOffset(int, DataType, int, String, String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html#insertAtOffset(int,ghidra.program.model.data.DataType,int,java.lang.String,java.lang.String)
                    component = struct.insertAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                }
            } else {
                // Ghidra API: Structure.add(DataType, String, String) (Composite) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Composite.html#add(ghidra.program.model.data.DataType,java.lang.String,java.lang.String)
                component = struct.add(fieldType, fieldName, comment);
            }
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Add structure field");

            Map<String, Object> result = createStructureInfo(struct);
            result.put("message", "Successfully added field: " + fieldName);
            result.put("fieldOrdinal", component.getOrdinal());
            
            // Add size tracking information
            int finalSize = struct.getLength();
            result.put("originalSize", originalSize);
            result.put("finalSize", finalSize);
            if (finalSize != originalSize) {
                result.put("sizeGrew", true);
                result.put("sizeGrowth", finalSize - originalSize);
                result.put("sizeWarning", "Structure grew from " + originalSize + " to " + finalSize + 
                    " bytes. Consider using useReplace=true for non-packed structures with explicit offsets.");
            }
            
            return createJsonResult(result);
        } catch (IllegalArgumentException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to add field: " + e.getMessage());
        }
    }

    /**
     * Handle batch add field operations when fields parameter is an array.
     * 
     * <p>This method supports two important options to prevent structure size growth:
     * <ul>
     *   <li><b>preserveSize</b>: Validates that the final structure size matches the original
     *       size. If the structure grows, the transaction is rolled back and an error is returned.
     *       Use this when you've created a structure with an explicit size and need to maintain it.</li>
     *   <li><b>useReplace</b>: Uses {@code replaceAtOffset()} instead of {@code insertAtOffset()}.
     *       This replaces existing undefined bytes at the offset rather than inserting and shifting.
     *       Recommended for non-packed structures with explicit field offsets.</li>
     * </ul>
     * 
     * <p><b>Root cause of size growth:</b> Ghidra's {@code insertAtOffset()} will shift existing
     * components to avoid conflicts, which can grow the structure. When adding fields with gaps
     * or embedded complex types, the structure can expand beyond the intended size.
     * 
     * <p><b>Recommended approach for byte-perfect layouts:</b>
     * <ol>
     *   <li>Use {@code parse_header} action with C definition including {@code #pragma pack(push, 1)}</li>
     *   <li>Or use {@code useReplace=true} with explicit offsets for non-packed structures</li>
     *   <li>Or use {@code preserveSize=true} to detect and reject size-growing operations</li>
     * </ol>
     */
    private McpSchema.CallToolResult handleBatchAddFields(Program program, CallToolRequest request,
            String structureName, List<Object> fieldsList) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        
        // Get options for size preservation behavior
        boolean preserveSize = getOptionalBoolean(request, "preserveSize", true);
        boolean useReplace = getOptionalBoolean(request, "useReplace", true);

        // Find structure once for all fields
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = dtm.getDataType(structureName);
        if (dt == null) {
            dt = findDataTypeByName(dtm, structureName);
        }
        if (dt == null) {
            return createErrorResult("Structure not found: " + structureName);
        }
        if (!(dt instanceof Composite)) {
            return createErrorResult("Data type is not a structure or union: " + structureName);
        }

        Composite composite = (Composite) dt;
        if (!(composite instanceof Structure)) {
            return createErrorResult("add_field is only supported for structures, not unions");
        }
        Structure struct = (Structure) composite;
        
        // Record original size for preserveSize validation
        int originalSize = struct.getLength();

        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        int txId = program.startTransaction("Batch Add Structure Fields");
        boolean committed = false;

        try {
            for (int i = 0; i < fieldsList.size(); i++) {
                try {
                    if (!(fieldsList.get(i) instanceof Map)) {
                        errors.add(Map.of("index", i, "error", "Field must be an object with fieldName and dataType"));
                        continue;
                    }

                    @SuppressWarnings("unchecked")
                    Map<String, Object> fieldDef = (Map<String, Object>) fieldsList.get(i);
                    
                    // Extract field parameters
                    Object fieldNameObj = fieldDef.get("fieldName");
                    if (fieldNameObj == null) {
                        errors.add(Map.of("index", i, "error", "fieldName is required for each field"));
                        continue;
                    }
                    String fieldName = fieldNameObj.toString();

                    Object dataTypeObj = fieldDef.get("dataType");
                    if (dataTypeObj == null) {
                        errors.add(Map.of("index", i, "fieldName", fieldName, "error", "dataType is required for each field"));
                        continue;
                    }
                    String dataTypeStr = dataTypeObj.toString();

                    Integer offset = null;
                    if (fieldDef.containsKey("offset")) {
                        Object offsetObj = fieldDef.get("offset");
                        if (offsetObj instanceof Number number) {
                            offset = number.intValue();
                        }
                    }

                    String comment = null;
                    if (fieldDef.containsKey("comment")) {
                        Object commentObj = fieldDef.get("comment");
                        if (commentObj != null) {
                            comment = commentObj.toString();
                        }
                    }

                    // Parse data type
                    DataType fieldType;
                    try {
                        fieldType = parser.parse(dataTypeStr);
                    } catch (InvalidDataTypeException | CancelledException e) {
                        errors.add(Map.of("index", i, "fieldName", fieldName, "error", "Failed to parse data type: " + e.getMessage()));
                        continue;
                    }
                    if (fieldType == null) {
                        errors.add(Map.of("index", i, "fieldName", fieldName, "error", "Could not parse data type: " + dataTypeStr));
                        continue;
                    }

                    // Add the field - use replaceAtOffset when useReplace is true to avoid shifting/growing
                    DataTypeComponent component;
                    if (offset != null) {
                        if (useReplace) {
                            // replaceAtOffset consumes undefined bytes at offset without shifting
                            // This preserves structure size for non-packed structures with explicit layouts
                            component = struct.replaceAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                        } else {
                            // insertAtOffset may shift existing components, potentially growing the structure
                            component = struct.insertAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                        }
                    } else {
                        component = struct.add(fieldType, fieldName, comment);
                    }

                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("fieldName", fieldName);
                    result.put("dataType", dataTypeStr);
                    result.put("offset", component.getOffset());
                    result.put("fieldOrdinal", component.getOrdinal());
                    results.add(result);

                } catch (IllegalArgumentException e) {
                    Map<String, Object> errorMap = new HashMap<>();
                    errorMap.put("index", i);
                    if (fieldsList.get(i) instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> fieldDef = (Map<String, Object>) fieldsList.get(i);
                        if (fieldDef.containsKey("fieldName")) {
                            errorMap.put("fieldName", fieldDef.get("fieldName"));
                        }
                    }
                    errorMap.put("error", e.getMessage());
                    errors.add(errorMap);
                }
            }

            // Validate size preservation if requested
            int finalSize = struct.getLength();
            if (preserveSize && finalSize != originalSize) {
                program.endTransaction(txId, false); // Roll back the transaction
                return createErrorResult(
                    "Structure size grew from " + originalSize + " to " + finalSize + " bytes. " +
                    "This can happen when insertAtOffset shifts components. "
                );
            }

            program.endTransaction(txId, true);
            committed = true;
            autoSaveProgram(program, "Batch add structure fields");

        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(txId, false);
            }
            return createErrorResult("Error in batch add fields: " + e.getMessage());
        }

        // Get final size after all operations
        int finalSize = struct.getLength();

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("success", true);
        resultData.put("structureName", structureName);
        resultData.put("total", fieldsList.size());
        resultData.put("succeeded", results.size());
        resultData.put("failed", errors.size());
        resultData.put("results", results);
        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }
        // Include updated structure info
        resultData.putAll(createStructureInfo(struct));
        
        // Add size tracking information
        resultData.put("originalSize", originalSize);
        resultData.put("finalSize", finalSize);
        if (finalSize != originalSize) {
            resultData.put("sizeGrew", true);
            resultData.put("sizeGrowth", finalSize - originalSize);
            resultData.put("sizeWarning", "Structure grew from " + originalSize + " to " + finalSize + 
                " bytes. Consider using useReplace=true or parse_header action for byte-perfect layouts.");
        }
        
        resultData.put("message", "Successfully added " + results.size() + " field(s) to structure: " + structureName);

        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleModifyFieldAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='modify_field'");
        }
        String fieldName = getOptionalString(request, "fieldName", null);
        String newDataTypeStr = getOptionalString(request, "newDataType", null);
        String newFieldName = getOptionalString(request, "newFieldName", null);
        String newComment = getOptionalString(request, "newComment", null);
        Integer newLength = getOptionalInteger(request.arguments(), "newLength", null);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Structure)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Structure struct = (Structure) dt;
        int txId = program.startTransaction("Modify Structure Field");
        try {
            DataTypeComponent targetComponent = null;
            int targetOrdinal = -1;

            if (fieldName != null) {
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    DataTypeComponent comp = struct.getComponent(i);
                    if (fieldName.equals(comp.getFieldName())) {
                        targetComponent = comp;
                        targetOrdinal = i;
                        break;
                    }
                }
            } else {
                // If no fieldName provided, must use offset to identify field
                Integer offset = getOptionalInteger(request.arguments(), "offset", null);
                if (offset != null) {
                    targetComponent = struct.getComponentAt(offset);
                    if (targetComponent != null) {
                        targetOrdinal = targetComponent.getOrdinal();
                    }
                }
            }

            if (targetComponent == null) {
                return createErrorResult("Field not found: " + (fieldName != null ? fieldName : "at specified offset"));
            }

            // Collect replacement values
            DataType replacementType = targetComponent.getDataType();
            String replacementName = targetComponent.getFieldName();
            String replacementComment = targetComponent.getComment();
            int replacementLength = targetComponent.getLength();

            if (newDataTypeStr != null) {
                DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
                DataType newType = parser.parse(newDataTypeStr);
                if (newType == null) {
                    return createErrorResult("Failed to parse new data type: " + newDataTypeStr);
                }
                replacementType = newType;
                if (newLength == null) {
                    replacementLength = newType.getLength();
                }
            }
            if (newFieldName != null) {
                replacementName = newFieldName;
            }
            if (newComment != null) {
                replacementComment = newComment;
            }
            if (newLength != null) {
                replacementLength = newLength;
            }

            // Replace the component
            struct.replace(targetOrdinal, replacementType, replacementLength, replacementName, replacementComment);

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Modify structure field");

            Map<String, Object> result = createStructureInfo(struct);
            result.put("message", "Successfully modified field");
            return createJsonResult(result);
        } catch (InvalidDataTypeException | CancelledException | IllegalArgumentException | IndexOutOfBoundsException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to modify field: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleModifyFromCAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='modify_from_c'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType parsedDt;
        try {
            CParser parser = new CParser(dtm);
            parsedDt = parser.parse(cDefinition);
        } catch (ParseException e) {
            return createErrorResult("Failed to parse C definition: " + e.getMessage());
        }

        if (parsedDt == null || !(parsedDt instanceof Structure)) {
            return createErrorResult("Parsed definition is not a structure");
        }

        Structure parsedStruct = (Structure) parsedDt;
        String structureName = parsedStruct.getName();
        DataType existingDt = findDataTypeByName(dtm, structureName);
        if (existingDt == null || !(existingDt instanceof Structure)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Structure existingStruct = (Structure) existingDt;
        int txId = program.startTransaction("Modify Structure from C");
        try {
            existingStruct.deleteAll();
            for (DataTypeComponent comp : parsedStruct.getComponents()) {
                existingStruct.add(comp.getDataType(), comp.getLength(), comp.getFieldName(), comp.getComment());
            }
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Modify structure from C");

            Map<String, Object> result = createStructureInfo(existingStruct);
            result.put("message", "Successfully modified structure from C definition: " + existingStruct.getName());
            return createJsonResult(result);
        } catch (IllegalArgumentException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to modify structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleInfoAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='info'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Map<String, Object> result = createDetailedStructureInfo((Composite) dt);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleListAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String nameFilter = getOptionalString(request, "nameFilter", null);
        boolean includeBuiltIn = getOptionalBoolean(request, "includeBuiltIn", false);
        int maxCount = getOptionalInt(request, "maxCount", 50);
        int startIndex = getOptionalInt(request, "startIndex", 0);

        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> structures = new ArrayList<>();
        int totalCount = 0;
        int currentIndex = 0;

        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (!(dt instanceof Composite)) continue;
            if (!includeBuiltIn && dt.getCategoryPath().toString().startsWith("/")) {
                if (dt.getCategoryPath().getName().equals("BuiltInTypes")) continue;
            }
            if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }
            
            totalCount++;
            if (currentIndex >= startIndex && structures.size() < maxCount) {
                structures.add(createStructureInfo(dt));
            }
            currentIndex++;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("structures", structures);
        result.put("count", structures.size());
        result.put("totalCount", totalCount);
        result.put("startIndex", startIndex);
        result.put("maxCount", maxCount);
        if (startIndex + maxCount < totalCount) {
            result.put("hasMore", true);
            result.put("nextStartIndex", startIndex + maxCount);
        }
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleApplyAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='apply'");
        }
        boolean clearExisting = getOptionalBoolean(request, "clearExisting", true);

        // Check if addressOrSymbol is an array (batch mode) - supports both camelCase and snake_case via getParameterValue
        List<Object> addressOrSymbolList = getParameterAsList(request.arguments(), "addressOrSymbol");

        if (addressOrSymbolList.size() > 1 || (!addressOrSymbolList.isEmpty() && addressOrSymbolList.get(0) instanceof List)) {
            List<?> batchList = addressOrSymbolList.size() > 1 ? addressOrSymbolList : (List<?>) addressOrSymbolList.get(0);
            return handleBatchApplyStructure(program, request, structureName, clearExisting, batchList);
        }

        // Single address mode
        String addressOrSymbol = getOptionalString(request, "addressOrSymbol", null);
        if (addressOrSymbol == null) {
            return createErrorResult("addressOrSymbol is required for action='apply'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressOrSymbol);
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        int txId = program.startTransaction("Apply Structure");
        try {
            Listing listing = program.getListing();
            if (clearExisting) {
                listing.clearCodeUnits(address, address.add(dt.getLength() - 1), false);
            }
            listing.createData(address, dt);
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Apply structure");

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("structureName", structureName);
            result.put("address", AddressUtil.formatAddress(address));
            return createJsonResult(result);
        } catch (AddressOutOfBoundsException | CodeUnitInsertionException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to apply structure: " + e.getMessage());
        }
    }

    /**
     * Handle batch apply structure operations when address_or_symbol is an array
     */
    private McpSchema.CallToolResult handleBatchApplyStructure(Program program, CallToolRequest request,
            String structureName, boolean clearExisting, List<?> addressList) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        // Find structure once for all addresses
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        int txId = program.startTransaction("Batch Apply Structure");
        boolean committed = false;

        try {
            Listing listing = program.getListing();

            for (int i = 0; i < addressList.size(); i++) {
                try {
                    String addressOrSymbol = addressList.get(i).toString();
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);

                    if (address == null) {
                        errors.add(Map.of("index", i, "addressOrSymbol", addressOrSymbol, "error", "Could not resolve address or symbol"));
                        continue;
                    }

                    // Clear existing data if requested
                    if (clearExisting) {
                        listing.clearCodeUnits(address, address.add(dt.getLength() - 1), false);
                    }

                    // Create data with the structure type
                    listing.createData(address, dt);

                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("structureName", structureName);
                    results.add(result);

                } catch (AddressOutOfBoundsException | CodeUnitInsertionException e) {
                    errors.add(Map.of("index", i, "addressOrSymbol", addressList.get(i).toString(), "error", e.getMessage()));
                }
            }

            program.endTransaction(txId, true);
            committed = true;
            autoSaveProgram(program, "Batch apply structure");

        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(txId, false);
            }
            return createErrorResult("Error in batch apply structure: " + e.getMessage());
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("success", true);
        resultData.put("structureName", structureName);
        resultData.put("total", addressList.size());
        resultData.put("succeeded", results.size());
        resultData.put("failed", errors.size());
        resultData.put("results", results);
        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }

        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleDeleteAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='delete'");
        }
        boolean force = getOptionalBoolean(request, "force", false);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null) {
            return createErrorResult("Structure not found: " + structureName);
        }

        // Check for references manually (DataTypeManager doesn't have getReferenceCount)
        if (!force) {
            // Check function signatures and variables
            List<String> functionReferences = new ArrayList<>();
            ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                ghidra.program.model.listing.Function func = functions.next();
                if (func.getReturnType().isEquivalent(dt)) {
                    functionReferences.add(func.getName() + " (return type)");
                }
                for (ghidra.program.model.listing.Parameter param : func.getParameters()) {
                    if (param.getDataType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (parameter: " + param.getName() + ")");
                    }
                }
                for (ghidra.program.model.listing.Variable var : func.getAllVariables()) {
                    if (var.getDataType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (variable: " + var.getName() + ")");
                    }
                }
            }

            // Check memory instances
            List<String> memoryReferences = new ArrayList<>();
            Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.getDataType().isEquivalent(dt)) {
                    memoryReferences.add(AddressUtil.formatAddress(data.getAddress()));
                }
            }

            int totalReferences = functionReferences.size() + memoryReferences.size();
            if (totalReferences > 0) {
                Map<String, Object> result = new HashMap<>();
                result.put("deleted", false);
                result.put("error", "Structure is referenced. Use force=true to delete anyway.");
                result.put("referenceCount", totalReferences);
                Map<String, Object> refs = new HashMap<>();
                refs.put("functions", functionReferences);
                refs.put("memoryLocations", memoryReferences);
                result.put("references", refs);
                return createJsonResult(result);
            }
        }

        int txId = program.startTransaction("Delete Structure");
        try {
            boolean removed = dtm.remove(dt);
            if (!removed) {
                program.endTransaction(txId, false);
                return createErrorResult("Failed to delete structure (may be locked or in use by another process)");
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Delete structure");

            Map<String, Object> result = new HashMap<>();
            result.put("deleted", true);
            result.put("message", "Successfully deleted structure: " + structureName);
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to delete structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleParseHeaderAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String headerContent = getOptionalString(request, "headerContent", null);
        if (headerContent == null) {
            return createErrorResult("headerContent is required for action='parse_header'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CParser parser = new CParser(dtm);
        List<Map<String, Object>> createdTypes = new ArrayList<>();

        int txId = program.startTransaction("Parse C Header");
        try {
            String[] lines = headerContent.split("\n");
            StringBuilder currentDefinition = new StringBuilder();
            for (String line : lines) {
                currentDefinition.append(line).append("\n");
                if (line.trim().endsWith("}") || line.trim().endsWith("};")) {
                    try {
                        DataType dt = parser.parse(currentDefinition.toString());
                        if (dt != null) {
                            DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                            createdTypes.add(createStructureInfo(resolved));
                        }
                    } catch (ParseException e) {
                        // Skip failed parse, continue with next
                    }
                    currentDefinition = new StringBuilder();
                }
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Parse C header");

            Map<String, Object> result = new HashMap<>();
            result.put("createdTypes", createdTypes);
            result.put("count", createdTypes.size());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to parse header: " + e.getMessage());
        }
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        // First try direct lookup
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        // Search all categories
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(name)) {
                return dataType;
            }
        }

        return null;
    }

    /**
     * Create basic structure info map
     */
    private Map<String, Object> createStructureInfo(DataType dt) {
        Map<String, Object> info = DataTypeParserUtil.createDataTypeInfo(dt);

        if (dt instanceof Composite composite) {
            info.put("isUnion", dt instanceof Union);
            info.put("numComponents", composite.getNumComponents());

            if (dt instanceof Structure struct) {
                info.put("isPacked", struct.isPackingEnabled());
                // hasFlexibleArray check would go here if method exists
            }
        }

        return info;
    }

    /**
     * Create detailed structure info including all fields
     */
    private Map<String, Object> createDetailedStructureInfo(Composite composite) {
        Map<String, Object> info = createStructureInfo(composite);

        // Add field information with undefined byte condensing
        List<Map<String, Object>> fields = new ArrayList<>();

        int i = 0;
        while (i < composite.getNumComponents()) {
            DataTypeComponent comp = composite.getComponent(i);

            // Check if this is an undefined byte that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int startOrdinal = comp.getOrdinal();
                int totalLength = 0;
                int count = 0;

                while (i < composite.getNumComponents()) {
                    DataTypeComponent nextComp = composite.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Create a condensed entry for the undefined range
                Map<String, Object> fieldInfo = new HashMap<>();
                fieldInfo.put("ordinal", startOrdinal);
                fieldInfo.put("offset", startOffset);
                fieldInfo.put("length", totalLength);
                fieldInfo.put("fieldName", "<undefined>");
                fieldInfo.put("dataType", "undefined");
                fieldInfo.put("dataTypeSize", totalLength);
                fieldInfo.put("isBitfield", false);
                fieldInfo.put("isCondensed", true);
                fieldInfo.put("componentCount", count);

                fields.add(fieldInfo);
            } else {
                // Regular field - add as-is
                Map<String, Object> fieldInfo = new HashMap<>();

                fieldInfo.put("ordinal", comp.getOrdinal());
                fieldInfo.put("offset", comp.getOffset());
                fieldInfo.put("length", comp.getLength());
                fieldInfo.put("fieldName", comp.getFieldName());
                if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                    fieldInfo.put("comment", comp.getComment());
                }

                DataType fieldType = comp.getDataType();
                fieldInfo.put("dataType", fieldType.getDisplayName());
                fieldInfo.put("dataTypeSize", fieldType.getLength());

                // Check if it's a bitfield
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    fieldInfo.put("isBitfield", true);
                    fieldInfo.put("bitSize", bitfield.getBitSize());
                    fieldInfo.put("bitOffset", bitfield.getBitOffset());
                    fieldInfo.put("baseDataType", bitfield.getBaseDataType().getDisplayName());
                } else {
                    fieldInfo.put("isBitfield", false);
                }

                fieldInfo.put("isCondensed", false);

                fields.add(fieldInfo);
                i++;
            }
        }

        info.put("fields", fields);

        // Add C representation
        if (composite instanceof Structure structure) {
            info.put("cRepresentation", generateCRepresentation(structure));
        }

        return info;
    }

    /**
     * Check if a field is an undefined/default field that should be condensed
     */
    private boolean isUndefinedField(DataTypeComponent comp) {
        // Check if the field name is null or empty (undefined)
        String fieldName = comp.getFieldName();
        if (fieldName == null || fieldName.isEmpty()) {
            return true;
        }

        // Check if it's a Ghidra default field name like "field_0x0", "field_0x1", etc.
        // These are generated for undefined structure areas
        if (fieldName.startsWith("field_0x") || fieldName.startsWith("field0x")) {
            return true;
        }

        // Check if the datatype is "undefined" or "undefined1"
        DataType fieldType = comp.getDataType();
        String typeName = fieldType.getName();
        return typeName != null && typeName.startsWith("undefined");
    }

    /**
     * Generate C representation of a structure with undefined byte condensing
     */
    private String generateCRepresentation(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(struct.getName()).append(" {\n");

        int i = 0;
        while (i < struct.getNumComponents()) {
            DataTypeComponent comp = struct.getComponent(i);
            sb.append("    ");

            // Check if this is an undefined field that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int totalLength = 0;
                int count = 0;

                while (i < struct.getNumComponents()) {
                    DataTypeComponent nextComp = struct.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Generate condensed line with offset range comment
                sb.append("undefined reserved_0x");
                sb.append(String.format("%x", startOffset));
                sb.append("[").append(count).append("]");
                sb.append(";");
                sb.append(" // 0x");
                sb.append(String.format("%x", startOffset));
                sb.append("-0x");
                sb.append(String.format("%x", startOffset + totalLength - 1));
                sb.append("\n");
            } else {
                // Regular field - output as-is
                DataType fieldType = comp.getDataType();
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    sb.append(bitfield.getBaseDataType().getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                    sb.append(" : ").append(bitfield.getBitSize());
                } else {
                    sb.append(fieldType.getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                }

                sb.append(";");

                if (comp.getComment() != null) {
                    sb.append(" // ").append(comp.getComment());
                }

                sb.append("\n");
                i++;
            }
        }

        sb.append("};");
        return sb.toString();
    }

    /**
     * Helper method to add fields to a structure (used for inline field addition during create)
     */
    private McpSchema.CallToolResult addFieldsToStructure(Program program, Composite composite, List<Object> fieldsList) {
        List<Map<String, Object>> errors = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();
        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        
        int txId = program.startTransaction("Add fields to structure");
        try {
            for (int i = 0; i < fieldsList.size(); i++) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> fieldSpec = (Map<String, Object>) fieldsList.get(i);
                    String fieldName = (String) fieldSpec.get("fieldName");
                    String dataTypeStr = (String) fieldSpec.get("dataType");
                    Integer offset = fieldSpec.containsKey("offset") ? ((Number) fieldSpec.get("offset")).intValue() : null;
                    String comment = (String) fieldSpec.get("comment");
                    
                    DataType fieldType = parser.parse(dataTypeStr);
                    if (fieldType == null) {
                        errors.add(Map.of("index", i, "fieldName", fieldName, "error", "Invalid data type: " + dataTypeStr));
                        continue;
                    }
                    
                    if (composite instanceof Structure struct) {
                        if (offset != null) {
                            struct.replaceAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                        } else {
                            struct.add(fieldType, fieldName, comment);
                        }
                    } else if (composite instanceof Union union) {
                        union.add(fieldType, fieldName, comment);
                    }
                } catch (InvalidDataTypeException | CancelledException e) {
                    errors.add(Map.of("index", i, "error", e.getMessage()));
                }
            }
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Add fields to structure");
            
            if (!errors.isEmpty()) {
                Map<String, Object> result = new HashMap<>();
                result.put("partialSuccess", true);
                result.put("errors", errors);
                return createJsonResult(result);
            }
            return null; // Success
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to add fields: " + e.getMessage());
        }
    }
    
    /**
     * Handle batch structure creation
     */
    private McpSchema.CallToolResult handleBatchCreateStructures(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, List<Object> structuresList) {
        Program program = getProgramFromArgs(request);
        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        
        int txId = program.startTransaction("Batch Create Structures");
        try {
            for (int i = 0; i < structuresList.size(); i++) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> structSpec = (Map<String, Object>) structuresList.get(i);
                    
                    String name = (String) structSpec.get("name");
                    if (name == null) {
                        errors.add(Map.of("index", i, "error", "name is required"));
                        continue;
                    }
                    
                    int size = structSpec.containsKey("size") ? ((Number) structSpec.get("size")).intValue() : 0;
                    String type = (String) structSpec.getOrDefault("type", "structure");
                    String category = (String) structSpec.getOrDefault("category", "/");
                    boolean packed = (Boolean) structSpec.getOrDefault("packed", false);
                    String description = (String) structSpec.get("description");
                    
                    CategoryPath catPath = new CategoryPath(category);
                    Category cat = dtm.createCategory(catPath);
                    
                    Composite composite;
                    if ("union".equals(type)) {
                        composite = new UnionDataType(catPath, name);
                    } else {
                        composite = new StructureDataType(catPath, name, size);
                        if (packed) {
                            ((Structure) composite).setPackingEnabled(true);
                        }
                    }
                    
                    if (description != null && !description.trim().isEmpty()) {
                        composite.setDescription(description);
                    }
                    
                    DataType resolved = dtm.resolve(composite, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (cat != null && resolved.getCategoryPath() != catPath) {
                        resolved.setName(resolved.getName());
                        cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    
                    // Handle inline fields if provided
                    @SuppressWarnings("unchecked")
                    List<Object> fields = (List<Object>) structSpec.get("fields");
                    if (fields != null && !fields.isEmpty() && resolved instanceof Composite) {
                        addFieldsToStructure(program, (Composite) resolved, fields);
                    }
                    
                    Map<String, Object> structInfo = createStructureInfo(resolved);
                    structInfo.put("index", i);
                    results.add(structInfo);
                } catch (Exception e) {
                    errors.add(Map.of("index", i, "error", e.getMessage()));
                }
            }
            
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Batch create structures");
            
            Map<String, Object> result = new HashMap<>();
            result.put("batchOperation", true);
            result.put("results", results);
            result.put("totalCreated", results.size());
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Batch create failed: " + e.getMessage());
        }
    }
    
    /**
     * Handle batch structure deletion
     */
    private McpSchema.CallToolResult handleBatchDeleteStructures(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, List<?> structureNames) {
        Program program = getProgramFromArgs(request);
        DataTypeManager dtm = program.getDataTypeManager();
        boolean force = getOptionalBoolean(request, "force", false);
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        
        int txId = program.startTransaction("Batch Delete Structures");
        try {
            for (int i = 0; i < structureNames.size(); i++) {
                try {
                    String structureName = structureNames.get(i).toString();
                    DataType dt = findDataTypeByName(dtm, structureName);
                    
                    if (dt == null) {
                        errors.add(Map.of("index", i, "structureName", structureName, "error", "Structure not found"));
                        continue;
                    }
                    
                    // Check for references if not forcing
                    if (!force) {
                        List<String> refs = new ArrayList<>();
                        ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                        while (functions.hasNext() && refs.size() < 5) {
                            ghidra.program.model.listing.Function func = functions.next();
                            if (func.getReturnType().isEquivalent(dt)) {
                                refs.add(func.getName());
                            }
                        }
                        if (!refs.isEmpty()) {
                            errors.add(Map.of("index", i, "structureName", structureName, "error", "Structure is referenced. Use force=true"));
                            continue;
                        }
                    }
                    
                    boolean removed = dtm.remove(dt);
                    if (removed) {
                        results.add(Map.of("index", i, "structureName", structureName, "deleted", true));
                    } else {
                        errors.add(Map.of("index", i, "structureName", structureName, "error", "Failed to delete"));
                    }
                } catch (Exception e) {
                    errors.add(Map.of("index", i, "structureName", structureNames.get(i).toString(), "error", e.getMessage()));
                }
            }
            
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Batch delete structures");
            
            Map<String, Object> result = new HashMap<>();
            result.put("batchOperation", true);
            result.put("results", results);
            result.put("totalDeleted", results.size());
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Batch delete failed: " + e.getMessage());
        }
    }
    
    /**
     * Handle batch structure parsing
     */
    private McpSchema.CallToolResult handleBatchParseStructures(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, List<?> cDefinitions) {
        Program program = getProgramFromArgs(request);
        String category = getOptionalString(request, "category", "/");
        DataTypeManager dtm = program.getDataTypeManager();
        CParser parser = new CParser(dtm);
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        
        int txId = program.startTransaction("Batch Parse Structures");
        try {
            CategoryPath catPath = new CategoryPath(category);
            Category cat = dtm.createCategory(catPath);
            
            for (int i = 0; i < cDefinitions.size(); i++) {
                try {
                    String cDefinition = cDefinitions.get(i).toString();
                    DataType dt = parser.parse(cDefinition);
                    if (dt == null) {
                        errors.add(Map.of("index", i, "error", "Failed to parse definition"));
                        continue;
                    }
                    
                    DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (cat != null && resolved.getCategoryPath() != catPath) {
                        resolved.setName(resolved.getName());
                        cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    
                    Map<String, Object> structInfo = createStructureInfo(resolved);
                    structInfo.put("index", i);
                    results.add(structInfo);
                } catch (Exception e) {
                    errors.add(Map.of("index", i, "error", e.getMessage()));
                }
            }
            
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Batch parse structures");
            
            Map<String, Object> result = new HashMap<>();
            result.put("batchOperation", true);
            result.put("results", results);
            result.put("totalParsed", results.size());
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Batch parse failed: " + e.getMessage());
        }
    }

}
