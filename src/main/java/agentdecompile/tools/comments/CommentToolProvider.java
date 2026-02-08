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
package agentdecompile.tools.comments;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import agentdecompile.plugin.ConfigManager;
import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;
import agentdecompile.util.DecompilationReadTracker;
import agentdecompile.util.SchemaUtil;
import agentdecompile.util.SmartSuggestionsUtil;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Tool provider for comment-related operations.
 * Provides tools to set, get, remove, and search comments in programs.
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Listing} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html">Listing API</a>,
 * {@link ghidra.program.model.listing.CommentType} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CommentType.html">CommentType API</a>,
 * {@link ghidra.program.model.listing.CodeUnit} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html">CodeUnit API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class CommentToolProvider extends AbstractToolProvider {

    private static final Map<String, CommentType> COMMENT_TYPES = Map.of(
        "pre", CommentType.PRE,
        "eol", CommentType.EOL,
        "post", CommentType.POST,
        "plate", CommentType.PLATE,
        "repeatable", CommentType.REPEATABLE
    );

    /**
     * Record for decompilation attempts with error handling
     */
    private record DecompilationAttempt(
        DecompileResults results,
        String errorMessage,
        boolean success
    ) {
        static DecompilationAttempt success(DecompileResults results) {
            return new DecompilationAttempt(results, null, true);
        }

        static DecompilationAttempt failure(String message) {
            return new DecompilationAttempt(null, message, false);
        }
    }

    /**
     * Constructor
     * @param server The MCP server
     */
    public CommentToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageCommentsTool();
    }

    private void registerManageCommentsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'set', 'get', 'remove', 'search', or 'search_decomp'",
            "enum", List.of("set", "get", "remove", "search", "search_decomp")
        ));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name where to set/get/remove the comment (required for set/remove when not using function/lineNumber)"));
        properties.put("function", SchemaUtil.stringProperty("Function name or address when setting decompilation line comment or searching decompilation"));
        properties.put("lineNumber", SchemaUtil.integerProperty("Line number in the decompiled function when action='set' with decompilation (1-based)"));
        properties.put("comment", SchemaUtil.stringProperty("The comment text to set (required for set when not using batch mode)"));
        properties.put("commentType", SchemaUtil.stringPropertyWithDefault("Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable')", "eol"));
        // Batch comments array - array of objects
        Map<String, Object> commentItemSchema = new HashMap<>();
        commentItemSchema.put("type", "object");
        Map<String, Object> commentItemProperties = new HashMap<>();
        commentItemProperties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name where to set the comment"));
        commentItemProperties.put("comment", SchemaUtil.stringProperty("The comment text to set"));
        commentItemProperties.put("commentType", SchemaUtil.stringPropertyWithDefault("Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable')", "eol"));
        commentItemSchema.put("properties", commentItemProperties);
        commentItemSchema.put("required", List.of("addressOrSymbol", "comment"));

        Map<String, Object> commentsArraySchema = new HashMap<>();
        commentsArraySchema.put("type", "array");
        commentsArraySchema.put("description", "Array of comment objects for batch setting. Each object should have 'addressOrSymbol' (required), 'comment' (required), and optional 'commentType' (defaults to 'eol'). When provided, sets multiple comments in a single transaction.");
        commentsArraySchema.put("items", commentItemSchema);
        properties.put("comments", commentsArraySchema);
        properties.put("start", SchemaUtil.stringProperty("Start address of the range when action='get'"));
        properties.put("end", SchemaUtil.stringProperty("End address of the range when action='get'"));
        properties.put("commentTypes", SchemaUtil.stringProperty("Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable)"));
        properties.put("searchText", SchemaUtil.stringProperty("Text to search for in comments when action='search'"));
        properties.put("pattern", SchemaUtil.stringProperty("Regular expression pattern to search for when action='search_decomp'"));
        properties.put("caseSensitive", SchemaUtil.booleanPropertyWithDefault("Whether search is case sensitive", false));
        properties.put("maxResults", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return", 100));
        properties.put("overrideMaxFunctionsLimit", SchemaUtil.booleanPropertyWithDefault("Whether to override the maximum function limit for decompiler searches", false));

        List<String> required = List.of("action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-comments")
            .title("Manage Comments")
            .description("Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String action = getString(request, "action");

                // For search actions, we support multiple programs
                if ("search".equals(action) || "search_decomp".equals(action)) {
                    List<Program> programs = getProgramsFromArgs(request);
                    if ("search".equals(action)) {
                        return handleSearchCommentsMulti(programs, request);
                    } else {
                        return handleSearchDecompilationMulti(programs, request, exchange);
                    }
                }

                // For other actions, resolve to a single program (using smart resolution)
                Program program = getProgramFromArgs(request);

                switch (action) {
                    case "set":
                        return handleSetComment(program, request);
                    case "get":
                        return handleGetComments(program, request);
                    case "remove":
                        return handleRemoveComment(program, request);
                    default:
                        return createErrorResult("Invalid action: " + action + ". Valid actions are: set, get, remove, search, search_decomp");
                }
            } catch (IllegalArgumentException e) {
                // Try to return default response with error message
                Program program = tryGetProgramSafely(request.arguments());
                if (program != null) {
                    // Return "get" action as default with error message
                    Map<String, Object> errorInfo = createIncorrectArgsErrorMap();
                    McpSchema.CallToolResult defaultResult = handleGetComments(program, request);
                    // Prepend error message to result
                    if (defaultResult.content() != null && !defaultResult.content().isEmpty()) {
                        try {
                            String jsonText = extractTextFromContent(defaultResult.content().get(0));
                            @SuppressWarnings("unchecked")
                            Map<String, Object> data = JSON.readValue(jsonText, Map.class);
                            data.put("error", errorInfo.get("error"));
                            return createJsonResult(data);
                        } catch (Exception ex) {
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
                logError("Error in manage-comments", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleSearchCommentsMulti(List<Program> programs, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        List<Map<String, Object>> allResults = new ArrayList<>();
        int maxResults = getOptionalInt(request, "maxResults", 100);
        
        for (Program program : programs) {
            if (allResults.size() >= maxResults) break;
            
            // Re-use existing search logic but collect results
            List<Map<String, Object>> progResults = searchCommentsInProgram(program, request, maxResults - allResults.size());
            
            // Add program name to results
            String programName = program.getDomainFile().getPathname();
            for (Map<String, Object> result : progResults) {
                result.put("program", programName);
                allResults.add(result);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("searchText", getString(request, "searchText"));
        result.put("caseSensitive", getOptionalBoolean(request, "caseSensitive", false));
        result.put("results", allResults);
        result.put("count", allResults.size());
        result.put("maxResults", maxResults);
        result.put("programsSearched", programs.stream().map(p -> p.getDomainFile().getPathname()).toList());
        
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSearchDecompilationMulti(List<Program> programs,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            io.modelcontextprotocol.server.McpSyncServerExchange exchange) {
            
        List<Map<String, Object>> allResults = new ArrayList<>();
        int maxResults = getOptionalInt(request, "maxResults", 50);
        
        for (Program program : programs) {
            if (allResults.size() >= maxResults) break;
            
            List<Map<String, Object>> progResults = searchDecompilationInProgram(program, request, maxResults - allResults.size());
            
            String programName = program.getDomainFile().getPathname();
            for (Map<String, Object> result : progResults) {
                result.put("program", programName);
                allResults.add(result);
            }
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("pattern", getString(request, "pattern"));
        result.put("caseSensitive", getOptionalBoolean(request, "caseSensitive", false));
        result.put("results", allResults);
        result.put("resultsCount", allResults.size());
        result.put("maxResults", maxResults);
        result.put("programsSearched", programs.stream().map(p -> p.getDomainFile().getPathname()).toList());
        
        return createJsonResult(result);
    }

    // ========================================================================
    // Helper Methods for Decompilation Comments
    // ========================================================================

    /**
     * Create a configured decompiler instance
     */
    private DecompInterface createConfiguredDecompilerForComments(Program program, String toolName) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            decompiler.dispose();
            return null;
        }

        return decompiler;
    }

    /**
     * Safely decompile a function with timeout handling
     */
    private DecompilationAttempt decompileFunctionSafelyForComments(
            DecompInterface decompiler,
            Function function,
            String toolName) {
        ConfigManager config = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(
            config.getDecompilerTimeoutSeconds(),
            TimeUnit.SECONDS);

        try {
            // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
            DecompileResults results = decompiler.decompileFunction(function, 0, monitor);
            if (monitor.isCancelled()) {
                // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
                String msg = "Decompilation timed out for function " + function.getName() +
                    " after " + config.getDecompilerTimeoutSeconds() + " seconds";
                return DecompilationAttempt.failure(msg);
            }

            if (!results.decompileCompleted()) {
                // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
                String msg = "Decompilation failed for function " + function.getName() +
                    ": " + results.getErrorMessage();
                return DecompilationAttempt.failure(msg);
            }

            return DecompilationAttempt.success(results);
        } catch (Exception e) {
            // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
            String msg = "Exception during decompilation of " + function.getName() + ": " + e.getMessage();
            logError(toolName + ": " + msg, e);
            return DecompilationAttempt.failure(msg);
        }
    }

    /**
     * Find the address corresponding to a decompilation line number
     */
    private Address findAddressForLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        for (ClangLine clangLine : clangLines) {
            if (clangLine.getLineNumber() == lineNumber) {
                List<ClangToken> tokens = clangLine.getAllTokens();

                // Find the first address on this line
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        return tokenAddr;
                    }
                }

                // If no direct address, find closest
                if (!tokens.isEmpty()) {
                    return DecompilerUtils.getClosestAddress(program, tokens.get(0));
                }
                break;
            }
        }
        return null;
    }

    /**
     * Check if a function's decompilation has been read (for line comment validation)
     * Uses the shared DecompilationReadTracker so it can see reads from DecompilerToolProvider
     */
    private boolean hasReadDecompilation(String functionKey) {
        return DecompilationReadTracker.hasReadDecompilation(functionKey);
    }

    private McpSchema.CallToolResult handleSetComment(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Check for batch mode (comments array)
        List<Map<String, Object>> commentsArray = getOptionalCommentsArray(request);

        if (commentsArray != null && !commentsArray.isEmpty()) {
            return handleBatchSetComments(program, request, commentsArray);
        }

        String addressStr = getOptionalString(request, "addressOrSymbol", null);

        // Check if setting decompilation line comment (function + lineNumber instead of address)
        String functionStr = getOptionalString(request, "function", null);
        Integer lineNumber = getOptionalInteger(request.arguments(), "lineNumber", null);

        // If we have function and lineNumber but no address, this is a decompilation line comment
        if (addressStr == null && functionStr != null && lineNumber != null) {
            return handleSetDecompilationLineComment(program, request, functionStr, lineNumber);
        }

        // Regular address-based comment
        if (addressStr == null) {
            return createErrorResult("addressOrSymbol is required for action='set' (or use 'comments' array for batch mode, or use function and lineNumber for decompilation line comments)");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        // Intelligent bookmarking: check if address should be bookmarked
        double bookmarkPercentile = agentdecompile.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
            agentdecompile.util.IntelligentBookmarkUtil.getDefaultPercentile());
        agentdecompile.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, address, bookmarkPercentile);

        String commentTypeStr = getOptionalString(request, "commentType", null);
        if (commentTypeStr == null) {
            commentTypeStr = getOptionalString(request, "commentType", null);
        }

        // Auto-label comment type if not provided (controlled by environment variable)
        boolean autoLabel = agentdecompile.util.EnvConfigUtil.getBooleanDefault("auto_label", true);
        if (autoLabel && commentTypeStr == null) {
            Map<String, Object> suggestion = SmartSuggestionsUtil.suggestCommentType(program, address);
            commentTypeStr = (String) suggestion.get("commentType");
        }

        if (commentTypeStr == null) {
            commentTypeStr = "eol"; // Default fallback
        }

        String comment = getOptionalString(request, "comment", null);

        // Auto-label comment text if not provided (controlled by environment variable)
        if (autoLabel && (comment == null || comment.trim().isEmpty())) {
            Map<String, Object> commentSuggestion = SmartSuggestionsUtil.suggestCommentText(program, address);
            comment = (String) commentSuggestion.get("text");
        }

        if (comment == null || comment.trim().isEmpty()) {
            return createErrorResult("comment is required for action='set'");
        }

        CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
        if (commentType == null) {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be one of: pre, eol, post, plate, repeatable");
        }

        try {
            // Ghidra API: Program.startTransaction(String) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int transactionId = program.startTransaction("Set Comment");
            try {
                // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
                Listing listing = program.getListing();
                // Ghidra API: Listing.setComment(Address, CommentType, String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#setComment(ghidra.program.model.address.Address,ghidra.program.model.listing.CommentType,java.lang.String)
                listing.setComment(address, commentType, comment);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", AddressUtil.formatAddress(address));
                result.put("commentType", commentTypeStr);
                result.put("comment", comment);

                // Ghidra API: Program.endTransaction(int, boolean) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Set comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error setting comment", e);
            return createErrorResult("Failed to set comment: " + e.getMessage());
        }
    }

    /**
     * Get optional comments array from request for batch operations
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getOptionalCommentsArray(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Use getParameterAsList to support both camelCase and snake_case parameter names
        List<Object> commentsList = getParameterAsList(request.arguments(), "comments");
        if (commentsList.isEmpty()) {
            return null;
        }
        Object value = commentsList.size() == 1 ? commentsList.get(0) : commentsList;
        if (value instanceof List) {
            return (List<Map<String, Object>>) value;
        }
        throw new IllegalArgumentException("Parameter 'comments' must be an array");
    }

    /**
     * Handle batch setting of multiple comments in a single transaction
     */
    private McpSchema.CallToolResult handleBatchSetComments(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            List<Map<String, Object>> commentsArray) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();

        try {
            // Ghidra API: Program.startTransaction(String) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int transactionId = program.startTransaction("Batch Set Comments");
            try {
                for (int i = 0; i < commentsArray.size(); i++) {
                    Map<String, Object> commentObj = commentsArray.get(i);

                    // Extract address
                    Object addressObj = commentObj.get("addressOrSymbol");
                    if (addressObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'addressOrSymbol' field in comment object"));
                        continue;
                    }
                    String addressStr = addressObj.toString();

                    // Extract comment text
                    Object commentObjValue = commentObj.get("comment");
                    if (commentObjValue == null) {
                        errors.add(createErrorInfo(i, "Missing 'comment' field in comment object"));
                        continue;
                    }
                    String comment = commentObjValue.toString();

                    // Extract comment type (optional, defaults to "eol")
                    String commentTypeStr = "eol";
                    Object commentTypeObj = commentObj.get("commentType");
                    if (commentTypeObj != null) {
                        commentTypeStr = commentTypeObj.toString();
                    } else {
                        // Also check snake_case variant for backward compatibility
                        commentTypeObj = commentObj.get("comment_type");
                        if (commentTypeObj != null) {
                            commentTypeStr = commentTypeObj.toString();
                        }
                    }

                    // Resolve address
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(createErrorInfo(i, "Could not resolve address or symbol: " + addressStr));
                        continue;
                    }

                    // Validate comment type
                    CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
                    if (commentType == null) {
                        errors.add(createErrorInfo(i, "Invalid comment type: " + commentTypeStr +
                            ". Must be one of: pre, eol, post, plate, repeatable"));
                        continue;
                    }

                    // Set the comment
                    // Ghidra API: Listing.setComment(Address, CommentType, String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#setComment(ghidra.program.model.address.Address,ghidra.program.model.listing.CommentType,java.lang.String)
                    listing.setComment(address, commentType, comment);

                    // Record success
                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("commentType", commentTypeStr);
                    result.put("comment", comment);
                    results.add(result);
                }

                // Ghidra API: Program.endTransaction(int, boolean) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Batch set comments");

                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("total", commentsArray.size());
                response.put("succeeded", results.size());
                response.put("failed", errors.size());
                response.put("results", results);
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }

                return createJsonResult(response);
            } catch (Exception e) {
                // Ghidra API: Program.endTransaction(int, boolean) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error in batch set comments", e);
            return createErrorResult("Failed to batch set comments: " + e.getMessage());
        }
    }

    /**
     * Create error info for batch operations
     */
    private Map<String, Object> createErrorInfo(int index, String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("index", index);
        error.put("error", message);
        return error;
    }

    private McpSchema.CallToolResult handleSetDecompilationLineComment(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            String functionStr, int lineNumber) {
        String commentTypeStr = getOptionalString(request, "commentType", "eol");
        String comment = getString(request, "comment");

        // Validate comment type (only 'pre' and 'eol' are valid for decompilation comments)
        CommentType commentType;
        if ("pre".equals(commentTypeStr.toLowerCase())) {
            commentType = CommentType.PRE;
        } else if ("eol".equals(commentTypeStr.toLowerCase())) {
            commentType = CommentType.EOL;
        } else {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be 'pre' or 'eol' for decompilation comments.");
        }

        // Get function
        Function function;
        try {
            Address funcAddr = AddressUtil.resolveAddressOrSymbol(program, functionStr);
            if (funcAddr == null) {
                return createErrorResult("Could not resolve function address or symbol: " + functionStr);
            }
            // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctionContaining(ghidra.program.model.address.Address)
            function = program.getFunctionManager().getFunctionContaining(funcAddr);
            if (function == null) {
                if (AddressUtil.isUndefinedFunctionAddress(program, functionStr)) {
                    return createErrorResult("Cannot set comment at " + functionStr +
                        ": this address has code but no defined function. " +
                        "Comments require a defined function. " +
                        "Use create-function to define it first, then retry.");
                }
                return createErrorResult("Function not found at: " + functionStr);
            }
        } catch (Exception e) {
            return createErrorResult("Error resolving function: " + e.getMessage());
        }

        // Validate that the decompilation has been read for this function first
        String programPath = getString(request, "programPath");
        // Ghidra API: Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getEntryPoint()
        String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());

        // If decompilation hasn't been read yet, we'll decompile it in this method anyway,
        // so populate the tracker now to allow the operation to proceed
        // (the user will see the decompilation when we decompile it below)
        if (!hasReadDecompilation(functionKey)) {
            // Populate tracker now since we're about to decompile anyway
            DecompilationReadTracker.markAsRead(functionKey);
        }

        // Initialize decompiler
        final String toolName = "manage-comments-set";
        DecompInterface decompiler = createConfiguredDecompilerForComments(program, toolName);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        try {
            // Decompile the function
            DecompilationAttempt attempt = decompileFunctionSafelyForComments(decompiler, function, toolName);
            if (!attempt.success()) {
                return createErrorResult(attempt.errorMessage());
            }

            // Track that this function's decompilation has been read (populate after successful decompilation)
            DecompilationReadTracker.markAsRead(functionKey);

            // Get the decompiled code and markup
            ClangTokenGroup markup = attempt.results().getCCodeMarkup();
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

            // Find the address for the specified line number
            Address targetAddress = findAddressForLine(program, clangLines, lineNumber);
            if (targetAddress == null) {
                return createErrorResult("Could not find an address for line " + lineNumber +
                    " in decompiled function. The line may not correspond to any actual code.");
            }

            // Set the comment
            // Ghidra API: Program.startTransaction(String) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int transactionId = program.startTransaction("Set Decompilation Comment");
            try {
                // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
                Listing listing = program.getListing();
                // Ghidra API: Listing.setComment(Address, CommentType, String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#setComment(ghidra.program.model.address.Address,ghidra.program.model.listing.CommentType,java.lang.String)
                listing.setComment(targetAddress, commentType, comment);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
                result.put("functionName", function.getName());
                result.put("lineNumber", lineNumber);
                result.put("address", AddressUtil.formatAddress(targetAddress));
                result.put("commentType", commentTypeStr);
                result.put("comment", comment);

                // Ghidra API: Program.endTransaction(int, boolean) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Set decompilation comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError(toolName + ": Error setting decompilation line comment for " + function.getName(), e);
            return createErrorResult("Failed to set decompilation line comment: " + e.getMessage());
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult handleGetComments(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "addressOrSymbol", null);
        String startStr = getOptionalString(request, "start", null);
        String endStr = getOptionalString(request, "end", null);
        String commentTypesStr = getOptionalString(request, "commentTypes", null);
        if (commentTypesStr == null) {
            commentTypesStr = getOptionalString(request, "commentTypes", null);
        }

        AddressSetView addresses;
        if (addressStr != null) {
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Could not resolve address or symbol: " + addressStr);
            }
            addresses = new AddressSet(address, address);
        } else if (startStr != null && endStr != null) {
            Address start = AddressUtil.resolveAddressOrSymbol(program, startStr);
            Address end = AddressUtil.resolveAddressOrSymbol(program, endStr);
            if (start == null || end == null) {
                return createErrorResult("Invalid address range");
            }
            addresses = new AddressSet(start, end);
        } else {
            return createErrorResult("Either 'address' or 'start'/'end' range must be provided");
        }

        List<CommentType> types = new ArrayList<>();
        if (commentTypesStr != null && !commentTypesStr.isEmpty()) {
            String[] typeStrs = commentTypesStr.split(",");
            for (String typeStr : typeStrs) {
                CommentType type = COMMENT_TYPES.get(typeStr.trim().toLowerCase());
                if (type == null) {
                    return createErrorResult("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else {
            // Use getOptionalStringList which already supports both camelCase and snake_case via getParameterValue
            List<String> commentTypesList = getOptionalStringList(request.arguments(), "commentTypes", null);
            if (commentTypesList == null || commentTypesList.isEmpty()) {
                commentTypesList = getOptionalStringList(request.arguments(), "commentTypes", null);
            }
            if (commentTypesList != null && !commentTypesList.isEmpty()) {
                for (String typeStr : commentTypesList) {
                    CommentType type = COMMENT_TYPES.get(typeStr.toLowerCase());
                    if (type == null) {
                        return createErrorResult("Invalid comment type: " + typeStr);
                    }
                    types.add(type);
                }
            } else {
                types.addAll(COMMENT_TYPES.values());
            }
        }

        List<Map<String, Object>> comments = new ArrayList<>();
        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();

        // Ghidra API: Listing.getCodeUnits(AddressSetView, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getCodeUnits(ghidra.program.model.address.AddressSetView,boolean)
        CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true);
        while (codeUnits.hasNext()) {
            CodeUnit codeUnit = codeUnits.next();
            // Ghidra API: CodeUnit.getAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getAddress()
            Address addr = codeUnit.getAddress();

            for (CommentType type : types) {
                // Ghidra API: CodeUnit.getComment(CommentType) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getComment(ghidra.program.model.listing.CommentType)
                String comment = codeUnit.getComment(type);
                if (comment != null && !comment.isEmpty()) {
                    Map<String, Object> commentInfo = new HashMap<>();
                    commentInfo.put("address", AddressUtil.formatAddress(addr));
                    commentInfo.put("commentType", getCommentTypeName(type));
                    commentInfo.put("comment", comment);
                    comments.add(commentInfo);
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("comments", comments);
        result.put("count", comments.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleRemoveComment(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "addressOrSymbol", null);
        if (addressStr == null) {
            return createErrorResult("addressOrSymbol is required for action='remove'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        // Intelligent bookmarking: check if address should be bookmarked
        double bookmarkPercentile = agentdecompile.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
            agentdecompile.util.IntelligentBookmarkUtil.getDefaultPercentile());
        agentdecompile.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, address, bookmarkPercentile);

        String commentTypeStr = getOptionalString(request, "commentType", null);
        if (commentTypeStr == null) {
            commentTypeStr = getOptionalString(request, "commentType", null);
        }
        if (commentTypeStr == null) {
            return createErrorResult("commentType is required for action='remove'");
        }

        CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
        if (commentType == null) {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be one of: pre, eol, post, plate, repeatable");
        }

        try {
            // Ghidra API: Program.startTransaction(String) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int transactionId = program.startTransaction("Remove Comment");
            try {
                // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
                Listing listing = program.getListing();
                // Ghidra API: Listing.setComment(Address, CommentType, String) — null to remove - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#setComment(ghidra.program.model.address.Address,ghidra.program.model.listing.CommentType,java.lang.String)
                listing.setComment(address, commentType, null);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", AddressUtil.formatAddress(address));
                result.put("commentType", commentTypeStr);

                // Ghidra API: Program.endTransaction(int, boolean) (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Remove comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error removing comment", e);
            return createErrorResult("Failed to remove comment: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> searchCommentsInProgram(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, int limit) {
        String searchText = getOptionalString(request, "searchText", null);
        if (searchText == null) {
            searchText = getOptionalString(request, "searchText", null);
        }
        if (searchText == null) {
            throw new IllegalArgumentException("searchText is required for action='search'");
        }

        boolean caseSensitive = getOptionalBoolean(request, "caseSensitive", false);

        String commentTypesStr = getOptionalString(request, "commentTypes", null);
        List<String> commentTypesList = getOptionalStringList(request.arguments(), "commentTypes", null);

        // maxResults is handled by the caller via 'limit', but we read it here to parse types
        
        List<CommentType> types = new ArrayList<>();
        if (commentTypesStr != null && !commentTypesStr.isEmpty()) {
            String[] typeStrs = commentTypesStr.split(",");
            for (String typeStr : typeStrs) {
                CommentType type = COMMENT_TYPES.get(typeStr.trim().toLowerCase());
                if (type == null) {
                    throw new IllegalArgumentException("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else if (commentTypesList != null && !commentTypesList.isEmpty()) {
            for (String typeStr : commentTypesList) {
                CommentType type = COMMENT_TYPES.get(typeStr.toLowerCase());
                if (type == null) {
                    throw new IllegalArgumentException("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else {
            types.addAll(COMMENT_TYPES.values());
        }

        String searchLower = caseSensitive ? searchText : searchText.toLowerCase();
        List<Map<String, Object>> results = new ArrayList<>();
        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();

        for (CommentType type : types) {
            if (results.size() >= limit) break;

            // Ghidra API: Listing.getCommentAddressIterator(CommentType, AddressSetView, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getCommentAddressIterator(ghidra.program.model.listing.CommentType,ghidra.program.model.address.AddressSetView,boolean)
            AddressIterator commentAddrs = listing.getCommentAddressIterator(
                type, program.getMemory(), true);

            while (commentAddrs.hasNext()) {
                if (results.size() >= limit) break;

                Address addr = commentAddrs.next();
                // Ghidra API: Listing.getComment(CommentType, Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getComment(ghidra.program.model.listing.CommentType,ghidra.program.model.address.Address)
                String comment = listing.getComment(type, addr);

                if (comment != null) {
                    String commentLower = caseSensitive ? comment : comment.toLowerCase();
                    if (commentLower.contains(searchLower)) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("address", AddressUtil.formatAddress(addr));
                        result.put("commentType", getCommentTypeName(type));
                        result.put("comment", comment);

                        // Ghidra API: Listing.getCodeUnitAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getCodeUnitAt(ghidra.program.model.address.Address)
                        CodeUnit cu = listing.getCodeUnitAt(addr);
                        if (cu != null) {
                            result.put("codeUnit", cu.toString());
                        }

                        results.add(result);
                    }
                }
            }
        }

        return results;
    }

    /**
     * @deprecated Use searchCommentsInProgram instead
     */
    private McpSchema.CallToolResult handleSearchComments(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
         // This method is kept if needed but we switched to multi-program search
         return createErrorResult("Deprecated internal method called");
    }

    private List<Map<String, Object>> searchDecompilationInProgram(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            int limit) {
        String pattern = getOptionalString(request, "pattern", null);
        if (pattern == null) {
            throw new IllegalArgumentException("pattern is required for action='search_decomp'");
        }

        boolean caseSensitive = getOptionalBoolean(request, "caseSensitive", false);
        boolean overrideMaxFunctionsLimit = getOptionalBoolean(request, "overrideMaxFunctionsLimit", false);

        if (pattern.trim().isEmpty()) {
            throw new IllegalArgumentException("Search pattern cannot be empty");
        }

        ConfigManager config = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        int maxFunctions = config.getMaxDecompilerSearchFunctions();
        // Ghidra API: Program.getFunctionManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
        FunctionManager functionManager = program.getFunctionManager();
        // Ghidra API: FunctionManager.getFunctionCount() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctionCount()
        if (functionManager.getFunctionCount() > maxFunctions && !overrideMaxFunctionsLimit) {
            throw new IllegalArgumentException("Program " + program.getName() + " has " + functionManager.getFunctionCount() +
                " functions, which exceeds the maximum limit of " + maxFunctions +
                ". Use 'override_max_functions_limit' to bypass this check.");
        }

        try {
            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            Pattern regex = Pattern.compile(pattern, flags);

            DecompInterface decompiler = createConfiguredDecompilerForComments(program, "manage-comments-search_decomp");
            if (decompiler == null) {
                 throw new RuntimeException("Failed to initialize decompiler");
            }

            List<Map<String, Object>> searchResults = new ArrayList<>();
            try {
                // Ghidra API: FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    if (searchResults.size() >= limit) {
                        break;
                    }
                    Function function = functions.next();

                    // Ghidra API: Function.isExternal() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#isExternal()
                    if (function.isExternal()) {
                        continue;
                    }

                    try {
                        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(
                            config.getDecompilerTimeoutSeconds(),
                            TimeUnit.SECONDS);
                        // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
                        DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

                        if (monitor.isCancelled()) {
                            continue;
                        }

                        if (decompileResults.decompileCompleted()) {
                            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                            String decompCode = decompiledFunction.getC();
                            String[] lines = decompCode.split("\n");

                            for (int i = 0; i < lines.length; i++) {
                                if (searchResults.size() >= limit) {
                                    break;
                                }
                                String line = lines[i];
                                Matcher matcher = regex.matcher(line);

                                if (matcher.find()) {
                                    Map<String, Object> result = new HashMap<>();
                                    // Ghidra API: Function.getName() (Namespace), Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getEntryPoint()
                                    result.put("functionName", function.getName());
                                    result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                                    result.put("lineNumber", i + 1);
                                    result.put("lineContent", line.trim());
                                    result.put("matchStart", matcher.start());
                                    result.put("matchEnd", matcher.end());
                                    result.put("matchedText", matcher.group());
                                    searchResults.add(result);
                                }
                            }
                        }
                    } catch (Exception e) {
                        continue;
                    }
                }
            } finally {
                decompiler.dispose();
            }

            return searchResults;
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex pattern: " + e.getMessage());
        } catch (Exception e) {
            logError("Error during decompilation search", e);
            throw new RuntimeException("Search failed: " + e.getMessage());
        }
    }

    /**
     * @deprecated Use searchDecompilationInProgram instead
     */
    private McpSchema.CallToolResult handleSearchDecompilation(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            io.modelcontextprotocol.server.McpSyncServerExchange exchange) {
        return createErrorResult("Deprecated internal method called");
    }

    /**
     * Get the string name for a comment type constant
     * @param commentType The comment type enum
     * @return The string name
     */
    private String getCommentTypeName(CommentType commentType) {
        for (Map.Entry<String, CommentType> entry : COMMENT_TYPES.entrySet()) {
            if (entry.getValue() == commentType) {
                return entry.getKey();
            }
        }
        return "unknown";
    }
}
