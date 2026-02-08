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
package agentdecompile.tools.getfunction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.util.AddressUtil;
import agentdecompile.plugin.ConfigManager;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.listing.Variable;
import ghidra.util.exception.InvalidInputException;
import agentdecompile.tools.ProgramValidationException;

/**
 * Tool provider for get-function.
 * Provides function details in various formats: decompiled code, assembly, function information, or internal calls.
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Function}, {@link ghidra.app.decompiler.DecompInterface} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html">Function API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html">DecompInterface API</a>,
 * {@link ghidra.util.UndefinedFunction} for addresses without defined functions.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class GetFunctionToolProvider extends AbstractToolProvider {

    public GetFunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetFunctionTool();
    }

    private void registerGetFunctionTool() {
        Map<String, Object> properties = new HashMap<>();
        Map<String, Object> programPathProperty = new HashMap<>();
        programPathProperty.put("oneOf", List.of(
            Map.of("type", "string", "description", "Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."),
            Map.of("type", "array", "items", Map.of("type", "string"), "description", "Array of program paths for multi-program analysis")
        ));
        properties.put("programPath", programPathProperty);
        Map<String, Object> identifierProperty = new HashMap<>();
        identifierProperty.put("description", "Function name or address (e.g., 'main' or '0x401000'). Can be a single string, an array of strings, or a JSON-encoded array string for batch operations. When omitted, returns all functions.");
        identifierProperty.put("oneOf", List.of(
            Map.of("type", "string", "description", "Single function identifier (name or address) or JSON-encoded array of identifiers"),
            Map.of("type", "array", "items", Map.of("type", "string"), "description", "Array of function names or addresses for batch operations")
        ));
        properties.put("identifier", identifierProperty);
        properties.put("view", Map.of(
            "type", "string",
            "description", "View mode: 'decompile', 'disassemble', 'info', 'calls'",
            "enum", List.of("decompile", "disassemble", "info", "calls"),
            "default", "decompile"
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Line number to start reading from when view='decompile' (1-based)",
            "default", 1
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Number of lines to return when view='decompile'",
            "default", 50
        ));
        properties.put("includeCallers", Map.of(
            "type", "boolean",
            "description", "Include list of functions that call this one when view='decompile'",
            "default", false
        ));
        properties.put("includeCallees", Map.of(
            "type", "boolean",
            "description", "Include list of functions this one calls when view='decompile'",
            "default", false
        ));
        properties.put("includeComments", Map.of(
            "type", "boolean",
            "description", "Whether to include comments in the decompilation when view='decompile'",
            "default", false
        ));
        properties.put("includeIncomingReferences", Map.of(
            "type", "boolean",
            "description", "Whether to include incoming cross references when view='decompile'",
            "default", true
        ));
        properties.put("includeReferenceContext", Map.of(
            "type", "boolean",
            "description", "Whether to include code context snippets from calling functions when view='decompile'",
            "default", true
        ));

        List<String> required = new ArrayList<>();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions")
            .title("Get Functions")
            .description("Get function details in various formats: decompiled code, assembly, function information, or internal calls. Supports single function, batch operations when identifier is an array, or all functions when identifier is omitted.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Use getParameterAsList to support both camelCase and snake_case parameter names
                List<Object> identifierList = getParameterAsList(request.arguments(), "identifier");
                
                // When identifier is omitted, return all functions
                if (identifierList.isEmpty()) {
                    return handleAllFunctions(request);
                }

                // Handle programPath as array or string - supports both camelCase and snake_case
                List<Object> programPathList = getParameterAsList(request.arguments(), "programPath");
                if (programPathList.isEmpty()) {
                    programPathList = getParameterAsList(request.arguments(), "programPath");
                }
                Object programPathValue = programPathList.isEmpty() ? null : (programPathList.size() == 1 ? programPathList.get(0) : programPathList);
                Program program;
                if (programPathValue instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> programPaths = (List<String>) programPathValue;
                    if (programPaths.isEmpty()) {
                        return createErrorResult("programPath array cannot be empty");
                    }
                    program = agentdecompile.util.ProgramLookupUtil.getValidatedProgram(programPaths.get(0));
                } else {
                    program = getProgramFromArgs(request);
                }

                // Check if identifier is an array
                // Handle case where identifier might be a JSON-encoded array string
                Object identifierValue = identifierList.get(0);
                if (identifierList.size() > 1 || (identifierValue instanceof List)) {
                    // Batch mode: use the list directly, or unwrap if nested
                    List<?> batchList = identifierList.size() > 1 ? identifierList : (List<?>) identifierValue;
                    return handleBatchGetFunction(program, request, batchList);
                } else if (identifierValue instanceof String identifierStr) {
                    // Check if it's a JSON-encoded array string
                    if (identifierStr.trim().startsWith("[") && identifierStr.trim().endsWith("]")) {
                        try {
                            @SuppressWarnings("unchecked")
                            List<String> parsedList = JSON.readValue(identifierStr, List.class);
                            if (parsedList.size() > 1) {
                                return handleBatchGetFunction(program, request, parsedList);
                            } else if (parsedList.size() == 1) {
                                identifierValue = parsedList.get(0);
                            }
                        } catch (JsonProcessingException e) {
                            // Not a valid JSON array, treat as regular string identifier
                        }
                    }
                }

                // Single function mode - ensure we have a valid identifier
                if (identifierValue == null) {
                    return createErrorResult("Invalid identifier value");
                }
                String identifier = identifierValue.toString();
                String view = getOptionalString(request, "view", "decompile");

                Function function = resolveFunction(program, identifier);
                if (function == null) {
                    return createErrorResult("Function not found: " + identifier);
                }

                // Intelligent bookmarking: check if function entry point should be bookmarked
                double bookmarkPercentile = agentdecompile.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
                    agentdecompile.util.IntelligentBookmarkUtil.getDefaultPercentile());
                // Ghidra API: Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getEntryPoint()
                agentdecompile.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, function.getEntryPoint(), bookmarkPercentile);

                return switch (view) {
                    case "decompile" -> handleDecompileView(program, function, request);
                    case "disassemble" -> handleDisassembleView(program, function);
                    case "info" -> handleInfoView(program, function);
                    case "calls" -> handleCallsView(program, function);
                    default -> createErrorResult("Invalid view mode: " + view);
                };
            } catch (IllegalArgumentException e) {
                // Try to return default response with error message
                Program program = tryGetProgramSafely(request.arguments());
                if (program != null) {
                    // Return empty result with error message
                    Map<String, Object> errorInfo = createIncorrectArgsErrorMap();
                    Map<String, Object> result = new HashMap<>();
                    result.put("error", errorInfo.get("error"));
                    // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                    result.put("programPath", program.getDomainFile().getPathname());
                    return createJsonResult(result);
                }
                // If we can't get a default response, return error with message
                return createErrorResult(e.getMessage() + " " + createIncorrectArgsErrorMap().get("error"));
            } catch (ProgramValidationException e) {
                logError("Error in get-function", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private Function resolveFunction(Program program, String identifier) {
        // Try as address or symbol first
        Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
        if (address != null) {
            Function function = AddressUtil.getContainingFunction(program, address);
            if (function != null) {
                return function;
            }
            // Try undefined function
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
            // Ghidra API: UndefinedFunction.findFunction(Program, Address, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/util/UndefinedFunction.html#findFunction(ghidra.program.model.listing.Program,ghidra.program.model.address.Address,ghidra.util.task.TaskMonitor)
            Function undefinedFunction = UndefinedFunction.findFunction(program, address, monitor);
            if (undefinedFunction != null) {
                return undefinedFunction;
            }
        }

        // Try as function name
        // Ghidra API: Program.getFunctionManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
        FunctionManager functionManager = program.getFunctionManager();
        // Ghidra API: FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            // Ghidra API: FunctionIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html#next()
            Function f = functions.next();
            // Ghidra API: Function.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
            if (f.getName().equals(identifier) || f.getName().equalsIgnoreCase(identifier)) {
                return f;
            }
        }

        return null;
    }

    private McpSchema.CallToolResult handleDecompileView(Program program, Function function, CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 1);
        int limit = getOptionalInt(request, "limit", 50);
        boolean includeCallers = getOptionalBoolean(request, "includeCallers", false);
        boolean includeCallees = getOptionalBoolean(request, "includeCallees", false);
        boolean includeComments = getOptionalBoolean(request, "includeComments", false);
        boolean includeIncomingReferences = getOptionalBoolean(request, "includeIncomingReferences", true);
        boolean includeReferenceContext = getOptionalBoolean(request, "includeReferenceContext", true);

        Map<String, Object> resultData = new HashMap<>();
        // Ghidra API: Function.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
        resultData.put("function", function.getName());
        // Ghidra API: Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getEntryPoint()
        resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        // Ghidra API: Program.getName() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getName()
        resultData.put("programName", program.getName());

        DecompInterface decompiler = createConfiguredDecompiler(program);
        if (decompiler == null) {
            resultData.put("decompilationError", "Failed to initialize decompiler");
            resultData.put("decompilation", "");
            return createJsonResult(resultData);
        }

        try {
            TaskMonitor monitor = createTimeoutMonitor();
            // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

            // Ghidra API: TaskMonitor.isCancelled() - https://ghidra.re/ghidra_docs/api/ghidra/util/task/TaskMonitor.html#isCancelled()
            if (monitor.isCancelled()) {
                return createErrorResult("Decompilation timed out after " + getTimeoutSeconds() + " seconds");
            }

            // Ghidra API: DecompileResults.decompileCompleted(), getErrorMessage() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#decompileCompleted()
            if (!decompileResults.decompileCompleted()) {
                return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
            }

            // Ghidra API: DecompileResults.getDecompiledFunction(), getCCodeMarkup() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#getDecompiledFunction()
            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
            ClangTokenGroup markup = decompileResults.getCCodeMarkup();

            // Get synchronized decompilation with optional comments and incoming references
            // Ghidra API: DecompiledFunction.getC() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html#getC()
            Map<String, Object> syncedContent = getSynchronizedContent(program, markup, decompiledFunction.getC(),
                offset, limit, false, includeComments, includeIncomingReferences, includeReferenceContext, function);

            // Add content to results
            resultData.putAll(syncedContent);

            if (syncedContent.containsKey("decompilation")) {
                String decompCode = (String) syncedContent.get("decompilation");
                resultData.put("decompiledCode", decompCode);
                resultData.put("code", decompCode);
            }

            // Get additional details
            // Ghidra API: DecompiledFunction.getSignature() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html#getSignature()
            resultData.put("decompSignature", decompiledFunction.getSignature());

            // Add callers/callees if requested
            if (includeCallers) {
                List<Function> callers = new ArrayList<>();
                // Ghidra API: Function.getCallingFunctions(TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getCallingFunctions(ghidra.util.task.TaskMonitor)
                for (Function caller : function.getCallingFunctions(monitor)) {
                    callers.add(caller);
                }
                List<Map<String, Object>> callerInfo = new ArrayList<>();
                for (Function caller : callers) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", caller.getName());
                    info.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                    callerInfo.add(info);
                }
                resultData.put("callers", callerInfo);
            }

            if (includeCallees) {
                List<Function> callees = new ArrayList<>();
                // Ghidra API: Function.getCalledFunctions(TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getCalledFunctions(ghidra.util.task.TaskMonitor)
                for (Function callee : function.getCalledFunctions(monitor)) {
                    callees.add(callee);
                }
                List<Map<String, Object>> calleeInfo = new ArrayList<>();
                for (Function callee : callees) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", callee.getName());
                    info.put("address", AddressUtil.formatAddress(callee.getEntryPoint()));
                    calleeInfo.add(info);
                }
                resultData.put("callees", calleeInfo);
            }

            return createJsonResult(resultData);
        } catch (Exception e) {
            logError("Error during decompilation", e);
            return createErrorResult("Exception during decompilation: " + e.getMessage());
        } finally {
            // Ghidra API: DecompInterface.dispose() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#dispose()
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult handleDisassembleView(Program program, Function function) {
        List<Map<String, Object>> instructions = new ArrayList<>();
        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();

        // Ghidra API: Listing.getInstructions(AddressSetView, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getInstructions(ghidra.program.model.address.AddressSetView,boolean)
        // Ghidra API: Function.getBody() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
        for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
            Map<String, Object> instrData = new HashMap<>();
            // Ghidra API: Instruction.getMinAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getMinAddress()
            Address addr = instr.getMinAddress();
            instrData.put("address", AddressUtil.formatAddress(addr));
            instrData.put("instruction", instr.toString());

            // Ghidra API: Listing.getCodeUnitAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getCodeUnitAt(ghidra.program.model.address.Address)
            CodeUnit codeUnit = listing.getCodeUnitAt(addr);
            if (codeUnit != null) {
                // Ghidra API: CodeUnit.getComment(CommentType) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getComment(ghidra.program.model.listing.CommentType)
                String comment = codeUnit.getComment(CommentType.EOL);
                if (comment == null || comment.isEmpty()) {
                    comment = codeUnit.getComment(CommentType.PRE);
                }
                if (comment != null && !comment.isEmpty()) {
                    instrData.put("comment", comment);
                }
            }

            instructions.add(instrData);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("instructions", instructions);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleInfoView(Program program, Function function) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", function.getName());
        info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        // Ghidra API: Function.getReturnType() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getReturnType()
        info.put("returnType", function.getReturnType().toString());
        // Ghidra API: Function.getCallingConventionName(), isExternal(), isThunk() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getCallingConventionName()
        info.put("callingConvention", function.getCallingConventionName());
        info.put("isExternal", function.isExternal());
        info.put("isThunk", function.isThunk());

        // Parameters
        List<Map<String, Object>> parameters = new ArrayList<>();
        // Ghidra API: Function.getParameterCount(), getParameter(int) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getParameterCount()
        for (int i = 0; i < function.getParameterCount(); i++) {
            Parameter param = function.getParameter(i);
            Map<String, Object> paramInfo = new HashMap<>();
            // Ghidra API: Parameter.getName(), getDataType() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Parameter.html#getName()
            paramInfo.put("name", param.getName());
            paramInfo.put("dataType", param.getDataType().toString());
            paramInfo.put("ordinal", i);
            parameters.add(paramInfo);
        }
        info.put("parameters", parameters);

        // Local variables
        List<Map<String, Object>> locals = new ArrayList<>();
        // Ghidra API: Function.getLocalVariables() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getLocalVariables()
        for (Variable local : function.getLocalVariables()) {
            Map<String, Object> localInfo = new HashMap<>();
            localInfo.put("name", local.getName());
            localInfo.put("dataType", local.getDataType().toString());
            locals.add(localInfo);
        }
        info.put("localVariables", locals);

        // Function body info
        // Ghidra API: Function.getBody() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
        var body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            info.put("startAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            // Ghidra API: AddressSetView.getMaxAddress(), getNumAddresses() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSetView.html#getMaxAddress()
            info.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            info.put("sizeInBytes", body.getNumAddresses());
        }

        return createJsonResult(info);
    }

    private McpSchema.CallToolResult handleCallsView(Program program, Function function) {
        List<Map<String, Object>> calls = new ArrayList<>();
        Listing listing = program.getListing();

        for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
            // Ghidra API: Instruction.getFlows() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getFlows()
            Address[] flowDestinations = instr.getFlows();
            for (Address dest : flowDestinations) {
                // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
                Function calledFunc = program.getFunctionManager().getFunctionAt(dest);
                if (calledFunc != null) {
                    Map<String, Object> callInfo = new HashMap<>();
                    callInfo.put("address", AddressUtil.formatAddress(instr.getMinAddress()));
                    callInfo.put("calledFunction", calledFunc.getName());
                    callInfo.put("calledAddress", AddressUtil.formatAddress(dest));
                    calls.add(callInfo);
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("calls", calls);
        return createJsonResult(result);
    }

    private TaskMonitor createTimeoutMonitor() {
        ConfigManager configManager = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private DecompInterface createConfiguredDecompiler(Program program) {
        DecompInterface decompiler = new DecompInterface();
        // Ghidra API: DecompInterface.toggleCCode(boolean), toggleSyntaxTree(boolean), setSimplificationStyle(String) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        // Ghidra API: DecompInterface.openProgram(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#openProgram(ghidra.program.model.listing.Program)
        if (!decompiler.openProgram(program)) {
            logError("Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    private int getTimeoutSeconds() {
        ConfigManager configManager = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        return configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
    }

    /** Map of Ghidra comment types to their string names for JSON output */
    private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        CommentType.PRE, "pre",
        CommentType.EOL, "eol",
        CommentType.POST, "post",
        CommentType.PLATE, "plate",
        CommentType.REPEATABLE, "repeatable"
    );

    /**
     * Get synchronized decompilation content with optional comments and incoming references
     */
    private Map<String, Object> getSynchronizedContent(Program program, ClangTokenGroup markup,
            String fullDecompCode, int offset, Integer limit, boolean includeDisassembly,
            boolean includeComments, boolean includeIncomingReferences, boolean includeReferenceContext, Function function) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Convert markup to lines
            String[] decompLines = fullDecompCode.split("\n");

            // Calculate range
            int totalLines = decompLines.length;
            int startIdx = Math.max(0, offset - 1); // Convert to 0-based
            int endIdx = limit != null ? Math.min(totalLines, startIdx + limit) : totalLines;

            result.put("totalLines", totalLines);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }

            // Include incoming references at the top level if requested
            if (includeIncomingReferences) {
                int maxIncomingRefs = 10;
                int totalRefCount = 0;
                // Ghidra API: Program.getReferenceManager(), ReferenceManager.getReferencesTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager()
                var refIterator = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
                while (refIterator.hasNext()) {
                    // Ghidra API: ReferenceIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceIterator.html#next()
                    refIterator.next();
                    totalRefCount++;
                }

                List<Map<String, Object>> incomingRefs = agentdecompile.util.DecompilationContextUtil
                    .getEnhancedIncomingReferences(program, function, includeReferenceContext, maxIncomingRefs);

                if (!incomingRefs.isEmpty()) {
                    result.put("incomingReferences", incomingRefs);
                    result.put("totalIncomingReferences", totalRefCount);

                    if (totalRefCount > maxIncomingRefs) {
                        result.put("incomingReferencesLimited", true);
                        result.put("incomingReferencesMessage", String.format(
                            "Showing first %d of %d references. Use 'find-cross-references' tool with target='%s' and mode='to' to see all references.",
                            maxIncomingRefs, totalRefCount, function.getName()
                        ));
                    }
                }
            }

            // Just return ranged decompilation (includeDisassembly not used in get-function view='decompile')
            StringBuilder rangedDecomp = new StringBuilder();
            for (int i = startIdx; i < endIdx; i++) {
                rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
            }
            result.put("decompilation", rangedDecomp.toString());

            // Include all comments for the function if requested
            if (includeComments) {
                List<Map<String, Object>> functionComments = getAllCommentsInFunction(program, function);
                if (!functionComments.isEmpty()) {
                    result.put("comments", functionComments);
                }
            }

        } catch (Exception e) {
            logError("Error creating synchronized content", e);
            // Fallback to simple line range
            result.put("decompilation", applyLineRange(fullDecompCode, offset, limit));
            result.put("totalLines", fullDecompCode.split("\n").length);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }
        }

        return result;
    }

    /**
     * Get all comments in a function
     */
    private List<Map<String, Object>> getAllCommentsInFunction(Program program, Function function) {
        List<Map<String, Object>> comments = new ArrayList<>();

        try {
            Listing listing = program.getListing();
            var body = function.getBody();

            // Ghidra API: Listing.getCodeUnits(AddressSetView, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getCodeUnits(ghidra.program.model.address.AddressSetView,boolean)
            CodeUnitIterator codeUnits = listing.getCodeUnits(body, true);
            while (codeUnits.hasNext()) {
                // Ghidra API: CodeUnitIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnitIterator.html#next()
                CodeUnit cu = codeUnits.next();
                // Ghidra API: CodeUnit.getAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getAddress()
                Address addr = cu.getAddress();

                // Check all comment types
                for (Entry<CommentType, String> entry : COMMENT_TYPE_NAMES.entrySet()) {
                    addCommentIfExists(comments, cu, entry.getKey(), entry.getValue(), addr);
                }
            }
        } catch (Exception e) {
            logError("Error getting all comments in function", e);
        }

        return comments;
    }

    /**
     * Add a comment to the list if it exists
     */
    private void addCommentIfExists(List<Map<String, Object>> comments, CodeUnit cu,
            CommentType commentType, String typeString, Address address) {
        // Ghidra API: CodeUnit.getComment(CommentType) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getComment(ghidra.program.model.listing.CommentType)
        String comment = cu.getComment(commentType);
        if (comment != null && !comment.isEmpty()) {
            Map<String, Object> commentInfo = new HashMap<>();
            commentInfo.put("address", AddressUtil.formatAddress(address));
            commentInfo.put("type", typeString);
            commentInfo.put("comment", comment);
            comments.add(commentInfo);
        }
    }

    /**
     * Apply line range to text
     */
    private String applyLineRange(String text, int offset, Integer limit) {
        String[] lines = text.split("\n");
        int startIdx = Math.max(0, offset - 1); // Convert to 0-based
        int endIdx = limit != null ? Math.min(lines.length, startIdx + limit) : lines.length;

        StringBuilder result = new StringBuilder();
        for (int i = startIdx; i < endIdx; i++) {
            result.append(String.format("%4d\t%s\n", i + 1, lines[i]));
        }

        return result.toString();
    }

    /**
     * Handle batch get-functions operations when identifier is an array
     */
    private McpSchema.CallToolResult handleBatchGetFunction(Program program, CallToolRequest request, List<?> identifierList) {
        String view = getOptionalString(request, "view", "decompile");
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        for (int i = 0; i < identifierList.size(); i++) {
            try {
                String identifier = identifierList.get(i).toString();
                Function function = resolveFunction(program, identifier);
                if (function == null) {
                    errors.add(Map.of("index", i, "identifier", identifier, "error", "Function not found"));
                    continue;
                }

                // For batch operations, get the full result for each function
                Map<String, Object> functionResult = new HashMap<>();

                switch (view) {
                    case "decompile" -> {
                        McpSchema.CallToolResult decompileResult = handleDecompileView(program, function, request);
                        if (decompileResult.isError()) {
                            String errorText = extractTextFromContent(decompileResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            // Extract structured data from JSON result
                            Map<String, Object> decompileData = extractJsonDataFromResult(decompileResult);
                            functionResult.putAll(decompileData);
                        }
                    }
                    case "disassemble" -> {
                        McpSchema.CallToolResult disassembleResult = handleDisassembleView(program, function);
                        if (disassembleResult.isError()) {
                            String errorText = extractTextFromContent(disassembleResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> disassembleData = extractJsonDataFromResult(disassembleResult);
                            functionResult.putAll(disassembleData);
                        }
                    }
                    case "info" -> {
                        McpSchema.CallToolResult infoResult = handleInfoView(program, function);
                        if (infoResult.isError()) {
                            String errorText = extractTextFromContent(infoResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> infoData = extractJsonDataFromResult(infoResult);
                            functionResult.putAll(infoData);
                        }
                    }
                    case "calls" -> {
                        McpSchema.CallToolResult callsResult = handleCallsView(program, function);
                        if (callsResult.isError()) {
                            String errorText = extractTextFromContent(callsResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> callsData = extractJsonDataFromResult(callsResult);
                            functionResult.putAll(callsData);
                        }
                    }
                    default -> {
                        errors.add(Map.of("index", i, "identifier", identifier, "error", "Invalid view: " + view));
                        continue;
                    }
                }

                if (!functionResult.isEmpty()) {
                    results.add(functionResult);
                }
            } catch (Exception e) {
                errors.add(Map.of("index", i, "identifier", identifierList.get(i).toString(), "error", e.getMessage()));
            }
        }

        // Return direct array of results when batch mode is used
        return createJsonResult(results);
    }

    /**
     * Handle request when identifier is omitted - returns all functions
     */
    private McpSchema.CallToolResult handleAllFunctions(CallToolRequest request) {
        try {
            // Supports both camelCase and snake_case via getParameterValue
            List<Object> programPathList = getParameterAsList(request.arguments(), "programPath");
            Object programPathValue = programPathList.isEmpty() ? null : (programPathList.size() == 1 ? programPathList.get(0) : programPathList);
            List<Program> programs = new ArrayList<>();
            
            if (programPathValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> programPaths = (List<String>) programPathValue;
                for (String path : programPaths) {
                    try {
                        Program p = agentdecompile.util.ProgramLookupUtil.getValidatedProgram(path);
                        // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
                        if (p != null && !p.isClosed()) {
                            programs.add(p);
                        }
                    } catch (ProgramValidationException e) {
                        // Skip invalid programs
                    }
                }
            } else {
                Program program = getProgramFromArgs(request);
                if (program != null) {
                    programs.add(program);
                }
            }
            
            if (programs.isEmpty()) {
                return createErrorResult("No valid programs found");
            }
            
            boolean filterDefaultNames = agentdecompile.util.EnvConfigUtil.getBooleanDefault("filter_default_names", true);
            List<Map<String, Object>> programResults = new ArrayList<>();
            int totalFunctions = 0;
            
            for (Program program : programs) {
                // Track initial function count for signature scanning
                // Ghidra API: Program.getFunctionManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
                FunctionManager funcManager = program.getFunctionManager();
                // Ghidra API: FunctionManager.getFunctionCount() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctionCount()
                int initialFunctionCount = funcManager.getFunctionCount();
                
                // Run signature scanning to discover undefined functions
                Map<String, Object> signatureScanResults = runSignatureScanning(program);
                
                // Get final function count
                int finalFunctionCount = funcManager.getFunctionCount();
                int functionsDiscovered = finalFunctionCount - initialFunctionCount;

                // Collect all functions
                List<Map<String, Object>> functions = new ArrayList<>();
                FunctionIterator funcIter = funcManager.getFunctions(true);
                TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(300, TimeUnit.SECONDS);

                while (funcIter.hasNext() && !monitor.isCancelled()) {
                    Function function = funcIter.next();

                    // Ghidra API: Function.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
                    if (filterDefaultNames && agentdecompile.util.SymbolUtil.isDefaultSymbolName(function.getName())) {
                        continue;
                    }
                    
                    Map<String, Object> funcInfo = buildFunctionInfo(program, function, monitor);
                    functions.add(funcInfo);
                }
                
                // Build procedural/actions object
                Map<String, Object> actions = new HashMap<>();
                actions.put("signatureScanning", signatureScanResults);
                actions.put("functionsDiscovered", functionsDiscovered);
                actions.put("initialFunctionCount", initialFunctionCount);
                actions.put("finalFunctionCount", finalFunctionCount);
                
                Map<String, Object> programResult = new HashMap<>();
                // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                programResult.put("programPath", program.getDomainFile().getPathname());
                programResult.put("totalFunctions", functions.size());
                programResult.put("functions", functions);
                programResult.put("actions", actions);
                programResults.add(programResult);
                totalFunctions += functions.size();
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            if (programResults.size() == 1) {
                result.putAll(programResults.get(0));
            } else {
                result.put("programs", programResults);
                result.put("totalPrograms", programResults.size());
                result.put("totalFunctions", totalFunctions);
            }
            
            return createJsonResult(result);
        } catch (IllegalArgumentException | ProgramValidationException e) {
            logError("Error handling all functions", e);
            return createErrorResult("Failed to retrieve all functions: " + e.getMessage());
        }
    }
    
    /**
     * Build function info map (similar to handleInfoView but returns Map directly)
     */
    private Map<String, Object> buildFunctionInfo(Program program, Function function, TaskMonitor monitor) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", function.getName());
        info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        info.put("returnType", function.getReturnType().toString());
        // Ghidra API: Function.getSignature() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getSignature()
        info.put("signature", function.getSignature().toString());
        info.put("callingConvention", function.getCallingConventionName());
        info.put("isExternal", function.isExternal());
        info.put("isThunk", function.isThunk());

        var body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            info.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            info.put("sizeInBytes", body.getNumAddresses());
        }

        // Parameters
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Parameter param = function.getParameter(i);
            Map<String, Object> paramInfo = new HashMap<>();
            paramInfo.put("name", param.getName());
            paramInfo.put("dataType", param.getDataType().toString());
            paramInfo.put("ordinal", i);
            parameters.add(paramInfo);
        }
        info.put("parameters", parameters);
        
        // Local variables
        List<Map<String, Object>> locals = new ArrayList<>();
        for (var local : function.getLocalVariables()) {
            Map<String, Object> localInfo = new HashMap<>();
            localInfo.put("name", local.getName());
            localInfo.put("dataType", local.getDataType().toString());
            locals.add(localInfo);
        }
        info.put("localVariables", locals);
        
        // Count callers and callees (with timeout)
        int callerCount = -1;
        int calleeCount = -1;
        if (monitor != null && !monitor.isCancelled()) {
            try {
                Set<Address> callerAddresses = new HashSet<>();
                var refManager = program.getReferenceManager();
                var refsTo = refManager.getReferencesTo(function.getEntryPoint());
                int refCount = 0;
                while (refsTo.hasNext() && !monitor.isCancelled()) {
                    if (++refCount % 1000 == 0 && monitor.isCancelled()) break;
                    var ref = refsTo.next();
                    // Ghidra API: Reference.getReferenceType(), ReferenceType.isCall() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html#getReferenceType()
                    if (ref.getReferenceType().isCall()) {
                        // Ghidra API: Reference.getFromAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html#getFromAddress()
                        Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            callerAddresses.add(caller.getEntryPoint());
                        }
                    }
                }
                callerCount = monitor.isCancelled() ? -1 : callerAddresses.size();

                if (!monitor.isCancelled()) {
                    Set<Address> calleeAddresses = new HashSet<>();
                    for (Instruction instr : program.getListing().getInstructions(body, true)) {
                        if (monitor.isCancelled()) break;
                        // Ghidra API: Instruction.getReferencesFrom() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getReferencesFrom()
                        Reference[] refsFrom = instr.getReferencesFrom();
                        for (Reference ref : refsFrom) {
                            if (ref.getReferenceType().isCall()) {
                                // Ghidra API: Reference.getToAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html#getToAddress()
                                Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                                if (callee == null) {
                                    callee = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
                                }
                                if (callee != null) {
                                    calleeAddresses.add(callee.getEntryPoint());
                                }
                            }
                        }
                    }
                    calleeCount = monitor.isCancelled() ? -1 : calleeAddresses.size();
                }
            } catch (Exception e) {
                // Leave as -1 if counting fails
            }
        }
        info.put("callerCount", callerCount);
        info.put("calleeCount", calleeCount);
        
        return info;
    }
    
    /**
     * Run signature scanning to discover undefined functions
     */
    private Map<String, Object> runSignatureScanning(Program program) {
        Map<String, Object> results = new HashMap<>();
        int functionsCreated = 0;
        List<Map<String, Object>> discoveredFunctions = new ArrayList<>();
        
        try {
            FunctionManager funcManager = program.getFunctionManager();
            Listing listing = program.getListing();
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS);

            Set<Address> calledAddresses = new HashSet<>();
            FunctionIterator funcIter = funcManager.getFunctions(true);

            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                AddressSetView body = func.getBody();
                if (body == null) continue;

                for (Instruction instr : listing.getInstructions(body, true)) {
                    if (monitor.isCancelled()) break;
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            Function targetFunc = funcManager.getFunctionAt(targetAddr);
                            if (targetFunc == null) {
                                CodeUnit cu = listing.getCodeUnitAt(targetAddr);
                                if (cu != null && cu instanceof Instruction) {
                                    calledAddresses.add(targetAddr);
                                }
                            }
                        }
                    }
                }
            }

            // Ghidra API: Program.startTransaction(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#startTransaction(java.lang.String)
            int txId = program.startTransaction("Signature Scanning - Create Functions");
            try {
                for (Address addr : calledAddresses) {
                    if (monitor.isCancelled()) break;
                    if (funcManager.getFunctionAt(addr) == null) {
                        try {
                            // Ghidra API: FunctionManager.createFunction(String, Address, AddressSetView, SourceType) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#createFunction(java.lang.String,ghidra.program.model.address.Address,ghidra.program.model.address.AddressSetView,ghidra.program.model.symbol.SourceType)
                            Function newFunc = funcManager.createFunction(null, addr, null, ghidra.program.model.symbol.SourceType.ANALYSIS);
                            if (newFunc != null) {
                                functionsCreated++;
                                discoveredFunctions.add(Map.of(
                                    "address", AddressUtil.formatAddress(addr),
                                    "name", newFunc.getName()
                                ));
                            }
                        } catch (OverlappingFunctionException | InvalidInputException e) {
                            // Skip if function creation fails
                        }
                    }
                }
                // Ghidra API: Program.endTransaction(int, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#endTransaction(int,boolean)
                program.endTransaction(txId, true);
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
            
            results.put("success", true);
            results.put("functionsCreated", functionsCreated);
            results.put("discoveredFunctions", discoveredFunctions);
        } catch (Exception e) {
            logError("Error running signature scanning", e);
            results.put("success", false);
            results.put("error", e.getMessage());
        }
        
        return results;
    }

    /**
     * Extract JSON data from a CallToolResult, returning the parsed map
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractJsonDataFromResult(McpSchema.CallToolResult result) {
        try {
            String jsonText = extractTextFromContent(result.content().get(0));
            return JSON.readValue(jsonText, Map.class);
        } catch (JsonProcessingException e) {
            // Fallback: return empty map if parsing fails
            logError("Error extracting JSON data from result", e);
            return new HashMap<>();
        }
    }

}
