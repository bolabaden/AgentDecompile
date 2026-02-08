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
package agentdecompile.tools.decompiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Matcher;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.UndefinedFunction;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import agentdecompile.plugin.ConfigManager;
import agentdecompile.tools.AbstractToolProvider;
import agentdecompile.util.AddressUtil;
import agentdecompile.util.DataTypeParserUtil;
import agentdecompile.util.DecompilationContextUtil;
import agentdecompile.util.DecompilationDiffUtil;
import agentdecompile.util.DecompilationReadTracker;
import agentdecompile.util.DebugLogger;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Tool provider for function decompilation operations.
 * <p>
 * Ghidra Decompiler API references:
 * <ul>
 *   <li>{@link ghidra.app.decompiler.DecompInterface} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html">DecompInterface API</a></li>
 *   <li>{@link ghidra.app.decompiler.DecompileResults} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html">DecompileResults API</a></li>
 *   <li>{@link ghidra.program.model.pcode.HighFunctionDBUtil} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunctionDBUtil.html">HighFunctionDBUtil API</a> (persist variable changes)</li>
 *   <li>{@link ghidra.app.decompiler.component.DecompilerUtils} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html">DecompilerUtils API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html">ghidra.app.decompiler package</a>.
 * </p>
 */
public class DecompilerToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public DecompilerToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Clean up read tracking entries when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
        String programPath = program.getDomainFile().getPathname();

        // Remove read tracking entries for the closed program using shared tracker
        int removed = DecompilationReadTracker.clearProgramEntries(programPath);

        if (removed > 0) {
            logInfo("DecompilerToolProvider: Cleared " + removed +
                " read tracking entries for closed program: " + programPath);
        }
    }

    @Override
    public void registerTools() {
    }

    /**
     * Creates a TaskMonitor with timeout configured from settings
     * @return TaskMonitor with timeout from configuration
     */
    private TaskMonitor createTimeoutMonitor() {
        ConfigManager configManager = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager.getDecompilerTimeoutSeconds();
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private boolean isTimedOut(TaskMonitor monitor) {
        return monitor.isCancelled();
    }

    private int getTimeoutSeconds() {
        return AgentDecompileInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
    }

    // ============================================================================
    // Helper Infrastructure for Decompiler Operations
    // ============================================================================

    /** Maximum callers to include in get-decompilation response */
    private static final int MAX_CALLERS_IN_DECOMPILATION = 50;

    /** Maximum callees to include in get-decompilation response */
    private static final int MAX_CALLEES_IN_DECOMPILATION = 50;

    /** Check timeout every N instructions during reference counting */
    private static final int TIMEOUT_CHECK_INSTRUCTION_INTERVAL = 100;

    /** Check timeout every N references during reference counting */
    private static final int TIMEOUT_CHECK_REFERENCE_INTERVAL = 50;

    /** Map of Ghidra comment types to their string names for JSON output */
    private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        CommentType.PRE, "pre",
        CommentType.EOL, "eol",
        CommentType.POST, "post",
        CommentType.PLATE, "plate",
        CommentType.REPEATABLE, "repeatable"
    );

    /**
     * Result of a safe decompilation attempt. Encapsulates either a successful
     * decompilation result or an error message.
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
     * Functional interface for processing high-level symbols during variable iteration.
     */
    @FunctionalInterface
    private interface SymbolProcessor {
        /**
         * Process a single symbol.
         * @param symbol The high-level symbol to process
         * @return true if processing was successful and changed something, false otherwise
         * @throws DuplicateNameException if a name conflict occurs
         * @throws InvalidInputException if the input is invalid
         */
        boolean process(HighSymbol symbol) throws DuplicateNameException, InvalidInputException;
    }

    /**
     * Creates and configures a DecompInterface for standard decompilation operations.
     * The caller is responsible for disposing the decompiler in a finally block.
     *
     * @param program The program to decompile
     * @param toolName The name of the tool (for logging)
     * @return A configured and initialized DecompInterface, or null if initialization failed
     */
    private DecompInterface createConfiguredDecompiler(Program program, String toolName) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        // Ghidra API: DecompInterface.openProgram(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#openProgram(ghidra.program.model.listing.Program)
        if (!decompiler.openProgram(program)) {
            // Ghidra API: Program.getName() (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getName()
            logError(toolName + ": Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    /**
     * Decompiles a function with timeout handling and consistent error reporting.
     *
     * @param decompiler The initialized decompiler to use
     * @param function The function to decompile
     * @param toolName The name of the tool (for logging)
     * @return DecompilationAttempt containing either the results or an error message
     */
    private DecompilationAttempt decompileFunctionSafely(
            DecompInterface decompiler,
            Function function,
            String toolName) {
        TaskMonitor timeoutMonitor = createTimeoutMonitor();
        // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
        DecompileResults results = decompiler.decompileFunction(function, 0, timeoutMonitor);

        if (isTimedOut(timeoutMonitor)) {
            String msg = "Decompilation timed out after " + getTimeoutSeconds() + " seconds";
            // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            // Ghidra API: Function.getName() (Namespace) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html#getName()
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        return DecompilationAttempt.success(results);
    }

    /**
     * Gets updated decompilation after modifications and creates a diff against the original.
     *
     * @param program The program containing the function
     * @param function The function to re-decompile
     * @param beforeDecompilation The original decompilation text to compare against
     * @param toolName The name of the tool (for logging)
     * @return Map containing diff results or error information
     */
    private Map<String, Object> getDecompilationDiff(
            Program program,
            Function function,
            String beforeDecompilation,
            String toolName) {
        Map<String, Object> result = new HashMap<>();

        DecompInterface newDecompiler = createConfiguredDecompiler(program, toolName + "-diff");
        if (newDecompiler == null) {
            result.put("decompilationError", "Failed to initialize decompiler for diff");
            return result;
        }

        try {
            DecompilationAttempt attempt = decompileFunctionSafely(newDecompiler, function, toolName + "-diff");
            if (!attempt.success()) {
                result.put("decompilationError", attempt.errorMessage());
                return result;
            }

            String afterDecompilation = attempt.results().getDecompiledFunction().getC();
            DecompilationDiffUtil.DiffResult diff =
                DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);

            if (diff.hasChanges()) {
                result.put("changes", DecompilationDiffUtil.toMap(diff));
            } else {
                result.put("changes", Map.of(
                    "hasChanges", false,
                    "summary", "No changes detected in decompilation"
                ));
            }
        } catch (Exception e) {
            logError(toolName + "-diff: Error during diff decompilation", e);
            result.put("decompilationError", "Exception during decompilation: " + e.getMessage());
        } finally {
            newDecompiler.dispose();
        }

        return result;
    }

    /**
     * Processes all variables (local and global) in a high function using the provided processor.
     *
     * @param highFunction The high function containing the variables
     * @param processor The processor to apply to each symbol
     * @param toolName The name of the tool (for logging)
     * @return The number of symbols successfully processed
     */
    private int processAllVariables(HighFunction highFunction, SymbolProcessor processor, String toolName) {
        int processedCount = 0;

        // Process local variables
        // Ghidra API: HighFunction.getLocalSymbolMap(), LocalSymbolMap.getSymbols() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html#getLocalSymbolMap(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/LocalSymbolMap.html#getSymbols()
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                // Ghidra API: HighSymbol.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html#getName()
                logError(toolName + ": Failed to process local variable " + symbol.getName(), e);
            }
        }

        // Process global variables
        // Ghidra API: HighFunction.getGlobalSymbolMap(), GlobalSymbolMap.getSymbols() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html#getGlobalSymbolMap(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/GlobalSymbolMap.html#getSymbols()
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                // Ghidra API: HighSymbol.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html#getName()
                logError(toolName + ": Failed to process global variable " + symbol.getName(), e);
            }
        }

        return processedCount;
    }

    /**
     * Finds the address corresponding to a line number in decompiled code.
     *
     * @param program The program
     * @param clangLines The decompiled code lines
     * @param lineNumber The line number to find (1-based)
     * @return The address for the line, or null if not found
     */
    private Address findAddressForLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        for (ClangLine clangLine : clangLines) {
            // Ghidra API: ClangLine.getLineNumber() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html#getLineNumber()
            if (clangLine.getLineNumber() == lineNumber) {
                // Ghidra API: ClangLine.getAllTokens() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html#getAllTokens()
                List<ClangToken> tokens = clangLine.getAllTokens();

                // Find the first address on this line
                for (ClangToken token : tokens) {
                    // Ghidra API: ClangToken.getMinAddress() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangToken.html#getMinAddress()
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        return tokenAddr;
                    }
                }

                // If no direct address, find closest
                if (!tokens.isEmpty()) {
                    // Ghidra API: DecompilerUtils.getClosestAddress(Program, ClangNode) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html#getClosestAddress(ghidra.program.model.listing.Program,ghidra.app.decompiler.ClangNode)
                    return DecompilerUtils.getClosestAddress(program, tokens.get(0));
                }
                break;
            }
        }
        return null;
    }

    /**
     * Processes variable data type changes for all variables in a high function.
     * This method handles the specific logic for data type changes including error collection.
     *
     * @param highFunction The high function containing the variables
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return The number of variables successfully changed
     */
    private int processVariableDataTypeChanges(
            HighFunction highFunction,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        int changedCount = 0;

        // Process local variables
        // Ghidra API: HighFunction.getLocalSymbolMap(), LocalSymbolMap.getSymbols() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html#getLocalSymbolMap(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/LocalSymbolMap.html#getSymbols()
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        // Process global variables
        // Ghidra API: HighFunction.getGlobalSymbolMap(), GlobalSymbolMap.getSymbols() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html#getGlobalSymbolMap(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/GlobalSymbolMap.html#getSymbols()
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        return changedCount;
    }

    /**
     * Processes a single data type change for a symbol.
     *
     * @param symbol The symbol to process
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return true if the data type was changed, false otherwise
     */
    private boolean processDataTypeChange(
            HighSymbol symbol,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        String varName = symbol.getName();
        String newDataTypeString = mappings.get(varName);

        if (newDataTypeString == null) {
            return false;
        }

        try {
            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                newDataTypeString, archiveName);

            if (newDataType == null) {
                errors.add("Could not find data type: " + newDataTypeString + " for variable " + varName);
                return false;
            }

            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
            logInfo(toolName + ": Changed data type of variable " + varName + " to " + newDataTypeString);
            return true;
        } catch (DuplicateNameException | InvalidInputException e) {
            errors.add("Failed to change data type of variable " + varName + " to " + newDataTypeString + ": " + e.getMessage());
        } catch (Exception e) {
            errors.add("Error parsing data type " + newDataTypeString + " for variable " + varName + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Result of counting call references with timeout handling.
     */
    private record CallCountResult(
        Map<Address, Integer> callCounts,
        boolean timedOut
    ) {}

    /**
     * Count call references for a function (either callers or callees) with timeout handling.
     * This method handles the iteration over instructions and references consistently.
     *
     * @param program The program
     * @param function The function to count calls for
     * @param countCallers true to count callers (references TO this function),
     *                     false to count callees (references FROM this function)
     * @return CallCountResult containing the counts and timeout status
     */
    private CallCountResult countCallsWithTimeout(Program program, Function function, boolean countCallers) {
        TaskMonitor monitor = createTimeoutMonitor();
        Map<Address, Integer> callCounts = new HashMap<>();
        boolean timedOut = false;

        // Ghidra API: Program.getReferenceManager(), getFunctionManager(), getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        Listing listing = program.getListing();
        // Ghidra API: Function.getBody() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
        AddressSetView functionBody = function.getBody();

        int instrCount = 0;
        int refCount = 0;

        // Ghidra API: Listing.getInstructions(AddressSetView, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getInstructions(ghidra.program.model.address.AddressSetView,boolean)
        for (Instruction instr : listing.getInstructions(functionBody, true)) {
            // Check timeout periodically on instruction boundary
            if (++instrCount % TIMEOUT_CHECK_INSTRUCTION_INTERVAL == 0 && monitor.isCancelled()) {
                timedOut = true;
                break;
            }

            if (countCallers) {
                // For callers: get references TO each instruction in this function
                // Ghidra API: ReferenceManager.getReferencesTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html#getReferencesTo(ghidra.program.model.address.Address)
                ReferenceIterator refsTo = refManager.getReferencesTo(instr.getAddress());
                while (refsTo.hasNext()) {
                    // Check timeout in inner loop for addresses with many references
                    if (++refCount % TIMEOUT_CHECK_REFERENCE_INTERVAL == 0 && monitor.isCancelled()) {
                        timedOut = true;
                        break;
                    }
                    Reference ref = refsTo.next();
                    if (ref.getReferenceType().isCall()) {
                        // Ghidra API: FunctionManager.getFunctionContaining(Address), Reference.getFromAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctionContaining(ghidra.program.model.address.Address), https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html#getFromAddress()
                        Function caller = funcManager.getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            // Ghidra API: Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getEntryPoint()
                            callCounts.merge(caller.getEntryPoint(), 1, Integer::sum);
                        }
                    }
                }
                if (timedOut) break;
            } else {
                // For callees: get references FROM each instruction in this function
                // No inner-loop timeout check needed here because getReferencesFrom() typically
                // returns very few references per instruction (usually 0-1 call targets),
                // unlike getReferencesTo() which can return thousands for popular functions
                // Ghidra API: Instruction.getReferencesFrom() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getReferencesFrom()
                Reference[] refsFrom = instr.getReferencesFrom();
                for (Reference ref : refsFrom) {
                    if (ref.getReferenceType().isCall()) {
                        // Resolve to function entry point (ref.getToAddress() may be inside function)
                        // Ghidra API: FunctionManager.getFunctionAt(Address), Reference.getToAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctionAt(ghidra.program.model.address.Address), https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html#getToAddress()
                        Function callee = funcManager.getFunctionAt(ref.getToAddress());
                        if (callee == null) {
                            // Try to find containing function if not at entry point
                            callee = funcManager.getFunctionContaining(ref.getToAddress());
                        }
                        if (callee != null) {
                            callCounts.merge(callee.getEntryPoint(), 1, Integer::sum);
                        }
                    }
                }
            }
        }

        return new CallCountResult(callCounts, timedOut);
    }

    // ============================================================================
    // Helper Infrastructure (kept for potential future use)
    // ============================================================================
}
