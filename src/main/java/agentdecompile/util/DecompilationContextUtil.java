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
package agentdecompile.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import agentdecompile.plugin.ConfigManager;

/**
 * Utility class for working with decompilation context and cross references.
 * Provides methods to map addresses to decompilation line numbers and extract
 * code context around specific lines.
 * <p>
 * Ghidra API: {@link ghidra.app.decompiler.DecompInterface}, {@link ghidra.app.decompiler.DecompileResults},
 * {@link ghidra.app.decompiler.component.DecompilerUtils} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html">ghidra.app.decompiler</a>,
 * {@link ghidra.program.model.symbol.Reference} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html">Reference API</a>.
 * </p>
 */
public class DecompilationContextUtil {

    /**
     * Get the decompilation line number for a specific address within a function.
     *
     * @param program The Ghidra program
     * @param function The function containing the address
     * @param address The address to find the line number for
     * @return The line number (1-based) or -1 if not found
     */
    public static int getLineNumberForAddress(Program program, Function function, Address address) {
        if (program == null || function == null || address == null) {
            return -1;
        }

        // Initialize decompiler
        // Ghidra API: DecompInterface.<init>() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
        DecompInterface decompiler = new DecompInterface();
        // Ghidra API: DecompInterface.toggleCCode(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#toggleCCode(boolean)
        decompiler.toggleCCode(true);
        // Ghidra API: DecompInterface.toggleSyntaxTree(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#toggleSyntaxTree(boolean)
        decompiler.toggleSyntaxTree(true);
        // Ghidra API: DecompInterface.setSimplificationStyle(String) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#setSimplificationStyle(java.lang.String)
        decompiler.setSimplificationStyle("decompile");

        // Ghidra API: DecompInterface.openProgram(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#openProgram(ghidra.program.model.listing.Program)
        if (!decompiler.openProgram(program)) {
            return -1;
        }

        try {
            // Decompile the function with timeout
            int timeoutSeconds = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
            // Ghidra API: TimeoutTaskMonitor.timeoutIn(long, TimeUnit) - https://ghidra.re/ghidra_docs/api/ghidra/util/task/TimeoutTaskMonitor.html#timeoutIn(long,java.util.concurrent.TimeUnit)
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
            // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);
            // Ghidra API: TaskMonitor.isCancelled() - https://ghidra.re/ghidra_docs/api/ghidra/util/task/TaskMonitor.html#isCancelled()
            if (timeoutMonitor.isCancelled()) {
                // Ghidra API: Msg.error(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object)
                Msg.error(DecompilationContextUtil.class, "Decompilation timed out for address " + address + " after " + timeoutSeconds + " seconds");
                return -1;
            }
            // Ghidra API: DecompileResults.decompileCompleted() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#decompileCompleted()
            if (!decompileResults.decompileCompleted()) {
                return -1;
            }

            // Get the markup for line mapping
            // Ghidra API: DecompileResults.getCCodeMarkup() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#getCCodeMarkup()
            ClangTokenGroup markup = decompileResults.getCCodeMarkup();
            // Ghidra API: DecompilerUtils.toLines(ClangTokenGroup) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html#toLines(ghidra.app.decompiler.ClangTokenGroup)
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

            // Find the line containing this address
            for (ClangLine clangLine : clangLines) {
                List<ClangToken> tokens = clangLine.getAllTokens();
                for (ClangToken token : tokens) {
                    // Ghidra API: ClangToken.getMinAddress() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangToken.html#getMinAddress()
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null && tokenAddr.equals(address)) {
                        // Ghidra API: ClangLine.getLineNumber() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html#getLineNumber()
                        return clangLine.getLineNumber();
                    }
                }

                // If no exact match, check if address is within the range of this line
                if (!tokens.isEmpty()) {
                    // Ghidra API: DecompilerUtils.getClosestAddress(Program, ClangNode) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html#getClosestAddress(ghidra.program.model.listing.Program,ghidra.app.decompiler.ClangNode)
                    Address closestAddr = DecompilerUtils.getClosestAddress(program, tokens.get(0));
                    if (closestAddr != null && closestAddr.equals(address)) {
                        // Ghidra API: ClangLine.getLineNumber() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html#getLineNumber()
                        return clangLine.getLineNumber();
                    }
                }
            }

            return -1;
        } catch (Exception e) {
            // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(DecompilationContextUtil.class, "Error getting line number for address " + address, e);
            return -1;
        } finally {
            // Ghidra API: DecompInterface.dispose() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#dispose()
            decompiler.dispose();
        }
    }

    /**
     * Get a context snippet around a specific line in a function's decompilation.
     *
     * @param program The Ghidra program
     * @param function The function to decompile
     * @param lineNumber The target line number (1-based)
     * @param contextLines Number of lines to include before and after the target line
     * @return A string containing the context lines separated by newlines, or null if error
     */
    public static String getDecompilationContext(Program program, Function function, int lineNumber, int contextLines) {
        if (program == null || function == null || lineNumber <= 0 || contextLines < 0) {
            return null;
        }

        // Initialize decompiler
        // Ghidra API: DecompInterface.<init>() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
        DecompInterface decompiler = new DecompInterface();
        // Ghidra API: DecompInterface.toggleCCode(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#toggleCCode(boolean)
        decompiler.toggleCCode(true);
        // Ghidra API: DecompInterface.toggleSyntaxTree(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#toggleSyntaxTree(boolean)
        decompiler.toggleSyntaxTree(true);
        // Ghidra API: DecompInterface.setSimplificationStyle(String) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#setSimplificationStyle(java.lang.String)
        decompiler.setSimplificationStyle("decompile");

        // Ghidra API: DecompInterface.openProgram(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#openProgram(ghidra.program.model.listing.Program)
        if (!decompiler.openProgram(program)) {
            return null;
        }

        try {
            // Decompile the function with timeout
            int timeoutSeconds = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
            // Ghidra API: TimeoutTaskMonitor.timeoutIn(long, TimeUnit) - https://ghidra.re/ghidra_docs/api/ghidra/util/task/TimeoutTaskMonitor.html#timeoutIn(long,java.util.concurrent.TimeUnit)
            TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
            // Ghidra API: DecompInterface.decompileFunction(Function, int, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#decompileFunction(ghidra.program.model.listing.Function,int,ghidra.util.task.TaskMonitor)
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, timeoutMonitor);
            // Ghidra API: TaskMonitor.isCancelled() - https://ghidra.re/ghidra_docs/api/ghidra/util/task/TaskMonitor.html#isCancelled()
            if (timeoutMonitor.isCancelled()) {
                // Ghidra API: Msg.error(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object)
                Msg.error(DecompilationContextUtil.class, "Decompilation timed out while getting context after " + timeoutSeconds + " seconds");
                return null;
            }
            // Ghidra API: DecompileResults.decompileCompleted() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#decompileCompleted()
            if (!decompileResults.decompileCompleted()) {
                return null;
            }

            // Get the decompiled code
            // Ghidra API: DecompileResults.getDecompiledFunction() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html#getDecompiledFunction()
            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
            // Ghidra API: DecompiledFunction.getC() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html#getC()
            String decompCode = decompiledFunction.getC();
            String[] lines = decompCode.split("\n");

            // Calculate range
            int startLine = Math.max(0, lineNumber - 1 - contextLines); // Convert to 0-based
            int endLine = Math.min(lines.length - 1, lineNumber - 1 + contextLines);

            // Build context string
            StringBuilder context = new StringBuilder();
            for (int i = startLine; i <= endLine; i++) {
                if (i > startLine) {
                    context.append("\n");
                }
                context.append(lines[i]);
            }

            return context.toString();
        } catch (Exception e) {
            // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(DecompilationContextUtil.class, "Error getting decompilation context", e);
            return null;
        } finally {
            // Ghidra API: DecompInterface.dispose() - https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#dispose()
            decompiler.dispose();
        }
    }

    /**
     * Get enhanced incoming reference information for a function with line numbers and optional context.
     *
     * @param program The Ghidra program
     * @param targetFunction The function to get incoming references for
     * @param includeContext Whether to include code context snippets
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedIncomingReferences(Program program, Function targetFunction, boolean includeContext) {
        // Default to no limit for backwards compatibility
        return getEnhancedIncomingReferences(program, targetFunction, includeContext, -1);
    }

    /**
     * Get enhanced incoming reference information for a function with line numbers and optional context.
     * This overload allows limiting the number of references to prevent performance issues.
     *
     * @param program The Ghidra program
     * @param targetFunction The function to get incoming references for
     * @param includeContext Whether to include code context snippets (expensive - requires decompilation per reference)
     * @param maxRefs Maximum number of references to return (-1 for no limit)
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedIncomingReferences(Program program, Function targetFunction, boolean includeContext, int maxRefs) {
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetFunction == null) {
            return enhancedRefs;
        }

        try {
            // Get references to this function's entry point
            // Ghidra API: Program.getReferenceManager(), ReferenceManager.getReferencesTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager(), Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager()
            ReferenceIterator incomingRefs = program.getReferenceManager().getReferencesTo(targetFunction.getEntryPoint());

            // Count total references first for logging (quick iteration)
            int totalRefs = 0;
            // Ghidra API: Program.getReferenceManager(), ReferenceManager.getReferencesTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager(), Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager()
            var countIterator = program.getReferenceManager().getReferencesTo(targetFunction.getEntryPoint());
            while (countIterator.hasNext()) {
                countIterator.next();
                totalRefs++;
            }

            DebugLogger.debug(DecompilationContextUtil.class,
                String.format("getEnhancedIncomingReferences: Function '%s' has %d total references, processing up to %d with context=%s",
                    targetFunction.getName(), totalRefs, maxRefs > 0 ? maxRefs : totalRefs, includeContext));

            int processed = 0;
            int contextFetched = 0;

            while (incomingRefs.hasNext()) {
                // Stop early if we've reached the limit
                if (maxRefs > 0 && enhancedRefs.size() >= maxRefs) {
                    DebugLogger.debug(DecompilationContextUtil.class,
                        String.format("getEnhancedIncomingReferences: Reached limit of %d references, stopping early", maxRefs));
                    break;
                }

                Reference ref = incomingRefs.next();
                Address fromAddress = ref.getFromAddress();
                // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
                Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddress);
                processed++;

                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddress));
                refInfo.put("referenceType", ref.getReferenceType().toString());

                // Add symbol name if available
                if (fromAddress != null) {
                    // Ghidra API: Program.getSymbolTable(), SymbolTable.getPrimarySymbol(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
                    Symbol fromSymbol = program.getSymbolTable().getPrimarySymbol(fromAddress);
                    if (fromSymbol != null) {
                        refInfo.put("fromSymbol", fromSymbol.getName());
                        refInfo.put("fromSymbolType", fromSymbol.getSymbolType().toString());
                    }
                }

                if (fromFunction != null) {
                    refInfo.put("fromFunction", fromFunction.getName());

                    // Get line number in the source function
                    int lineNumber = getLineNumberForAddress(program, fromFunction, fromAddress);
                    if (lineNumber > 0) {
                        refInfo.put("fromLine", lineNumber);

                        // Add context if requested (this is expensive - requires decompilation)
                        if (includeContext) {
                            contextFetched++;
                            // Log progress every 3 context fetches (each is a decompilation)
                            if (contextFetched % 3 == 0) {
                                DebugLogger.debug(DecompilationContextUtil.class,
                                    String.format("getEnhancedIncomingReferences: Fetched context for %d/%d references (decompiling calling functions)",
                                        contextFetched, maxRefs > 0 ? Math.min(maxRefs, totalRefs) : totalRefs));
                            }

                            String context = getDecompilationContext(program, fromFunction, lineNumber, 1);
                            if (context != null) {
                                refInfo.put("context", context);
                            }
                        }
                    }
                }

                enhancedRefs.add(refInfo);
            }

            DebugLogger.debug(DecompilationContextUtil.class,
                String.format("getEnhancedIncomingReferences: Completed - processed %d references, fetched %d contexts, returning %d results",
                    processed, contextFetched, enhancedRefs.size()));

        } catch (Exception e) {
            // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(DecompilationContextUtil.class, "Error getting enhanced incoming references", e);
        }

        return enhancedRefs;
    }

    /**
     * Get enhanced reference information for any address with line numbers and optional context.
     * This method can be used by cross reference tools to add decompilation context.
     *
     * @param program The Ghidra program
     * @param targetAddress The address to get references to
     * @param includeContext Whether to include code context snippets
     * @return List of enhanced reference maps
     */
    public static List<Map<String, Object>> getEnhancedReferencesTo(Program program, Address targetAddress, boolean includeContext) {
        List<Map<String, Object>> enhancedRefs = new ArrayList<>();

        if (program == null || targetAddress == null) {
            return enhancedRefs;
        }

        try {
            // Get references to this address
            // Ghidra API: Program.getReferenceManager(), ReferenceManager.getReferencesTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getReferenceManager()
            ReferenceIterator refs = program.getReferenceManager().getReferencesTo(targetAddress);

            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddress = ref.getFromAddress();
                // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
                Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddress);

                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddress));
                refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));
                refInfo.put("referenceType", ref.getReferenceType().toString());
                refInfo.put("isPrimary", ref.isPrimary());
                refInfo.put("operandIndex", ref.getOperandIndex());
                refInfo.put("sourceType", ref.getSource().toString());

                if (fromFunction != null) {
                    // Ghidra API: Function.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
                    refInfo.put("fromFunction", fromFunction.getName());

                    // Get line number in the source function
                    int lineNumber = getLineNumberForAddress(program, fromFunction, fromAddress);
                    if (lineNumber > 0) {
                        refInfo.put("fromLine", lineNumber);

                        // Add context if requested
                        if (includeContext) {
                            String context = getDecompilationContext(program, fromFunction, lineNumber, 1);
                            if (context != null) {
                                refInfo.put("context", context);
                            }
                        }
                    }
                }

                enhancedRefs.add(refInfo);
            }
        } catch (Exception e) {
            // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(DecompilationContextUtil.class, "Error getting enhanced references to address", e);
        }

        return enhancedRefs;
    }
}