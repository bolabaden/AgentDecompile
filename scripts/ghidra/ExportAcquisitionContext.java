// Export advisory Ghidra facts for AgentDecompile acquisition bundles.
// This script is intentionally read-only: it exports current Program evidence
// and never mutates analysis or project databases.

import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportAcquisitionContext extends GhidraScript {
    private final Gson gson = new Gson();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: ExportAcquisitionContext.java <facts.jsonl> <metadata.json>");
            return;
        }
        File facts = new File(args[0]);
        File metadata = new File(args[1]);
        if (facts.getParentFile() != null) facts.getParentFile().mkdirs();
        if (metadata.getParentFile() != null) metadata.getParentFile().mkdirs();

        Program program = currentProgram;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        int count = 0;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(facts))) {
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                writer.write(gson.toJson(functionRow(program, function, decompiler)));
                writer.newLine();
                count++;
            }
            SymbolIterator symbols = program.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION) continue;
                writer.write(gson.toJson(symbolRow(symbol)));
                writer.newLine();
            }
        } finally {
            decompiler.dispose();
        }
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema", "agentdecompile.ghidra-acquisition-metadata.v1");
        meta.put("programName", program.getName());
        meta.put("language", program.getLanguageID().getIdAsString());
        meta.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        meta.put("imageBase", program.getImageBase().toString());
        meta.put("functionCount", count);
        meta.put("claimBoundary", "Ghidra evidence is advisory acquisition context only; compiler and objdiff verification remain required.");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(metadata))) {
            writer.write(gson.toJson(meta));
            writer.newLine();
        }
    }

    private Map<String, Object> functionRow(Program program, Function function, DecompInterface decompiler) {
        Map<String, Object> row = base("function", function.getName(), function.getEntryPoint());
        row.put("bodyBytes", function.getBody().getNumAddresses());
        row.put("prototype", function.getPrototypeString(true, true));
        row.put("callingConvention", function.getCallingConventionName());
        row.put("sourceNativeId", function.getID());
        List<String> xrefs = new ArrayList<>();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refs.hasNext()) xrefs.add(refs.next().getFromAddress().toString());
        row.put("incomingXrefs", xrefs);
        try {
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                row.put("decompiled", result.getDecompiledFunction().getC());
                row.put("decompilationStatus", "complete");
            } else {
                row.put("decompilationStatus", "failed");
                row.put("decompilationError", result.getErrorMessage());
            }
        } catch (Exception ex) {
            row.put("decompilationStatus", "failed");
            row.put("decompilationError", ex.toString());
        }
        return row;
    }

    private Map<String, Object> symbolRow(Symbol symbol) {
        Map<String, Object> row = base("label", symbol.getName(), symbol.getAddress());
        row.put("sourceNativeId", symbol.getID());
        row.put("symbolType", symbol.getSymbolType().toString());
        return row;
    }

    private Map<String, Object> base(String kind, String name, Address address) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("schema", "agentdecompile.ghidra-acquisition-fact.v1");
        row.put("entityKind", kind);
        row.put("name", name);
        row.put("addressSpace", address.getAddressSpace().getName());
        row.put("address", address.getOffset());
        row.put("entryOffset", address.getOffset());
        row.put("provider", "ghidra");
        row.put("tool", "ExportAcquisitionContext");
        row.put("claimBoundary", "Ghidra evidence is advisory acquisition context only; compiler and objdiff verification remain required.");
        return row;
    }
}
