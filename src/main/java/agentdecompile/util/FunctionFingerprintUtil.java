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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Computes and indexes function fingerprints for cross-program matching.
 * <p>
 * Goal: match "the same" function across multiple executables where addresses differ,
 * but code is identical or near-identical. The fingerprint is intentionally independent
 * of address and symbol names. Uses a normalized signature of the first N instructions
 * (mnemonics + operand-type categories), size metadata, and SHA-256.
 * </p>
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Function}, {@link ghidra.program.model.listing.Instruction},
 * {@link ghidra.program.model.listing.Listing}, {@link ghidra.program.model.lang.OperandType} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html">Function API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html">Instruction API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public final class FunctionFingerprintUtil {
    /** Default number of instructions to sample from each function for fingerprinting. */
    public static final int DEFAULT_MAX_INSTRUCTIONS = 64;

    /**
     * Minimum instruction count for a function to be considered "meaningful" for matching.
     * Functions below this threshold (thunks, import stubs, tiny wrappers) produce
     * non-discriminative signatures that cause massive ambiguity.
     */
    public static final int MIN_MEANINGFUL_INSTRUCTIONS = 4;

    /**
     * Maximum number of candidates allowed per fingerprint bucket before it's
     * considered "degenerate" (non-unique). Degenerate buckets are excluded from
     * exact matching because they will always produce ambiguous results.
     */
    private static final int MAX_DEGENERATE_BUCKET_SIZE = 8;

    private static final int MAX_CANDIDATES_RETURNED = 25;
    private static final int FUZZY_SHORTLIST_FACTOR = 24;
    private static final int FUZZY_SHORTLIST_MIN = 64;
    private static final int FUZZY_SHORTLIST_MAX = 384;

    private static final Map<String, CachedProgramIndex> INDEX_CACHE = new ConcurrentHashMap<>();

    private FunctionFingerprintUtil() {
        // utility
    }

    /**
     * Returns {@code true} if a function is "degenerate" for matching purposes.
     * Degenerate functions (thunks, tiny stubs, import trampolines) produce
     * non-discriminative signatures that cause massive ambiguity in both
     * exact and fuzzy matching.
     *
     * @param function the function to test (may be null)
     * @return true if the function should be excluded from matching
     */
    public static boolean isDegenerateFunction(Function function) {
        if (function == null || function.isExternal()) {
            return true;
        }
        return function.isThunk();
    }

    /**
     * A minimal descriptor for a function match candidate.
     *
     * @param programPath Ghidra project pathname (e.g., "/swkotor.exe")
     * @param functionName Function name in that program
     * @param entryPoint Function entry point
     */
    /**
     * A function match candidate with similarity score.
     */
    public record Candidate(String programPath, String functionName, Address entryPoint) {
        /**
         * Create a candidate with similarity score.
         */
        public record Scored(Candidate candidate, double similarityScore) {}
    }

    /**
     * An immutable snapshot index for a specific program and {@code maxInstructions}.
     * <p>
     * This is intentionally NOT tied to {@link Program#getModificationNumber()} because
     * many matching workflows (e.g. propagating names/tags/comments) modify program metadata
     * without changing the underlying instructions. Using a snapshot avoids repeated
     * full-program re-indexing inside a single match/propagation run.
     * </p>
     *
     * @param programPath Program pathname used for candidates
     * @param maxInstructions Instruction sampling size
     * @param byFingerprint Exact-match index (fingerprint -> candidates)
     * @param signatures Precomputed canonical signatures for fuzzy matching
     * @param tokenToSignatureIndexes Inverted index for token-to-candidate lookup
     */
    public record ProgramIndex(
            String programPath,
            int maxInstructions,
            Map<String, List<Candidate>> byFingerprint,
            List<SignatureEntry> signatures,
            Map<Integer, List<Integer>> tokenToSignatureIndexes
    ) {}

    /**
     * Signature entry used for fuzzy matching.
     *
     * @param candidate function descriptor
     * @param signature canonical signature string
     * @param bodySize function body size (addresses)
     * @param instructionCount number of instructions included in the signature
     * @param uniqueTokenCount number of unique hashed instruction tokens/shingles
     */
    public record SignatureEntry(Candidate candidate, String signature, long bodySize, int instructionCount,
            int uniqueTokenCount) {}

    private record CachedProgramIndex(long programModificationNumber, int maxInstructions,
                                      Map<String, List<Candidate>> byFingerprint) {}

    /**
     * Cached signature index for fast fuzzy matching.
     * Stores canonical signatures and function metadata for efficient similarity search.
     */
    private record CachedSignatureIndex(long programModificationNumber, int maxInstructions,
                                        List<IndexedFunction> functions) {
        record IndexedFunction(Candidate candidate, String signature, long bodySize, int instructionCount) {}
    }

    private static final Map<String, CachedSignatureIndex> SIGNATURE_INDEX_CACHE = new ConcurrentHashMap<>();

    // ========================== Enhanced multi-feature matching ==========================

    /** Number of instruction-category histogram buckets. */
    public static final int HIST_SIZE = 8;
    private static final int HIST_DATA_MOVE = 0;
    private static final int HIST_ARITHMETIC = 1;
    private static final int HIST_LOGIC = 2;
    private static final int HIST_COMPARE = 3;
    private static final int HIST_BRANCH = 4;
    private static final int HIST_CALL = 5;
    private static final int HIST_FLOAT = 6;
    private static final int HIST_OTHER = 7;

    /**
     * Rich multi-dimensional feature vector for a single function.
     * Captures structural, call-graph, data-reference, and instruction-distribution
     * features to enable robust cross-binary matching even across different compiler settings.
     *
     * @param edgeCount Approximate CFG edge count (conditional branches * 2 + unconditional jumps + fallthroughs)
     * @param cyclomaticComplexity Cyclomatic complexity approximation: edges - nodes + 2
     * @param instrHistogram Instruction-category distribution over {@link #HIST_SIZE} buckets
     */
    public record FunctionProfile(
            Candidate candidate,
            String fingerprint,
            String canonicalSignature,
            int instructionCount,
            long bodySize,
            int parameterCount,
            int branchCount,
            int edgeCount,
            int cyclomaticComplexity,
            List<String> calleeNames,
            String calleeSetHash,
            List<String> stringRefs,
            String stringRefsHash,
            long[] notableConstants,
            int[] instrHistogram
    ) {}

    /**
     * Multi-strategy index for a program. Enables O(1) lookups by instruction fingerprint,
     * callee-set hash, string-reference hash, and notable-constant hash, plus inverted
     * callee-name and per-string indexes for fast shortlisting during fuzzy matching.
     */
    public record EnhancedProgramIndex(
            String programPath,
            int maxInstructions,
            Map<String, List<FunctionProfile>> byFingerprint,
            Map<String, List<FunctionProfile>> byCalleeSetHash,
            Map<String, List<FunctionProfile>> byStringRefsHash,
            Map<String, List<FunctionProfile>> byConstantSetHash,
            List<FunctionProfile> allProfiles,
            Map<Address, FunctionProfile> byEntryPoint,
            Map<String, List<Integer>> calleeNameIndex,
            Map<String, List<Integer>> stringIndex
    ) {}

    /**
     * A match result with confidence score and the strategy that produced it.
     */
    public record ScoredMatch(Candidate candidate, double score, String strategy)
            implements Comparable<ScoredMatch> {
        @Override
        public int compareTo(ScoredMatch other) {
            int cmp = Double.compare(other.score, this.score);
            if (cmp != 0) {
                return cmp;
            }
            return this.candidate.entryPoint().compareTo(other.candidate.entryPoint());
        }
    }

    private static final int MAX_FEATURE_INSTRUCTIONS = 256;

    /**
     * Build an enhanced multi-strategy index for a program in a single pass.
     * Extracts structural, call-graph, and data-reference features for every non-thunk function.
     */
    public static EnhancedProgramIndex buildEnhancedIndex(Program program, int maxInstructions) {
        if (program == null) {
            return new EnhancedProgramIndex("", maxInstructions,
                    Map.of(), Map.of(), Map.of(), Map.of(), List.of(), Map.of(), Map.of(), Map.of());
        }

        String programPath = program.getDomainFile().getPathname();
        Map<String, List<FunctionProfile>> byFingerprint = new HashMap<>();
        Map<String, List<FunctionProfile>> byCalleeSetHash = new HashMap<>();
        Map<String, List<FunctionProfile>> byStringRefsHash = new HashMap<>();
        Map<String, List<FunctionProfile>> byConstantSetHash = new HashMap<>();
        List<FunctionProfile> allProfiles = new ArrayList<>();
        Map<Address, FunctionProfile> byEntryPoint = new HashMap<>();
        Map<String, List<Integer>> calleeNameIndex = new HashMap<>();
        Map<String, List<Integer>> stringIndex = new HashMap<>();

        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal() || f.isThunk()) {
                continue;
            }

            FunctionProfile profile = buildFunctionProfile(program, f, maxInstructions);
            if (profile == null) {
                continue;
            }

            int profileIndex = allProfiles.size();
            allProfiles.add(profile);
            byEntryPoint.put(f.getEntryPoint(), profile);

            if (profile.fingerprint() != null) {
                byFingerprint.computeIfAbsent(profile.fingerprint(), k -> new ArrayList<>()).add(profile);
            }
            if (profile.calleeSetHash() != null) {
                byCalleeSetHash.computeIfAbsent(profile.calleeSetHash(), k -> new ArrayList<>()).add(profile);
            }
            if (profile.stringRefsHash() != null) {
                byStringRefsHash.computeIfAbsent(profile.stringRefsHash(), k -> new ArrayList<>()).add(profile);
            }
            if (profile.notableConstants().length > 0) {
                String constHash = hashLongArray(profile.notableConstants());
                if (constHash != null) {
                    byConstantSetHash.computeIfAbsent(constHash, k -> new ArrayList<>()).add(profile);
                }
            }
            for (String calleeName : profile.calleeNames()) {
                calleeNameIndex.computeIfAbsent(calleeName, k -> new ArrayList<>()).add(profileIndex);
            }
            for (String str : profile.stringRefs()) {
                stringIndex.computeIfAbsent(str, k -> new ArrayList<>()).add(profileIndex);
            }
        }

        byFingerprint.entrySet().removeIf(e -> e.getValue().size() > MAX_DEGENERATE_BUCKET_SIZE);

        return new EnhancedProgramIndex(
                programPath, maxInstructions,
                Collections.unmodifiableMap(byFingerprint),
                Collections.unmodifiableMap(byCalleeSetHash),
                Collections.unmodifiableMap(byStringRefsHash),
                Collections.unmodifiableMap(byConstantSetHash),
                Collections.unmodifiableList(allProfiles),
                Collections.unmodifiableMap(byEntryPoint),
                Collections.unmodifiableMap(calleeNameIndex),
                Collections.unmodifiableMap(stringIndex)
        );
    }

    /**
     * Build a {@link FunctionProfile} extracting all features in a combined pass.
     * Public so tool providers can build profiles for source functions.
     *
     * Computes in a single instruction iteration:
     * <ul>
     *   <li>Canonical signature + SHA-256 fingerprint</li>
     *   <li>Instruction-category histogram ({@link #HIST_SIZE} buckets)</li>
     *   <li>Branch count, edge count, cyclomatic complexity</li>
     *   <li>Notable constants, string references</li>
     * </ul>
     */
    public static FunctionProfile buildFunctionProfile(Program program, Function function, int maxInstructions) {
        if (program == null || function == null) {
            return null;
        }
        String canonicalSig;
        try {
            canonicalSig = buildCanonicalSignature(program, function, maxInstructions);
        } catch (Exception e) {
            return null;
        }
        if (canonicalSig == null || canonicalSig.isEmpty()) {
            return null;
        }

        String fingerprint = computeFingerprintFromCanonicalSignature(canonicalSig);
        int instructionCount = extractIntField(canonicalSig, "C=");
        long bodySize = extractLongField(canonicalSig, "B=");

        String programPath = program.getDomainFile().getPathname();
        Candidate candidate = new Candidate(programPath, function.getName(), function.getEntryPoint());

        int parameterCount = 0;
        try {
            parameterCount = function.getParameterCount();
        } catch (Exception e) {
            // ignore
        }

        List<String> calleeNames = extractMeaningfulCalleeNames(function);
        String calleeSetHash = calleeNames.isEmpty() ? null : hashStringList(calleeNames);

        int branchCount = 0;
        int unconditionalJumps = 0;
        int totalNodes = 1; // entry node
        int[] histogram = new int[HIST_SIZE];
        Set<String> stringSet = new java.util.TreeSet<>();
        Set<Long> constantSet = new java.util.TreeSet<>();

        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(function.getBody(), true);
        int processed = 0;
        boolean prevWasTerminator = false;

        while (instrIter.hasNext() && processed < MAX_FEATURE_INSTRUCTIONS) {
            Instruction instr = instrIter.next();
            if (instr == null) {
                continue;
            }
            processed++;

            if (prevWasTerminator) {
                totalNodes++;
                prevWasTerminator = false;
            }

            ghidra.program.model.symbol.FlowType flow = instr.getFlowType();
            if (flow.isConditional()) {
                branchCount++;
                totalNodes++;
                prevWasTerminator = false;
            } else if (flow.isJump() || flow.isTerminal()) {
                if (flow.isJump() && !flow.isConditional()) {
                    unconditionalJumps++;
                }
                prevWasTerminator = true;
            }

            histogram[classifyInstruction(instr)]++;

            for (int i = 0; i < instr.getNumOperands(); i++) {
                Scalar scalar = instr.getScalar(i);
                if (scalar != null && isNotableConstant(scalar.getSignedValue())) {
                    constantSet.add(scalar.getSignedValue());
                }
            }

            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                if (!ref.getReferenceType().isCall()) {
                    try {
                        Data data = listing.getDataAt(ref.getToAddress());
                        if (data != null && data.getValue() instanceof String strValue
                                && strValue.length() >= 4) {
                            stringSet.add(strValue);
                        }
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
        }

        // E = conditional*2 + unconditional + fallthroughs; approximated from instruction flow
        int edgeCount = branchCount * 2 + unconditionalJumps + Math.max(0, totalNodes - 1);
        int cyclomaticComplexity = Math.max(1, edgeCount - totalNodes + 2);

        List<String> sortedStrings = new ArrayList<>(stringSet);
        String stringRefsHash = sortedStrings.isEmpty() ? null : hashStringList(sortedStrings);
        long[] constants = constantSet.stream().mapToLong(Long::longValue).toArray();

        return new FunctionProfile(
                candidate, fingerprint, canonicalSig, instructionCount, bodySize,
                parameterCount, branchCount, edgeCount, cyclomaticComplexity,
                calleeNames, calleeSetHash,
                sortedStrings, stringRefsHash, constants, histogram
        );
    }

    /**
     * Classify an instruction into one of {@link #HIST_SIZE} semantic categories.
     * Uses both mnemonic patterns and Ghidra's FlowType for accurate classification.
     */
    private static int classifyInstruction(Instruction instr) {
        ghidra.program.model.symbol.FlowType flow = instr.getFlowType();
        if (flow.isCall()) {
            return HIST_CALL;
        }
        if (flow.isJump() || flow.isConditional() || flow.isTerminal()) {
            return HIST_BRANCH;
        }

        String mnem = instr.getMnemonicString().toUpperCase();
        return switch (mnem.length() > 0 ? mnem.charAt(0) : ' ') {
            case 'M', 'L', 'S', 'P' -> {
                if (mnem.startsWith("MOV") || mnem.startsWith("LEA")
                        || mnem.startsWith("PUSH") || mnem.startsWith("POP")
                        || mnem.startsWith("LD") || mnem.startsWith("ST")
                        || mnem.startsWith("LDR") || mnem.startsWith("STR")
                        || mnem.startsWith("LOAD") || mnem.startsWith("STORE")) {
                    yield HIST_DATA_MOVE;
                }
                if (mnem.startsWith("MUL") || mnem.startsWith("SUB")) {
                    yield HIST_ARITHMETIC;
                }
                if (mnem.startsWith("MOVS") || mnem.startsWith("STOS")
                        || mnem.startsWith("LODS") || mnem.startsWith("SCAS")) {
                    yield HIST_DATA_MOVE;
                }
                yield HIST_OTHER;
            }
            case 'A', 'I', 'D', 'N' -> {
                if (mnem.startsWith("ADD") || mnem.startsWith("ADC")
                        || mnem.startsWith("SUB") || mnem.startsWith("SBB")
                        || mnem.startsWith("INC") || mnem.startsWith("DEC")
                        || mnem.startsWith("MUL") || mnem.startsWith("IMUL")
                        || mnem.startsWith("DIV") || mnem.startsWith("IDIV")
                        || mnem.startsWith("NEG")) {
                    yield HIST_ARITHMETIC;
                }
                if (mnem.startsWith("AND") || mnem.startsWith("NOT")) {
                    yield HIST_LOGIC;
                }
                yield HIST_OTHER;
            }
            case 'O', 'X', 'R' -> {
                if (mnem.startsWith("OR") || mnem.startsWith("XOR")
                        || mnem.startsWith("ROL") || mnem.startsWith("ROR")
                        || mnem.startsWith("RCL") || mnem.startsWith("RCR")) {
                    yield HIST_LOGIC;
                }
                if (mnem.startsWith("RET")) {
                    yield HIST_BRANCH;
                }
                yield HIST_OTHER;
            }
            case 'C', 'T' -> {
                if (mnem.startsWith("CMP") || mnem.startsWith("TEST")) {
                    yield HIST_COMPARE;
                }
                yield HIST_OTHER;
            }
            case 'F', 'V' -> {
                if (mnem.startsWith("F") || mnem.startsWith("VMOV")
                        || mnem.startsWith("VADD") || mnem.startsWith("VMUL")
                        || mnem.startsWith("VDIV") || mnem.startsWith("VSUB")
                        || mnem.startsWith("VCMP")) {
                    yield HIST_FLOAT;
                }
                yield HIST_OTHER;
            }
            case 'J' -> HIST_BRANCH;
            case 'B' -> {
                if (mnem.startsWith("BT") || mnem.startsWith("BSF") || mnem.startsWith("BSR")) {
                    yield HIST_LOGIC;
                }
                if (mnem.equals("B") || mnem.startsWith("BL") || mnem.startsWith("BX")
                        || mnem.startsWith("BEQ") || mnem.startsWith("BNE")
                        || mnem.startsWith("BGT") || mnem.startsWith("BLT")
                        || mnem.startsWith("BGE") || mnem.startsWith("BLE")
                        || mnem.startsWith("BCC") || mnem.startsWith("BCS")) {
                    yield HIST_BRANCH;
                }
                yield HIST_OTHER;
            }
            default -> HIST_OTHER;
        };
    }

    /**
     * Multi-strategy matching pipeline inspired by BinDiff / Diaphora / BSim.
     *
     * <ol>
     *   <li>Exact instruction fingerprint</li>
     *   <li>Identical callee-set hash</li>
     *   <li>Identical string-reference set hash</li>
     *   <li>Identical notable-constant set hash</li>
     *   <li>Multi-feature fuzzy matching with callee+string shortlisting</li>
     *   <li>Broad structural scan fallback</li>
     * </ol>
     *
     * Each exact-hash strategy attempts disambiguation via the full multi-feature
     * similarity when multiple candidates share the same hash.
     */
    public static List<ScoredMatch> findBestMatches(
            FunctionProfile source, EnhancedProgramIndex targetIndex,
            double minConfidence, int maxResults) {

        if (source == null || targetIndex == null) {
            return List.of();
        }

        // ---- Strategy 1: Exact instruction fingerprint ----
        if (source.fingerprint() != null) {
            List<FunctionProfile> exact = targetIndex.byFingerprint().get(source.fingerprint());
            if (exact != null && !exact.isEmpty()) {
                if (exact.size() == 1) {
                    return List.of(new ScoredMatch(exact.get(0).candidate(), 1.0, "exact-fingerprint"));
                }
                List<ScoredMatch> disambiguated = disambiguateByFeatures(source, exact, "exact-fingerprint");
                if (!disambiguated.isEmpty()) {
                    return cap(disambiguated, maxResults);
                }
            }
        }

        // ---- Strategy 2: Identical callee-set ----
        if (source.calleeSetHash() != null) {
            List<FunctionProfile> calleeMatches = targetIndex.byCalleeSetHash().get(source.calleeSetHash());
            if (calleeMatches != null && !calleeMatches.isEmpty()) {
                if (calleeMatches.size() == 1) {
                    double conf = Math.max(computeMultiFeatureSimilarity(source, calleeMatches.get(0)), 0.90);
                    return List.of(new ScoredMatch(calleeMatches.get(0).candidate(), conf, "callee-set"));
                }
                List<ScoredMatch> disambiguated = disambiguateByFeatures(source, calleeMatches, "callee-set");
                if (!disambiguated.isEmpty() && disambiguated.get(0).score() >= minConfidence) {
                    return cap(disambiguated, maxResults);
                }
            }
        }

        // ---- Strategy 3: Identical string-reference set ----
        if (source.stringRefsHash() != null) {
            List<FunctionProfile> stringMatches = targetIndex.byStringRefsHash().get(source.stringRefsHash());
            if (stringMatches != null && !stringMatches.isEmpty()) {
                if (stringMatches.size() == 1) {
                    double conf = Math.max(computeMultiFeatureSimilarity(source, stringMatches.get(0)), 0.85);
                    return List.of(new ScoredMatch(stringMatches.get(0).candidate(), conf, "string-refs"));
                }
                List<ScoredMatch> disambiguated = disambiguateByFeatures(source, stringMatches, "string-refs");
                if (!disambiguated.isEmpty() && disambiguated.get(0).score() >= minConfidence) {
                    return cap(disambiguated, maxResults);
                }
            }
        }

        // ---- Strategy 4: Identical notable-constant set ----
        if (source.notableConstants().length > 0) {
            String constHash = hashLongArray(source.notableConstants());
            if (constHash != null) {
                List<FunctionProfile> constMatches = targetIndex.byConstantSetHash().get(constHash);
                if (constMatches != null && !constMatches.isEmpty()) {
                    if (constMatches.size() == 1) {
                        double conf = Math.max(computeMultiFeatureSimilarity(source, constMatches.get(0)), 0.80);
                        return List.of(new ScoredMatch(constMatches.get(0).candidate(), conf, "constant-set"));
                    }
                    List<ScoredMatch> disambiguated = disambiguateByFeatures(source, constMatches, "constant-set");
                    if (!disambiguated.isEmpty() && disambiguated.get(0).score() >= minConfidence) {
                        return cap(disambiguated, maxResults);
                    }
                }
            }
        }

        // ---- Strategy 5: Multi-feature fuzzy matching with combined shortlisting ----
        Set<Integer> shortlist = buildCombinedShortlist(source, targetIndex);

        List<ScoredMatch> results = new ArrayList<>();
        if (!shortlist.isEmpty()) {
            for (int idx : shortlist) {
                FunctionProfile target = targetIndex.allProfiles().get(idx);
                if (!structurallyCompatible(source, target)) {
                    continue;
                }
                double sim = computeMultiFeatureSimilarity(source, target);
                if (sim >= minConfidence) {
                    results.add(new ScoredMatch(target.candidate(), sim, "multi-feature"));
                }
            }
        }

        // ---- Strategy 6: Broad structural scan fallback ----
        if (results.isEmpty() && source.instructionCount() >= MIN_MEANINGFUL_INSTRUCTIONS) {
            for (FunctionProfile target : targetIndex.allProfiles()) {
                if (!structurallyCompatible(source, target)) {
                    continue;
                }
                double sim = computeMultiFeatureSimilarity(source, target);
                if (sim >= minConfidence) {
                    results.add(new ScoredMatch(target.candidate(), sim, "structural-scan"));
                }
            }
        }

        Collections.sort(results);
        return cap(results, maxResults);
    }

    /**
     * BinDiff-style call graph propagation.
     * Given a set of already-confirmed matches (source entry -> target entry), look at
     * each matched pair's callees/callers and try to match currently-unmatched neighbors.
     *
     * @param confirmedMatches source entry-point -> target {@link FunctionProfile}
     * @param sourceProgram the source program
     * @param targetIndex index for the target program
     * @param minConfidence minimum score threshold
     * @return additional matches discovered through propagation
     */
    public static Map<Address, ScoredMatch> propagateCallGraph(
            Map<Address, FunctionProfile> confirmedMatches,
            Program sourceProgram,
            EnhancedProgramIndex targetIndex,
            double minConfidence) {

        if (confirmedMatches == null || confirmedMatches.isEmpty()
                || sourceProgram == null || targetIndex == null) {
            return Map.of();
        }

        Map<Address, ScoredMatch> newMatches = new HashMap<>();
        Set<Address> processedSource = new HashSet<>(confirmedMatches.keySet());

        java.util.Deque<Map.Entry<Address, FunctionProfile>> worklist = new java.util.ArrayDeque<>(
                confirmedMatches.entrySet());

        int rounds = 0;
        final int maxRounds = 3;

        while (!worklist.isEmpty() && rounds < maxRounds) {
            rounds++;
            java.util.Deque<Map.Entry<Address, FunctionProfile>> nextWorklist = new java.util.ArrayDeque<>();

            while (!worklist.isEmpty()) {
                Map.Entry<Address, FunctionProfile> entry = worklist.poll();
                Address srcAddr = entry.getKey();
                FunctionProfile targetProfile = entry.getValue();

                Function srcFunc = sourceProgram.getFunctionManager().getFunctionAt(srcAddr);
                if (srcFunc == null) {
                    continue;
                }

                FunctionProfile targetNeighborProfile = targetIndex.byEntryPoint().get(
                        targetProfile.candidate().entryPoint());
                if (targetNeighborProfile == null) {
                    continue;
                }

                Set<Function> srcCallees;
                try {
                    srcCallees = srcFunc.getCalledFunctions(TaskMonitor.DUMMY);
                } catch (Exception e) {
                    continue;
                }

                for (Function srcCallee : srcCallees) {
                    if (srcCallee.isExternal() || srcCallee.isThunk()) {
                        continue;
                    }
                    Address calleeAddr = srcCallee.getEntryPoint();
                    if (processedSource.contains(calleeAddr)) {
                        continue;
                    }

                    FunctionProfile calleeProfile = buildFunctionProfile(
                            sourceProgram, srcCallee, targetIndex.maxInstructions());
                    if (calleeProfile == null) {
                        continue;
                    }

                    List<ScoredMatch> candidates = findBestMatches(
                            calleeProfile, targetIndex, minConfidence, 5);
                    if (!candidates.isEmpty()) {
                        ScoredMatch best = candidates.get(0);
                        boolean unambiguous = candidates.size() == 1
                                || best.score() - candidates.get(1).score() > 0.05;
                        if (unambiguous) {
                            double boosted = Math.min(1.0, best.score() + 0.05);
                            ScoredMatch propagated = new ScoredMatch(
                                    best.candidate(), boosted, "propagated-" + best.strategy());
                            newMatches.put(calleeAddr, propagated);
                            processedSource.add(calleeAddr);

                            FunctionProfile targetMatch = targetIndex.byEntryPoint().get(
                                    best.candidate().entryPoint());
                            if (targetMatch != null) {
                                nextWorklist.add(Map.entry(calleeAddr, targetMatch));
                            }
                        }
                    }
                }
            }
            worklist = nextWorklist;
        }

        return newMatches;
    }

    // ========================== Enhanced matching helpers ==========================

    private static List<String> extractMeaningfulCalleeNames(Function function) {
        Set<Function> callees;
        try {
            callees = function.getCalledFunctions(TaskMonitor.DUMMY);
        } catch (Exception e) {
            return List.of();
        }

        List<String> names = new ArrayList<>();
        for (Function callee : callees) {
            Function resolved = callee;
            Set<Function> visited = new HashSet<>();
            while (resolved.isThunk() && visited.add(resolved)) {
                Function thunked = resolved.getThunkedFunction(true);
                if (thunked == null) {
                    break;
                }
                resolved = thunked;
            }
            String name = resolved.getName();
            if (resolved.isExternal() || !SymbolUtil.isDefaultSymbolName(name)) {
                names.add(name);
            }
        }
        Collections.sort(names);
        return names;
    }

    private static boolean isNotableConstant(long value) {
        if (value >= -16 && value <= 256) {
            return false;
        }
        long unsigned = value & 0xFFFFFFFFL;
        if (unsigned == 0xFFFFFFFFL || unsigned == 0xFFFFL || unsigned == 0xFFL) {
            return false;
        }
        long abs = Math.abs(value);
        if (abs > 0 && Long.bitCount(abs) == 1) {
            return false;
        }
        return abs <= 0 || Long.bitCount(abs + 1) != 1;
    }

    private static String hashStringList(List<String> strings) {
        try {
            return sha256Hex(String.join("\0", strings));
        } catch (Exception e) {
            return null;
        }
    }

    private static List<ScoredMatch> disambiguateByFeatures(
            FunctionProfile source, List<FunctionProfile> candidates, String baseStrategy) {
        List<ScoredMatch> scored = new ArrayList<>();
        for (FunctionProfile target : candidates) {
            double featureSim = computeMultiFeatureSimilarity(source, target);
            scored.add(new ScoredMatch(target.candidate(), featureSim, baseStrategy));
        }
        Collections.sort(scored);

        if (scored.size() >= 2
                && scored.get(0).score() - scored.get(1).score() > 0.05) {
            double boosted = "exact-fingerprint".equals(baseStrategy)
                    ? 1.0
                    : Math.max(scored.get(0).score(), 0.90);
            return List.of(new ScoredMatch(scored.get(0).candidate(), boosted, baseStrategy));
        }
        return scored;
    }

    /**
     * Build a combined shortlist from callee-name overlap AND individual string overlap.
     * Union of candidates from both inverted indexes gives much better recall than
     * callee-overlap alone for functions that reference unique strings but share no callees.
     */
    private static Set<Integer> buildCombinedShortlist(
            FunctionProfile source, EnhancedProgramIndex targetIndex) {
        Set<Integer> candidates = new HashSet<>();
        for (String calleeName : source.calleeNames()) {
            List<Integer> indexes = targetIndex.calleeNameIndex().get(calleeName);
            if (indexes != null) {
                candidates.addAll(indexes);
            }
        }
        for (String str : source.stringRefs()) {
            List<Integer> indexes = targetIndex.stringIndex().get(str);
            if (indexes != null) {
                candidates.addAll(indexes);
            }
        }
        return candidates;
    }

    /**
     * Quick structural compatibility check using body size, instruction count,
     * and cyclomatic complexity. Rejects obviously incompatible pairs early to
     * avoid expensive multi-feature scoring.
     */
    private static boolean structurallyCompatible(FunctionProfile a, FunctionProfile b) {
        if (a.bodySize() > 0 && b.bodySize() > 0) {
            long maxSize = Math.max(a.bodySize(), b.bodySize());
            long minSize = Math.min(a.bodySize(), b.bodySize());
            if (minSize > 0 && maxSize > minSize * 3) {
                return false;
            }
        }
        if (a.instructionCount() > 0 && b.instructionCount() > 0) {
            int maxCount = Math.max(a.instructionCount(), b.instructionCount());
            int minCount = Math.min(a.instructionCount(), b.instructionCount());
            if (minCount > 0 && maxCount > minCount * 3) {
                return false;
            }
        }
        if (a.cyclomaticComplexity() > 2 && b.cyclomaticComplexity() > 2) {
            int maxCC = Math.max(a.cyclomaticComplexity(), b.cyclomaticComplexity());
            int minCC = Math.min(a.cyclomaticComplexity(), b.cyclomaticComplexity());
            if (maxCC > minCC * 5) {
                return false;
            }
        }
        return true;
    }

    /**
     * Weighted multi-feature similarity combining call-graph, data-reference,
     * structural, instruction-histogram, and instruction-sequence features.
     *
     * Weights adapt dynamically: features that are absent in both profiles contribute
     * zero weight, and the remaining weights are renormalized. Instruction-category
     * histogram cosine similarity replaces raw Levenshtein for the instruction-mix
     * dimension, making this robust to instruction reordering.
     */
    static double computeMultiFeatureSimilarity(FunctionProfile a, FunctionProfile b) {
        double calleeScore = jaccardSimilarity(a.calleeNames(), b.calleeNames());
        double stringScore = jaccardSimilarity(a.stringRefs(), b.stringRefs());
        double constantScore = constantJaccardSimilarity(a.notableConstants(), b.notableConstants());
        double structScore = structuralSimilarity(a, b);
        double histScore = histogramCosineSimilarity(a.instrHistogram(), b.instrHistogram());
        double sigScore = computeSignatureSimilarity(a.canonicalSignature(), b.canonicalSignature());

        boolean hasCallees = !a.calleeNames().isEmpty() || !b.calleeNames().isEmpty();
        boolean hasStrings = !a.stringRefs().isEmpty() || !b.stringRefs().isEmpty();
        boolean hasConstants = a.notableConstants().length > 0 || b.notableConstants().length > 0;
        boolean hasHistogram = hasNonzeroHistogram(a.instrHistogram()) || hasNonzeroHistogram(b.instrHistogram());

        double wCallee = hasCallees ? 0.25 : 0;
        double wString = hasStrings ? 0.20 : 0;
        double wConst = hasConstants ? 0.10 : 0;
        double wStruct = 0.10;
        double wHist = hasHistogram ? 0.15 : 0;
        double wSig = 0.20;
        double total = wCallee + wString + wConst + wStruct + wHist + wSig;
        if (total <= 0) {
            return 0;
        }

        return (calleeScore * wCallee
                + stringScore * wString
                + constantScore * wConst
                + structScore * wStruct
                + histScore * wHist
                + sigScore * wSig) / total;
    }

    private static double jaccardSimilarity(List<String> a, List<String> b) {
        if (a.isEmpty() || b.isEmpty()) {
            return 0;
        }
        Set<String> setA = new HashSet<>(a);
        Set<String> setB = new HashSet<>(b);
        long intersection = setA.stream().filter(setB::contains).count();
        long union = setA.size() + setB.size() - intersection;
        return union == 0 ? 0 : (double) intersection / union;
    }

    private static double constantJaccardSimilarity(long[] a, long[] b) {
        if (a.length == 0 || b.length == 0) {
            return 0;
        }
        Set<Long> setA = new HashSet<>();
        for (long v : a) {
            setA.add(v);
        }
        Set<Long> setB = new HashSet<>();
        for (long v : b) {
            setB.add(v);
        }
        long intersection = setA.stream().filter(setB::contains).count();
        long union = setA.size() + setB.size() - intersection;
        return union == 0 ? 0 : (double) intersection / union;
    }

    /**
     * Structural similarity combining body size, instruction count, branch count,
     * edge count, cyclomatic complexity, and parameter count into a single [0,1] score.
     */
    private static double structuralSimilarity(FunctionProfile a, FunctionProfile b) {
        double scores = 0;
        int count = 0;

        if (a.bodySize() > 0 && b.bodySize() > 0) {
            scores += ratioSimilarity(a.bodySize(), b.bodySize());
            count++;
        }
        if (a.instructionCount() > 0 && b.instructionCount() > 0) {
            scores += ratioSimilarity(a.instructionCount(), b.instructionCount());
            count++;
        }
        scores += intDiffSimilarity(a.branchCount(), b.branchCount());
        count++;

        if (a.edgeCount() > 0 && b.edgeCount() > 0) {
            scores += ratioSimilarity(a.edgeCount(), b.edgeCount());
            count++;
        }
        if (a.cyclomaticComplexity() > 1 && b.cyclomaticComplexity() > 1) {
            scores += ratioSimilarity(a.cyclomaticComplexity(), b.cyclomaticComplexity());
            count++;
        }

        if (a.parameterCount() == b.parameterCount()) {
            scores += 1.0;
            count++;
        } else if (a.parameterCount() > 0 && b.parameterCount() > 0) {
            scores += ratioSimilarity(a.parameterCount(), b.parameterCount());
            count++;
        }
        return count == 0 ? 0 : scores / count;
    }

    private static double ratioSimilarity(long a, long b) {
        return (double) Math.min(a, b) / Math.max(a, b);
    }

    private static double intDiffSimilarity(int a, int b) {
        if (a == 0 && b == 0) {
            return 1.0;
        }
        int mx = Math.max(a, b);
        return mx > 0 ? 1.0 - ((double) Math.abs(a - b) / mx) : 0;
    }

    private static <T> List<T> cap(List<T> list, int max) {
        return list.size() <= max ? list : list.subList(0, max);
    }

    /**
     * Cosine similarity between two instruction-category histograms.
     * Returns 1.0 for identical distributions, 0.0 for orthogonal.
     * This is far more robust to instruction reordering than Levenshtein on instruction sequences.
     */
    static double histogramCosineSimilarity(int[] a, int[] b) {
        if (a == null || b == null || a.length != b.length) {
            return 0;
        }
        long dot = 0, normA = 0, normB = 0;
        for (int i = 0; i < a.length; i++) {
            dot += (long) a[i] * b[i];
            normA += (long) a[i] * a[i];
            normB += (long) b[i] * b[i];
        }
        if (normA == 0 || normB == 0) {
            return 0;
        }
        return dot / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private static boolean hasNonzeroHistogram(int[] histogram) {
        if (histogram == null) {
            return false;
        }
        for (int v : histogram) {
            if (v != 0) {
                return true;
            }
        }
        return false;
    }

    private static String hashLongArray(long[] values) {
        if (values == null || values.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (long v : values) {
            if (!sb.isEmpty()) {
                sb.append('\0');
            }
            sb.append(v);
        }
        try {
            return sha256Hex(sb.toString());
        } catch (Exception e) {
            return null;
        }
    }

    // ========================== Original fingerprinting methods ==========================

    /**
     * Compute a SHA-256 fingerprint for a function.
     *
     * @param program Program containing the function
     * @param function Function to fingerprint
     * @return fingerprint string (hex), or null if fingerprinting fails
     */
    public static String computeFingerprint(Program program, Function function) {
        return computeFingerprint(program, function, DEFAULT_MAX_INSTRUCTIONS);
    }

    /**
     * Compute a SHA-256 fingerprint for a function using the first {@code maxInstructions}.
     *
     * @param program Program containing the function
     * @param function Function to fingerprint
     * @param maxInstructions Number of instructions to include (recommended: 32-128)
     * @return fingerprint string (hex), or null if fingerprinting fails
     */
    public static String computeFingerprint(Program program, Function function, int maxInstructions) {
        try {
            String canonical = buildCanonicalSignature(program, function, maxInstructions);
            if (canonical == null || canonical.isEmpty()) {
                return null;
            }
            return computeFingerprintFromCanonicalSignature(canonical);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Compute the fingerprint hash for an already-computed canonical signature.
     *
     * @param canonicalSignature canonical signature string (see {@link #computeCanonicalSignature(Program, Function, int)})
     * @return fingerprint string (hex), or null if hashing fails
     */
    public static String computeFingerprintFromCanonicalSignature(String canonicalSignature) {
        if (canonicalSignature == null || canonicalSignature.isEmpty()) {
            return null;
        }
        try {
            return sha256Hex(canonicalSignature);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Find fingerprint matches for {@code fingerprint} in {@code targetProgram}.
     *
     * @param targetProgram Target program to search
     * @param fingerprint Fingerprint string
     * @param maxInstructions Fingerprint configuration used for the index
     * @return candidate list (possibly empty)
     */
    public static List<Candidate> findMatches(Program targetProgram, String fingerprint, int maxInstructions) {
        if (fingerprint == null || fingerprint.isEmpty() || targetProgram == null) {
            return List.of();
        }
        CachedProgramIndex index = getOrBuildIndex(targetProgram, maxInstructions);
        List<Candidate> matches = index.byFingerprint().get(fingerprint);
        if (matches == null || matches.isEmpty()) {
            return List.of();
        }
        if (matches.size() <= MAX_CANDIDATES_RETURNED) {
            return matches;
        }
        return matches.subList(0, MAX_CANDIDATES_RETURNED);
    }

    /**
     * Build a snapshot index for a program in a single pass.
     * <p>
     * This computes canonical signatures once per function and derives both:
     * - exact fingerprints (SHA-256 of signature) and
     * - signature entries for fuzzy matching.
     * </p>
     */
    public static ProgramIndex buildProgramIndex(Program program, int maxInstructions) {
        if (program == null) {
            return new ProgramIndex("", maxInstructions, Map.of(), List.of(), Map.of());
        }

        String programPath = program.getDomainFile().getPathname();
        Map<String, List<Candidate>> byFingerprint = new HashMap<>();
        List<SignatureEntry> signatures = new ArrayList<>();
        Map<Integer, List<Integer>> tokenToSignatureIndexes = new HashMap<>();

        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal()) {
                continue;
            }

            boolean degenerate = isDegenerateFunction(f);

            String sig;
            try {
                sig = buildCanonicalSignature(program, f, maxInstructions);
            } catch (Exception e) {
                continue;
            }
            if (sig == null || sig.isEmpty()) {
                continue;
            }

            String fp = computeFingerprintFromCanonicalSignature(sig);
            if (fp == null || fp.isEmpty()) {
                continue;
            }

            int instructionCount = extractIntField(sig, "C=");

            Candidate cand = new Candidate(programPath, f.getName(), f.getEntryPoint());
            byFingerprint.computeIfAbsent(fp, k -> new ArrayList<>()).add(cand);

            if (degenerate || instructionCount < MIN_MEANINGFUL_INSTRUCTIONS) {
                continue;
            }

            long bodySize = extractLongField(sig, "B=");
            int[] tokenHashes = buildUniqueInstructionTokenHashes(sig);
            int signatureIndex = signatures.size();
            signatures.add(new SignatureEntry(cand, sig, bodySize, instructionCount, tokenHashes.length));
            for (int tokenHash : tokenHashes) {
                tokenToSignatureIndexes.computeIfAbsent(tokenHash, k -> new ArrayList<>()).add(signatureIndex);
            }
        }

        for (Map.Entry<String, List<Candidate>> e : byFingerprint.entrySet()) {
            e.getValue().sort((a, b) -> a.entryPoint().compareTo(b.entryPoint()));
        }

        byFingerprint.entrySet().removeIf(e -> e.getValue().size() > MAX_DEGENERATE_BUCKET_SIZE);

        Map<Integer, List<Integer>> immutableTokenIndex = new HashMap<>();
        for (Map.Entry<Integer, List<Integer>> entry : tokenToSignatureIndexes.entrySet()) {
            immutableTokenIndex.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }

        return new ProgramIndex(
                programPath,
                maxInstructions,
                Collections.unmodifiableMap(byFingerprint),
                Collections.unmodifiableList(signatures),
                Collections.unmodifiableMap(immutableTokenIndex)
        );
    }

    /**
     * Find matches in a prebuilt {@link ProgramIndex} without consulting global caches.
     */
    public static List<Candidate> findMatches(ProgramIndex index, String fingerprint) {
        if (index == null || fingerprint == null || fingerprint.isEmpty()) {
            return List.of();
        }
        List<Candidate> matches = index.byFingerprint().get(fingerprint);
        if (matches == null || matches.isEmpty()) {
            return List.of();
        }
        if (matches.size() <= MAX_CANDIDATES_RETURNED) {
            return matches;
        }
        return matches.subList(0, MAX_CANDIDATES_RETURNED);
    }

    /**
     * Find fuzzy matches using a prebuilt {@link ProgramIndex} without consulting global caches.
     */
    public static List<Candidate.Scored> findFuzzyMatches(String sourceCanonicalSignature,
            ProgramIndex targetIndex, double minSimilarity, int maxResults) {
        if (sourceCanonicalSignature == null || sourceCanonicalSignature.isEmpty() || targetIndex == null) {
            return List.of();
        }

        int sourceInstructionCount = extractIntField(sourceCanonicalSignature, "C=");
        if (sourceInstructionCount < MIN_MEANINGFUL_INSTRUCTIONS) {
            return List.of();
        }

        long sourceBodySize = extractLongField(sourceCanonicalSignature, "B=");

        List<Candidate.Scored> scored = new ArrayList<>();
        Candidate.Scored perfectMatch = null;

        double sizeTolerance = 0.5; // Allow 50% size difference
        long minSize = (long) (sourceBodySize * (1.0 - sizeTolerance));
        long maxSize = (long) (sourceBodySize * (1.0 + sizeTolerance));
        int minInstrCount = Math.max(1, (int) (sourceInstructionCount * (1.0 - sizeTolerance)));
        int maxInstrCount = (int) (sourceInstructionCount * (1.0 + sizeTolerance)) + 1;

        int[] sourceTokenHashes = buildUniqueInstructionTokenHashes(sourceCanonicalSignature);
        List<Integer> candidateIndexes = shortlistCandidateIndexes(sourceTokenHashes, targetIndex, minSimilarity, maxResults);
        boolean useShortlist = !candidateIndexes.isEmpty();

        Iterable<SignatureEntry> candidates = useShortlist
                ? candidateIndexes.stream().map(i -> targetIndex.signatures().get(i)).toList()
                : targetIndex.signatures();

        for (SignatureEntry entry : candidates) {
            if (sourceBodySize > 0 && entry.bodySize() > 0) {
                if (entry.bodySize() < minSize || entry.bodySize() > maxSize) {
                    continue;
                }
            }
            if (sourceInstructionCount > 0 && entry.instructionCount() > 0) {
                if (entry.instructionCount() < minInstrCount || entry.instructionCount() > maxInstrCount) {
                    continue;
                }
            }

            String targetSig = entry.signature();
            if (targetSig == null || targetSig.isEmpty()) {
                continue;
            }

            if (sourceCanonicalSignature.equals(targetSig)) {
                perfectMatch = new Candidate.Scored(entry.candidate(), 1.0);
                break;
            }

            int lenDiff = Math.abs(sourceCanonicalSignature.length() - targetSig.length());
            int maxLen = Math.max(sourceCanonicalSignature.length(), targetSig.length());
            if (maxLen > 0) {
                double lengthSimilarity = 1.0 - ((double) lenDiff / maxLen);
                if (lengthSimilarity < minSimilarity * 0.7) {
                    continue;
                }
            }

            double similarity = computeSignatureSimilarity(sourceCanonicalSignature, targetSig);
            if (similarity >= minSimilarity) {
                scored.add(new Candidate.Scored(entry.candidate(), similarity));
            }
        }

        if (perfectMatch != null) {
            return List.of(perfectMatch);
        }

        scored.sort((a, b) -> {
            int cmp = Double.compare(b.similarityScore(), a.similarityScore());
            if (cmp != 0) {
                return cmp;
            }
            return a.candidate().entryPoint().compareTo(b.candidate().entryPoint());
        });

        if (scored.size() <= maxResults) {
            return scored;
        }
        return scored.subList(0, maxResults);
    }

    private static List<Integer> shortlistCandidateIndexes(int[] sourceTokenHashes, ProgramIndex targetIndex,
            double minSimilarity, int maxResults) {
        if (sourceTokenHashes.length == 0 || targetIndex.tokenToSignatureIndexes().isEmpty()
                || targetIndex.signatures().isEmpty()) {
            return List.of();
        }

        Map<Integer, Integer> overlapCounts = new HashMap<>();
        for (int tokenHash : sourceTokenHashes) {
            List<Integer> postings = targetIndex.tokenToSignatureIndexes().get(tokenHash);
            if (postings == null || postings.isEmpty()) {
                continue;
            }
            for (Integer idx : postings) {
                overlapCounts.merge(idx, 1, Integer::sum);
            }
        }
        if (overlapCounts.isEmpty()) {
            return List.of();
        }

        int requested = Math.max(FUZZY_SHORTLIST_MIN, maxResults * FUZZY_SHORTLIST_FACTOR);
        requested = Math.min(requested, FUZZY_SHORTLIST_MAX);
        requested = Math.min(requested, targetIndex.signatures().size());

        int minOverlap = Math.max(1, (int) Math.floor(sourceTokenHashes.length * Math.max(0.08, minSimilarity * 0.2)));

        List<Map.Entry<Integer, Integer>> ranked = new ArrayList<>(overlapCounts.entrySet());
        ranked.sort((a, b) -> {
            int cmp = Integer.compare(b.getValue(), a.getValue());
            if (cmp != 0) {
                return cmp;
            }
            return Integer.compare(a.getKey(), b.getKey());
        });

        List<Integer> shortlist = new ArrayList<>(Math.min(requested, ranked.size()));
        for (Map.Entry<Integer, Integer> entry : ranked) {
            if (entry.getValue() < minOverlap && shortlist.size() >= requested / 2) {
                break;
            }
            shortlist.add(entry.getKey());
            if (shortlist.size() >= requested) {
                break;
            }
        }

        return shortlist;
    }

    /**
     * Get (or build) a fingerprint index for a program.
     *
     * @param program Program to index
     * @param maxInstructions Instruction sampling size
     * @return cached index
     */
    private static CachedProgramIndex getOrBuildIndex(Program program, int maxInstructions) {
        // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
        String programPath = program.getDomainFile().getPathname();
        // Ghidra API: Program.getModificationNumber() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getModificationNumber()
        long mod = program.getModificationNumber();

        CachedProgramIndex cached = INDEX_CACHE.get(programPath);
        if (cached != null && cached.programModificationNumber == mod && cached.maxInstructions == maxInstructions) {
            return cached;
        }

        Map<String, List<Candidate>> byFingerprint = new HashMap<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal() || isDegenerateFunction(f)) {
                continue;
            }
            String fp = computeFingerprint(program, f, maxInstructions);
            if (fp == null) {
                continue;
            }
            Candidate cand = new Candidate(programPath, f.getName(), f.getEntryPoint());
            byFingerprint.computeIfAbsent(fp, k -> new ArrayList<>()).add(cand);
        }

        for (Map.Entry<String, List<Candidate>> e : byFingerprint.entrySet()) {
            e.getValue().sort((a, b) -> a.entryPoint().compareTo(b.entryPoint()));
        }
        byFingerprint.entrySet().removeIf(e -> e.getValue().size() > MAX_DEGENERATE_BUCKET_SIZE);

        CachedProgramIndex built = new CachedProgramIndex(mod, maxInstructions,
            Collections.unmodifiableMap(byFingerprint));
        INDEX_CACHE.put(programPath, built);
        return built;
    }

    private static String buildCanonicalSignature(Program program, Function function, int maxInstructions) {
        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();
        // Ghidra API: Listing.getInstructions(AddressSetView, boolean), Function.getBody() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getInstructions(ghidra.program.model.address.AddressSetView,boolean)
        InstructionIterator instrIter = listing.getInstructions(function.getBody(), true);

        StringBuilder sb = new StringBuilder(4096);

        long bodySize = 0;
        try {
            // Ghidra API: Function.getBody(), AddressSetView.getNumAddresses() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
            bodySize = function.getBody().getNumAddresses();
        } catch (Exception e) {
            // Keep default (0) on error
        }

        // Add coarse metadata (helps reduce collisions for tiny stubs)
        sb.append("B=").append(bodySize).append(';');
        sb.append("N=").append(maxInstructions).append(';');

        int count = 0;
        while (instrIter.hasNext() && count < maxInstructions) {
            // Ghidra API: InstructionIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/InstructionIterator.html#next()
            Instruction instr = instrIter.next();
            if (instr == null) {
                continue;
            }
            // Ghidra API: Instruction.getMnemonicString() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getMnemonicString()
            sb.append(instr.getMnemonicString());
            sb.append('(');
            // Ghidra API: Instruction.getNumOperands() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getNumOperands()
            int opCount = instr.getNumOperands();
            for (int i = 0; i < opCount; i++) {
                // Ghidra API: Instruction.getOperandType(int) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getOperandType(int)
                int opType = instr.getOperandType(i);
                sb.append(operandTypeCategory(opType));
                if (i + 1 < opCount) {
                    sb.append(',');
                }
            }
            sb.append(')');
            sb.append(';');
            count++;
        }

        sb.append("C=").append(count).append(';');
        return sb.toString();
    }

    /**
     * Map Ghidra operand type bitmask to a small canonical category string.
     * This intentionally discards concrete values (addresses/immediates) to survive rebases.
     */
    private static String operandTypeCategory(int operandType) {
        // Order matters: some operands have multiple bits.
        if ((operandType & OperandType.REGISTER) != 0) {
            return "reg";
        }
        if ((operandType & OperandType.SCALAR) != 0) {
            return "imm";
        }
        if ((operandType & OperandType.ADDRESS) != 0) {
            return "addr";
        }
        if ((operandType & OperandType.DYNAMIC) != 0) {
            return "dyn";
        }
        if ((operandType & OperandType.DATA) != 0) {
            return "data";
        }
        if ((operandType & OperandType.IMMEDIATE) != 0) {
            return "imm";
        }
        // NOTE: OperandType.MEMORY was removed in Ghidra 12.0
        // Memory operands are typically covered by ADDRESS or DATA types
        return "other";
    }

    /**
     * Compute the canonical signature (without hashing) for similarity matching.
     * This is the same format used for exact fingerprints but returned as a string.
     *
     * @param program Program containing the function
     * @param function Function to analyze
     * @param maxInstructions Number of instructions to include
     * @return canonical signature string, or null if computation fails
     */
    public static String computeCanonicalSignature(Program program, Function function, int maxInstructions) {
        try {
            return buildCanonicalSignature(program, function, maxInstructions);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Find fuzzy matches for a source function in a target program using similarity scoring.
     * Returns candidates sorted by similarity (highest first).
     * 
     * <p>Optimized for large-scale matching (16k+ functions) by:
     * - Pre-indexing target program signatures (cached)
     * - Size-based pre-filtering to reduce comparisons
     * - Early termination for perfect matches
     * - Limiting expensive Levenshtein calculations
     *
     * @param sourceProgram Source program containing the reference function
     * @param sourceFunction Source function to match
     * @param targetProgram Target program to search
     * @param maxInstructions Number of instructions to use for comparison
     * @param minSimilarity Minimum similarity score (0.0-1.0) to include in results
     * @param maxResults Maximum number of results to return
     * @return List of scored candidates, sorted by similarity (highest first)
     */
    public static List<Candidate.Scored> findFuzzyMatches(Program sourceProgram, Function sourceFunction,
            Program targetProgram, int maxInstructions, double minSimilarity, int maxResults) {
        if (sourceFunction == null || targetProgram == null) {
            return List.of();
        }
        if (isDegenerateFunction(sourceFunction)) {
            return List.of();
        }

        String sourceSig = computeCanonicalSignature(sourceProgram, sourceFunction, maxInstructions);
        if (sourceSig == null || sourceSig.isEmpty()) {
            return List.of();
        }

        // Extract source function metadata for size filtering
        long sourceBodySize = 0;
        int sourceInstructionCount = 0;
        try {
            // Ghidra API: Function.getBody(), AddressSetView.getNumAddresses() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
            sourceBodySize = sourceFunction.getBody().getNumAddresses();
            // Extract instruction count from signature (format: "C=64;")
            int cIdx = sourceSig.indexOf("C=");
            if (cIdx >= 0) {
                int endIdx = sourceSig.indexOf(';', cIdx);
                if (endIdx > cIdx) {
                    try {
                        sourceInstructionCount = Integer.parseInt(sourceSig.substring(cIdx + 2, endIdx));
                    } catch (NumberFormatException e) {
                        // Ignore
                    }
                }
            }
        } catch (Exception e) {
            // Ignore size extraction errors
        }

        // Get or build signature index for target program
        CachedSignatureIndex index = getOrBuildSignatureIndex(targetProgram, maxInstructions);

        List<Candidate.Scored> scored = new ArrayList<>();
        Candidate.Scored perfectMatch = null;

        // Size-based pre-filtering: only compare functions with similar sizes
        // This dramatically reduces comparisons for large programs
        double sizeTolerance = 0.5; // Allow 50% size difference
        long minSize = (long) (sourceBodySize * (1.0 - sizeTolerance));
        long maxSize = (long) (sourceBodySize * (1.0 + sizeTolerance));
        int minInstrCount = Math.max(1, (int) (sourceInstructionCount * (1.0 - sizeTolerance)));
        int maxInstrCount = (int) (sourceInstructionCount * (1.0 + sizeTolerance)) + 1;

        for (CachedSignatureIndex.IndexedFunction indexedFunc : index.functions()) {
            // Quick size-based pre-filter (avoids expensive signature computation)
            if (sourceBodySize > 0 && indexedFunc.bodySize() > 0) {
                if (indexedFunc.bodySize() < minSize || indexedFunc.bodySize() > maxSize) {
                    continue;
                }
            }
            if (sourceInstructionCount > 0 && indexedFunc.instructionCount() > 0) {
                if (indexedFunc.instructionCount() < minInstrCount || 
                    indexedFunc.instructionCount() > maxInstrCount) {
                    continue;
                }
            }

            String targetSig = indexedFunc.signature();
            if (targetSig == null || targetSig.isEmpty()) {
                continue;
            }

            // Fast path: exact match (no need for Levenshtein)
            if (sourceSig.equals(targetSig)) {
                perfectMatch = new Candidate.Scored(indexedFunc.candidate(), 1.0);
                break; // Early termination for perfect match
            }

            // Quick length-based filter before expensive Levenshtein
            int lenDiff = Math.abs(sourceSig.length() - targetSig.length());
            int maxLen = Math.max(sourceSig.length(), targetSig.length());
            if (maxLen > 0) {
                double lengthSimilarity = 1.0 - ((double) lenDiff / maxLen);
                // If length similarity is too low, skip expensive Levenshtein
                if (lengthSimilarity < minSimilarity * 0.7) {
                    continue;
                }
            }

            double similarity = computeSignatureSimilarity(sourceSig, targetSig);
            if (similarity >= minSimilarity) {
                scored.add(new Candidate.Scored(indexedFunc.candidate(), similarity));
            }
        }

        // If we found a perfect match, return it immediately
        if (perfectMatch != null) {
            return List.of(perfectMatch);
        }

        // Sort by similarity (highest first), then by address for determinism
        scored.sort((a, b) -> {
            int cmp = Double.compare(b.similarityScore(), a.similarityScore());
            if (cmp != 0) {
                return cmp;
            }
            return a.candidate().entryPoint().compareTo(b.candidate().entryPoint());
        });

        if (scored.size() <= maxResults) {
            return scored;
        }
        return scored.subList(0, maxResults);
    }

    /**
     * Get or build a signature index for a program (cached for performance).
     * This pre-computes all function signatures to avoid recomputation during fuzzy matching.
     *
     * @param program Program to index
     * @param maxInstructions Instruction sampling size
     * @return cached signature index
     */
    private static CachedSignatureIndex getOrBuildSignatureIndex(Program program, int maxInstructions) {
        // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
        String programPath = program.getDomainFile().getPathname();
        // Ghidra API: Program.getModificationNumber() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getModificationNumber()
        long mod = program.getModificationNumber();

        CachedSignatureIndex cached = SIGNATURE_INDEX_CACHE.get(programPath);
        if (cached != null && cached.programModificationNumber == mod && 
            cached.maxInstructions == maxInstructions) {
            return cached;
        }

        List<CachedSignatureIndex.IndexedFunction> indexed = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        String targetPath = program.getDomainFile().getPathname();

        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal() || isDegenerateFunction(f)) {
                continue;
            }

            String sig = computeCanonicalSignature(program, f, maxInstructions);
            if (sig == null || sig.isEmpty()) {
                continue;
            }

            long bodySize = 0;
            int instructionCount = 0;
            try {
                bodySize = f.getBody().getNumAddresses();
                instructionCount = extractIntField(sig, "C=");
            } catch (Exception e) {
                // Ignore size extraction errors
            }

            if (instructionCount < MIN_MEANINGFUL_INSTRUCTIONS) {
                continue;
            }

            Candidate cand = new Candidate(targetPath, f.getName(), f.getEntryPoint());
            indexed.add(new CachedSignatureIndex.IndexedFunction(cand, sig, bodySize, instructionCount));
        }

        indexed.sort((a, b) -> a.candidate().entryPoint().compareTo(b.candidate().entryPoint()));

        CachedSignatureIndex built = new CachedSignatureIndex(mod, maxInstructions,
            Collections.unmodifiableList(indexed));
        SIGNATURE_INDEX_CACHE.put(programPath, built);
        return built;
    }

    /**
     * Compute similarity between two canonical signatures using normalized edit distance.
     * Returns a score between 0.0 (completely different) and 1.0 (identical).
     *
     * @param sig1 First canonical signature
     * @param sig2 Second canonical signature
     * @return similarity score (0.0-1.0)
     */
    public static double computeSignatureSimilarity(String sig1, String sig2) {
        if (sig1 == null || sig2 == null || sig1.isEmpty() || sig2.isEmpty()) {
            return 0.0;
        }
        if (sig1.equals(sig2)) {
            return 1.0;
        }

        // Use normalized Levenshtein distance
        int maxLen = Math.max(sig1.length(), sig2.length());
        if (maxLen == 0) {
            return 1.0;
        }

        int distance = levenshteinDistance(sig1, sig2);
        return 1.0 - ((double) distance / maxLen);
    }

    public static int extractIntField(String sig, String prefix) {
        if (sig == null || sig.isEmpty() || prefix == null || prefix.isEmpty()) {
            return 0;
        }
        int idx = sig.indexOf(prefix);
        if (idx < 0) {
            return 0;
        }
        int endIdx = sig.indexOf(';', idx);
        if (endIdx <= idx) {
            return 0;
        }
        try {
            return Integer.parseInt(sig.substring(idx + prefix.length(), endIdx));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long extractLongField(String sig, String prefix) {
        if (sig == null || sig.isEmpty() || prefix == null || prefix.isEmpty()) {
            return 0;
        }
        int idx = sig.indexOf(prefix);
        if (idx < 0) {
            return 0;
        }
        int endIdx = sig.indexOf(';', idx);
        if (endIdx <= idx) {
            return 0;
        }
        try {
            return Long.parseLong(sig.substring(idx + prefix.length(), endIdx));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static int[] buildUniqueInstructionTokenHashes(String canonicalSignature) {
        if (canonicalSignature == null || canonicalSignature.isEmpty()) {
            return new int[0];
        }

        Set<Integer> tokenHashes = new HashSet<>();
        List<String> instructionUnits = extractInstructionUnits(canonicalSignature);
        String prev = null;
        for (String unit : instructionUnits) {
            if (unit == null || unit.isEmpty()) {
                continue;
            }
            tokenHashes.add(unit.hashCode());
            if (prev != null) {
                tokenHashes.add((prev + ">" + unit).hashCode());
            }
            prev = unit;
        }

        int[] hashes = new int[tokenHashes.size()];
        int i = 0;
        for (Integer hash : tokenHashes) {
            hashes[i++] = hash;
        }
        return hashes;
    }

    private static List<String> extractInstructionUnits(String canonicalSignature) {
        List<String> units = new ArrayList<>();
        int start = 0;
        while (start < canonicalSignature.length()) {
            int end = canonicalSignature.indexOf(';', start);
            if (end < 0) {
                break;
            }
            if (end > start) {
                String segment = canonicalSignature.substring(start, end);
                if (!segment.startsWith("B=") && !segment.startsWith("N=") && !segment.startsWith("C=")) {
                    units.add(segment);
                }
            }
            start = end + 1;
        }
        return units;
    }

    /**
     * Compute Levenshtein (edit) distance between two strings.
     * Optimized with early termination for large differences.
     */
    private static int levenshteinDistance(String s1, String s2) {
        int m = s1.length();
        int n = s2.length();
        
        // Early termination: if length difference is too large, skip expensive calculation
        int lenDiff = Math.abs(m - n);
        int maxLen = Math.max(m, n);
        if (maxLen > 0 && lenDiff > maxLen * 0.5) {
            // Return approximate distance for very different lengths
            return lenDiff + Math.min(m, n);
        }
        
        // Use space-optimized version for large strings (O(min(m,n)) space instead of O(m*n))
        if (m < n) {
            // Swap to ensure m >= n for space optimization
            String temp = s1;
            s1 = s2;
            s2 = temp;
            int tempLen = m;
            m = n;
            n = tempLen;
        }
        
        // Space-optimized: only keep two rows
        int[] prev = new int[n + 1];
        int[] curr = new int[n + 1];
        
        // Initialize first row
        for (int j = 0; j <= n; j++) {
            prev[j] = j;
        }
        
        // Compute distance row by row
        for (int i = 1; i <= m; i++) {
            curr[0] = i;
            for (int j = 1; j <= n; j++) {
                if (s1.charAt(i - 1) == s2.charAt(j - 1)) {
                    curr[j] = prev[j - 1];
                } else {
                    curr[j] = 1 + Math.min(Math.min(prev[j], curr[j - 1]), prev[j - 1]);
                }
            }
            // Swap arrays for next iteration
            int[] temp = prev;
            prev = curr;
            curr = temp;
        }
        
        return prev[n];
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

