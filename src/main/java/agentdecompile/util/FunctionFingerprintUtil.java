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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

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

    private static final int MAX_CANDIDATES_RETURNED = 25;
    private static final int FUZZY_SHORTLIST_FACTOR = 24;
    private static final int FUZZY_SHORTLIST_MIN = 64;
    private static final int FUZZY_SHORTLIST_MAX = 384;

    private static final Map<String, CachedProgramIndex> INDEX_CACHE = new ConcurrentHashMap<>();

    private FunctionFingerprintUtil() {
        // utility
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

            Candidate cand = new Candidate(programPath, f.getName(), f.getEntryPoint());
            byFingerprint.computeIfAbsent(fp, k -> new ArrayList<>()).add(cand);

            long bodySize = extractLongField(sig, "B=");
            int instructionCount = extractIntField(sig, "C=");
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

        long sourceBodySize = extractLongField(sourceCanonicalSignature, "B=");
        int sourceInstructionCount = extractIntField(sourceCanonicalSignature, "C=");

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
        // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            // Ghidra API: FunctionIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html#next()
            Function f = it.next();
            // Ghidra API: Function.isExternal() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#isExternal()
            if (f == null || f.isExternal()) {
                continue;
            }
            String fp = computeFingerprint(program, f, maxInstructions);
            if (fp == null) {
                continue;
            }
            // Ghidra API: Function.getName(), Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
            Candidate cand = new Candidate(programPath, f.getName(), f.getEntryPoint());
            byFingerprint.computeIfAbsent(fp, k -> new ArrayList<>()).add(cand);
        }

        // Make candidate lists deterministic
        for (Map.Entry<String, List<Candidate>> e : byFingerprint.entrySet()) {
            // Ghidra API: Address.compareTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#compareTo(ghidra.program.model.address.Address)
            e.getValue().sort((a, b) -> a.entryPoint().compareTo(b.entryPoint()));
        }

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
        // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctions(boolean) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager(), https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(boolean)
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
        String targetPath = program.getDomainFile().getPathname();

        while (it.hasNext()) {
            // Ghidra API: FunctionIterator.next() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html#next()
            Function f = it.next();
            // Ghidra API: Function.isExternal() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#isExternal()
            if (f == null || f.isExternal()) {
                continue;
            }

            String sig = computeCanonicalSignature(program, f, maxInstructions);
            if (sig == null || sig.isEmpty()) {
                continue;
            }

            long bodySize = 0;
            int instructionCount = 0;
            try {
                // Ghidra API: Function.getBody(), AddressSetView.getNumAddresses() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getBody()
                bodySize = f.getBody().getNumAddresses();
                // Extract instruction count from signature
                int cIdx = sig.indexOf("C=");
                if (cIdx >= 0) {
                    int endIdx = sig.indexOf(';', cIdx);
                    if (endIdx > cIdx) {
                        try {
                            instructionCount = Integer.parseInt(sig.substring(cIdx + 2, endIdx));
                        } catch (NumberFormatException e) {
                            // Ignore
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore size extraction errors
            }

            // Ghidra API: Function.getName(), Function.getEntryPoint() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getName()
            Candidate cand = new Candidate(targetPath, f.getName(), f.getEntryPoint());
            indexed.add(new CachedSignatureIndex.IndexedFunction(cand, sig, bodySize, instructionCount));
        }

        // Sort by address for determinism
        // Ghidra API: Address.compareTo(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#compareTo(ghidra.program.model.address.Address)
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

    private static int extractIntField(String sig, String prefix) {
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

