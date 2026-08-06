# The ideal swkotor.exe reconstruction loop

What a best-possible implementation looks like, what it would produce, and how
far today's system is from it.

## 1. Where we actually are

From `target/agentdecompile-reconstruct/swkotor-parity/claim-report.json`:

| Class | Count | Meaning |
|---|---:|---|
| `objdiff-verified-semantic` | **6** | Byte-exact. Real proof. |
| `advisory-decompiler` | 11,865 | Decompiler output. Unproven. |
| `byte-authoritative` | 14,373 | Copied bytes. **Not source recovery.** |

Proof-ladder coverage: **0.0467%** (6 / 12,845). Rung: `below-1`.

That is the honest state. Everything below is written against it.

## 2. Why the loop is rate-limited

To make one function match under objdiff, *all* of these must be right at once:

1. Compiler identity (KOTOR is 2003 — MSVC 6.0 / 7.0 / 7.1 era)
2. Optimization flags (`/O2 /Ob1 /GF /Gy /GR /EHsc` and friends)
3. Struct layouts — every field offset the function touches
4. Calling conventions and name mangling
5. Inlining decisions the original build made
6. Source-level idiom (loop form, expression association, temporaries)

**Items 1–4 are global. Solve once, benefit all 12,845 functions.
Items 5–6 are per-function.**

The current loop spends its compute on 5–6 while 1–4 are unsettled. That is
precisely the shape that produces 0.0467%: per-function idiom search cannot
converge when the global preconditions are wrong, because a wrong struct offset
or wrong flag set makes *every* affected function unmatchable no matter how
good the source guess is. The six that did match are the ones insensitive to
all four globals — trivial leaves.

This is the single most important finding in this document. The system is not
short on cleverness per function. It is attacking the wrong layer.

## 3. The ideal architecture

Invert the investment: spend early compute almost entirely on global
preconditions, using the matches you have as an oracle. Per-function work then
converges cheaply.

### Layer A — Compiler identification by calibration (not guessing)

KOTOR statically links the MSVC CRT. **The CRT source ships with MSVC.** That
gives hundreds of functions where both the exact original source *and* the
exact shipped binary are known — a ground-truth calibration set that costs
nothing to obtain.

Procedure: for each candidate `(compiler version, flag set)` tuple, compile the
known CRT sources and objdiff them against the CRT functions located in
`swkotor.exe` (found via FLIRT/BSim). The tuple that matches the most
ground-truth pairs *is* the build configuration. This is a measurement with a
decidable answer, not a search.

Cost: a few hundred compiles. Value: unblocks items 1–2 for all 12,845
functions permanently. This is the highest-leverage single action available to
the project, and it is not currently being done.

Success signal: >80% of ground-truth CRT functions matching. Below ~50% means
the compiler guess is wrong and no per-function work should proceed.

### Layer B — Type and struct layout recovery (global, once)

A wrong field offset kills every function touching that struct. Evidence
sources, in descending authority:

- **The curated Ghidra project** — 273 composite types already defined by hand.
- **Access-pattern inference** — `[esi+0x2C]` proves a field exists at 0x2C,
  and its access width proves its size.
- **RTTI** — class names and inheritance graphs, directly readable.
- **Cross-binary corroboration** — the Mac/Xbox/sequel Odyssey builds use
  different compilers over the same logical structures. Field *identity and
  order* survive even when offsets shift; disagreement localizes the error.

The critical property: a struct definition is **checkable**, not guessable.
Compile it, take `offsetof` for every field, compare against every observed
access site. Mismatch is a hard error with a specific location. This makes
struct recovery a convergent process rather than an open search.

### Layer C — Dependency-ordered attack

Build the call graph and attack **leaves first**. Every matched leaf yields a
*verified* signature and calling convention, which becomes a hard constraint on
its callers rather than another free variable. Bottom-up ordering converts an
exponential joint search into a sequence of small local ones.

Inlined callees must be identified explicitly — if the original build inlined a
function, its caller can never match while the reconstruction still calls it
out-of-line. Detecting inlining is a precondition for attempting the caller,
not a discovery to be made 200 failed attempts later.

### Layer D — The agent loop (this is the part that matters most)

**Context assembly.** Each attempt should receive everything the project knows
about that function, not a decompiler blob:

- Curated name, plate comment, signature, parameter names *(now wired — U8/U9/U13)*
- **Both** the disassembly and the decompilation — they carry different
  information and the model needs both
- **The objdiff output of the previous attempt** — the single richest signal in
  the system
- Verified sources of all already-matched callees, so signatures are known facts
- Struct definitions the function touches
- Already-matched sibling functions from the same module, for idiom transfer
- The build configuration, stated explicitly
- Prior failed attempts *with their diffs*, so the loop cannot repeat itself

**The central principle: the loop is a conversation with the diff, not a
sequence of independent guesses.** Today's failure mode is re-rolling variants
blind. Each iteration must be strictly conditioned on the exact instruction-level
delta the last one produced.

**Turn the pass/fail gate into a gradient.** objdiff yields far more than a
boolean, and the difference *class* maps to a specific corrective action:

| Difference class | Almost always means | Correct response |
|---|---|---|
| Register allocation differs | Expression tree shape is wrong | Restructure temporaries |
| Instruction selection differs | Wrong idiom | Permute the idiom |
| Immediate offset differs | **Wrong struct layout** | **Escalate to Layer B** |
| Missing/extra instructions | Wrong control flow, or inlining | Restructure, or check inlining |
| Wholesale divergence | Wrong compiler/flags | **Escalate to Layer A** |

**Escalation is the key control-flow innovation.** A per-function failure whose
signature is *global* must escape the per-function loop and file a global work
item. The current design has no escape hatch, so a function blocked on a bad
struct offset burns unbounded compute on idiom permutations that cannot
possibly help. Every such loop is pure waste, and at 0.0467% most loops are
exactly this.

**Budget allocation by proximity.** A function at 2 differing instructions is
nearly solved and deserves the strongest model with full context. A function at
200 differing instructions is blocked on something global and deserves
escalation, not compute. Spending equally on both is the second-largest waste
in the current design.

**Cache by `(source_text, flags)` → object.** Never compile the same thing twice.

### Layer E — Readability, fully decoupled from parity

The primary objective is a readable representation of the binary **in its
entirety**. Gating readability behind byte-parity would cap it at 0.0467%
forever. So readability must be produced for all 12,845 functions regardless of
proof status, with honest per-tier labeling:

| Tier | Content | Claim |
|---|---|---|
| `verified/` | Byte-exact | Provably original semantics |
| `readable/` | Named, typed, de-Ghidra-ified, compiles | Faithful, not byte-proven |
| advisory | Best-effort | Decompiler output, cleaned |

Every function gets its curated name, signature, comment, and parameter names —
these come from the curated project, cost nothing, and cover **94.7%** of the
binary. That alone turns `sub_401b80(param_1, param_2)` into
`CServer::CreateModule(pModuleName, bLoadSave)` across essentially the whole
binary, entirely independent of parity.

## 4. Expected results

Stated as predictions with reasoning, not aspirations.

**Readability (primary objective) — achievable in its entirety:**

| Metric | Expected | Basis |
|---|---:|---|
| Functions with a real curated name | **94.7%** | 25,557 / 26,975, already measured |
| Functions with curated comments | 5,151 comments | Measured |
| Functions with curated parameter names | 1,032 | Measured (3.8% — modest, honest) |
| `undefinedN` / register-artifact identifiers remaining | **~0** | U11 rewrite is deterministic |

**Byte-parity (secondary objective) — not achievable in its entirety:**

| Stage | Expected coverage | Reasoning |
|---|---:|---|
| Today | 0.0467% | Measured |
| After Layer A (compiler ID) | 3–8% | Trivial leaves stop failing for global reasons |
| After Layer B (structs) | 15–25% | Unblocks the large mid-tier |
| After Layers C+D (ordering, real feedback loop) | **25–45%** | Mature decompilation projects land here |

**100% byte-parity is not reachable, and claiming otherwise would be dishonest.**
Some functions were built from sources whose idioms are not uniquely
recoverable; others are affected by COMDAT folding and inlining decisions that
make per-function parity ill-defined in principle. 25–45% would be an excellent
result and is comparable to well-run matching-decompilation projects.

The honest headline: **the primary goal (readable, in its entirety) is fully
achievable; the secondary goal (byte-exact source) is achievable for roughly a
third of the binary.** That aligns with the stated priority ordering.

## 4a. Hard blocker found 2026-07-31: there is no compiler

Verified on this machine:

```
/run/media/brunner56/MyBook/Toolchains/msvc8.0-main
  -> broken symbolic link to
     /run/media/brunner56/MyBook/MizuchiSource/toolchains/msvc8.0-main   (does not exist)
```

A `find` for `cl.exe` across the entire workspace drive returns nothing. `wine`
is installed; the MSVC toolchain it used to run is gone.

Consequences, stated plainly:

- **The objdiff parity gate cannot execute at all.** Every compile attempt fails
  before it reaches objdiff.
- **Restarting the parity pipeline in this state would produce exactly zero new
  verified functions**, at full compute cost. Not "few" — zero, deterministically.
- **Layer A (CRT calibration) is itself blocked**, because calibration is
  fundamentally a compile-and-compare procedure.
- The 6 existing verified functions date from a session when the toolchain was
  mounted; they are not reproducible today.

This reorders the gap analysis: acquiring an MSVC toolchain is item **#0**, a
hard prerequisite for every parity-related item below. Nothing in Layers A–D can
be built, tested, or measured without it.

The readability track (Layer E, the *primary* objective) needs no compiler and
is unaffected.

## 5. Gap analysis — what to build, in order

| # | Work | Layer | Status |
|---|---|---|---|
| 0 | **Acquire an MSVC toolchain** | — | **BLOCKER. Nothing parity-related runs without it.** |
| 1 | CRT calibration harness → identify compiler + flags | A | Not built. Highest leverage *once #0 lands*. |
| 2 | Struct-layout validator (`offsetof` vs access sites) | B | Not built |
| 3 | Escalation path: per-function failure → global work item | D | **Not built. Largest waste today.** |
| 4 | objdiff difference *classifier* (gradient, not boolean) | D | Not built |
| 5 | Call-graph leaf-first ordering + inlining detection | C | Not built |
| 6 | Context assembly with prior diffs and matched callees | D | Partial |
| 7 | Budget allocation by proximity-to-match | D | Not built |
| 8 | Curated naming/params/comments wired into emission | E | **Done** (U8/U9/U13) |
| 9 | De-Ghidra-ification into a `readable/` tier | E | **Done** (U11/U13) |
| 10 | objdiff re-verification proving byte-neutrality (V2) | E | Blocked: no toolchain |

Items 1 and 3 together are the difference between 0.0467% and double-digit
coverage. Nothing in the per-function loop matters until they exist.

## 6. Scope boundaries

- objdiff-zero remains the sole parity gate. Readability never relaxes it.
- The user's Ghidra project is read-only, always.
- `readable/` is never claimed as byte-proven.
- Coverage numbers are reported as measured, never extrapolated.

## 7. Trailing suffixes in curated names: an upstream data defect, not a reader bug

*(found 2026-07-31; root-caused 2026-08-05, initial diagnosis was wrong)*

213 of 24,060 curated names read from the K1 database (`k1_win_gog_swkotor.exe.gzf`)
carry a trailing run of `控制` after an otherwise-valid ASCII name, e.g.
`CSWSVirtualMachineCommands::ExecuteCommandActionCloseDoor`.

This was **initially recorded here as a `.gbf` string-reader defect**, on the
reasoning that a single repeating 6-byte constant (`e6 8e a7 e5 88 b6`) looks like
a length prefix read too long, with the surplus coming from a pattern-filled
region. Byte-level inspection of the raw `Symbols` records disproves that:

- For all 213 affected names, the record's declared string length **exactly equals**
  the UTF-8 byte length of the decoded name. Zero mismatches. The longest declares
  417 bytes and decodes to 417.
- An over-read is definitionally a case where the decoded value extends past what
  the record header accounts for. That never happens here, so no over-read occurs.
- The raw record parses cleanly on either side of the name: the `Address` field
  immediately follows the declared payload at the expected offset.

The suffix is therefore genuinely stored in the curated Ghidra project. The
repetition histogram identifies the upstream mechanism: 98 names carry one copy of
the suffix, 44 carry two, 16 three, tailing to a handful with 60+. That is a
rename script that appends a marker, run repeatedly over the same symbols.

The reader is correct and needs no change. Because C identifiers are ASCII, the
trailing run carries no meaning, so `source_dump.sanitize_curated_name` strips it
and **recovers the ASCII prefix** — turning 213 discarded symbols into 213 usable
curated names. Interior non-ASCII is deliberately left alone and still refused by
`is_usable_curated_name`: that shape has not been characterised, and guessing at it
would risk inventing a name rather than recovering one.

The emit-layer bounds (`safe_file_stem`) remain, since path-length safety should
not depend on the name source being well-behaved.
