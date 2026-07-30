# Agent-loop context engineering for matching recovery

- Date: 2026-07-30
- Status: design
- Target: `swkotor.exe` whole-binary readable C/C++ reconstruction
- Related: [2026-07-29-001-feat-llm-candidate-rewriting-plan.md](2026-07-29-001-feat-llm-candidate-rewriting-plan.md), [2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md](2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md)

## Why now

The recovery pipeline is parked below the 1% rung on its own ladder and is not
moving. The stage responsible for actually reconstructing C — challenger-lane
mechanism 3 — has never run on the primary swkotor work dir.

## Measured baseline

| Signal | Value | Source |
|---|---|---|
| Inventoried functions | 8,621 (facts-local); ~12,845 queued | `target/swkotor-ghidra-facts-local.jsonl` |
| Ladder rung | `below-1`, 129 functions short of 1% | `swkotor-parity/state/proof-campaign.json` |
| Last campaign | attempted 5, accepts 0, near-misses 0 | same, `writtenAt 2026-07-30T01:34:16Z` |
| Rewrite queue (primary work dir) | file absent — mechanism 3 never fired | `swkotor-parity/state/` |
| Rewrite queue (inv work dir) | 1 entry, 1 completed, ever | `swkotor-parity-inv/state/rewrite-queue.json` |

## Findings

### F1 — Mechanism 3 is off by default (P0)

`autonomy_budget.py:21` sets `DEFAULT_MAX_REWRITE_REQUESTS_PER_FUNCTION = 0`.
`autonomous_policy.choose_next_action` reaches `try-rewrite-request` only when
`rewrite_remaining > 0`, so a default campaign can never take that branch. Every
run silently degrades to mechanisms 1+2 — deterministic search over compiler
flags and idiom permutations — and reports `accepts: 0` without ever indicating
that the reconstruction stage was skipped.

### F2 — The loop is open (P0)

`rewrite_queue.py` writes a pending request and returns. Fulfillment requires a
human to have separately launched a Claude Code session running `/loop` against
the `agentdecompile-rewrite-worker` skill. If that session is not running,
requests persist indefinitely with no timeout, no alert, and no fallback. The
result, once written, is consumed only by *a later, separate* `--autonomous`
invocation. End-to-end latency for one rewrite is therefore unbounded and gated
on two manual human actions.

### F3 — The prompt omits the target (P0)

The queue entry carries `functionName`, `entry`, `candidateSource`,
`mismatchClass`, and `mismatchHistogram`. `SKILL.md` states plainly: *"the queue
does not carry a separate raw byte slice."*

The subagent is asked to produce C that assembles to specific machine code,
while being shown neither that machine code nor which instructions currently
differ. `mismatchHistogram` supplies only a count per difference kind
(`{'REPLACEMENT': 2}`). This is the single largest defect in the loop: the task
as posed is not reliably solvable, and no amount of retry budget fixes it.

### F4 — Pattern memory cannot compound (P1)

`pattern_memory.store_verified_pattern` computes a signature over
`(compiler, arch, mismatch_class, fix_shape)`, then drops every existing row
sharing that signature before appending. Across 12,845 functions the signature
space is on the order of a dozen values, so the store holds roughly one row per
class; the `patterns[-500:]` cap never engages. Each new accept erases the prior
exemplar for its class.

Worse, a stored row contains only labels — `functionName`, `entry`,
`mismatchClass`, `fixShape`. It records no before/after source. Even if
retrieval returned every row, there would be nothing transferable in them.
`near_miss_repair.py` calls `retrieve_patterns` and uses the result solely to
report `patternHintCount` in a receipt. No pattern content reaches any prompt.

### F5 — The rewrite lane produces inline assembly (P1)

The only completed mechanism-3 result in the repo:

```c
void FUN_004a23b0(void) {
  __asm { inc dword ptr [DAT_00830540] }
  return;
}
```

This passes objdiff and advances the ladder while directly defeating the stated
deliverable of readable C. The mechanism-3 prompt forbids `#pragma`, `#include`,
and linker directives, but not `__asm`. `readability_repair.py` operates on a
facts-derived queue and does not gate this path.

Inline asm is the local optimum of "minimize objdiff subject to no stated
constraint." The loop found it immediately. It will find it every time.

### F6 — `mismatchHistogram` is stored as a Python repr (P2)

The live entry holds the string `"{'REPLACEMENT': 2}"` — single-quoted Python
`repr` output, not JSON. Any consumer parsing it as JSON fails.

### F7 — `source_parity_synthesize.py` is 23,118 lines (P2)

A single module holding candidate generation, rule generators, symbol inference,
and shim construction. Recent history shows repeated defects localized here
(stdcall decoration, `packaged_stack_bytes` regex, `build_shim` pointer types).
Size is a direct contributor: the file cannot be held in context, so changes are
made against a partial view.

### F8 — Work dir is on a rotational USB disk (P2)

`work_dir_diagnostics.py` warns about exactly this, and the active configuration
trips it. Compile+objdiff is I/O-bound per candidate; this is a throughput
ceiling on every mechanism.

## Design

### Principle

Give the model what a human matching-decomp engineer would have on screen, close
the loop so it sees the consequence of each edit, and constrain the output space
so the readable solution is the only accepted one.

### D1 — Context pack

Replace the five-field queue entry with a structured pack assembled at request
time:

| Field | Purpose | Source |
|---|---|---|
| `targetDisassembly` | The instructions to match | target slice, already in the source task |
| `alignedDiff` | Which instructions differ, side by side | objdiff output, currently reduced to a histogram |
| `candidateSource` | Current C | unchanged |
| `compilerProfile` | Exact flags and toolchain | run config |
| `calleeProtos` | Prototypes and conventions for called symbols | `infer_packaged_symbol` |
| `dataRefs` | Types of referenced globals | facts |
| `priorAttempts` | Previous rewrites for this function and their diffs | new, per-function episodic log |
| `exemplars` | Verified before/after pairs for this mismatch class | rebuilt pattern memory (D4) |

`alignedDiff` is the highest-value single field. The histogram is a lossy
projection of data the pipeline already computes and discards.

### D2 — Closed inner loop

Iterate inside one fulfillment: rewrite → compile → objdiff → append the new
aligned diff to `priorAttempts` → rewrite again. Stop on diff 0, on budget
exhaustion, or on two consecutive iterations with no diff reduction.

This changes rewriting from a blind single shot into hill-climbing with a
measured objective. It is the difference between guessing and searching.

### D3 — In-process fulfillment via headless CLI

The campaign invokes `claude -p` as its rewrite provider. No credentialed API
client, no second human session, no dead drop. The file-queue path is retained
for operators who want a human in the lane, but is no longer the only route.

The repo premise moves from *"never calls an LLM directly"* to *"never calls a
credentialed LLM API directly; fulfillment runs through the local Claude Code
CLI."* This must be restated in `SKILL.md` and the plan docs rather than left
implicit.

### D4 — Pattern memory that compounds

- Key on a discriminative signature, not a four-value tuple: include the
  normalized source shape and the diff signature.
- Store `sourceBefore` and `sourceAfter` — the actual transformation.
- Append rather than replace within a signature; cap per signature, not globally.
- Inject the top-k retrieved exemplars into the context pack.

This is what makes function 500 cheaper than function 5.

### D5 — Readability as an acceptance constraint

- Forbid `__asm`, `__declspec(naked)`, and intrinsic-only bodies in the
  mechanism-3 prompt, explicitly and with a stated reason.
- Add a content check on the fulfillment path that rejects them, mirroring the
  existing `#pragma`/`#include` check.
- Route accepted candidates through the readability score before promotion to
  `verified/`; a byte-matching but unreadable candidate is `advisory/`, not
  `verified/`.

Honesty gate unchanged: objdiff 0 remains necessary. Readability becomes
additionally necessary for `verified/`.

### D6 — Equivalence-class batching

Cluster near-miss targets by `(mismatchClass, diff signature, source shape)`.
Solve one representative per cluster; attempt the accepted transformation across
the whole cluster before requesting another rewrite.

The repo's own history validates this: a single stdcall-decoration fix unblocked
37 functions simultaneously. Per-function grinding rediscovers shared root
causes once per function.

## Expected results

Mechanisms 1+2 already deposit candidates in the ≤8-difference near-miss band;
`NEAR_MISS_MAX_DIFF = 8`. Those are the reachable population. D1 and D2 target
conversion within that band; D6 multiplies each conversion across its cluster.

Near-term objective is the 1% rung — 129 functions — with readable C, not inline
asm. 5% is the stretch objective. Whole-binary parity remains out of scope as a
claim, per `STRATEGY.md`.

## Non-goals

- Relaxing the objdiff-zero gate.
- Claiming whole-binary semantic parity.
- Promoting inline-asm or byte-emitting candidates to `verified/`.
- Rewriting `source_parity_synthesize.py` wholesale; F7 is recorded, not
  scheduled here.

## Sequencing

| Unit | Change | Findings |
|---|---|---|
| U1 | Aligned diff + target disassembly into the context pack | F3 |
| U2 | Readability constraint: prompt, content check, promotion gate | F5 |
| U3 | Headless CLI fulfillment provider | F2 |
| U4 | Closed inner loop with diff feedback | F2 |
| U5 | Pattern memory rebuild and prompt injection | F4 |
| U6 | Enable the rewrite budget by default | F1 |
| U7 | Equivalence-class batching | F6 covered incidentally |

U6 lands after U1–U5 deliberately: enabling the budget before the prompt carries
the target would only spend budget on the unsolvable formulation.
