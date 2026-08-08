---
title: File-queue handoff for subagent-fulfilled asynchronous work
date: 2026-07-30
category: architecture-patterns
module: agentdecompile_recovery
problem_type: architecture_pattern
component: tooling
severity: medium
applies_when:
  - "A headless Python loop needs work done by an LLM but must not hold its own API credential"
  - "The work naturally spans two separate processes: a bounded synchronous producer and an out-of-process, potentially slow consumer (a live agent session)"
  - "Two or more processes (e.g. a campaign loop and a /loop-driven worker session) may read/write the same coordination file concurrently"
tags:
  - rewrite-queue
  - subagent
  - file-queue
  - concurrency
  - claude-code-loop
  - fcntl
---

# File-queue handoff for subagent-fulfilled asynchronous work

## Context

Challenger-lane mechanism 3 (LLM-based candidate rewriting) originally called
the Anthropic API directly from the Python `--autonomous` recovery loop,
requiring its own `ANTHROPIC_API_KEY` independent of whatever agent session
launched the tool. This was replaced with a file-queue handoff: the Python
loop writes a typed pending request and stops (non-blocking); a separate,
live Claude Code session running `/loop` claims and fulfills requests via an
`Agent` subagent dispatch, with no API credential anywhere in the Python
code. See `docs/plans/2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md`
for the full origin design and `src/agentdecompile_recovery/rewrite_queue.py`
for the implementation.

The first version of this pattern shipped without real cross-process locking
— its mutating functions did read-check-write with no lock, described in
comments as "compare-and-swap" but not actually one. Code review (8 parallel
reviewer personas) converged independently on this from three angles
(correctness, adversarial, maintainability): two processes could both read a
`pending` entry and both successfully claim it, or two processes writing
different entries in the same file could silently drop each other's writes.
A second, related bug: the per-function request budget was derived by
scanning *currently live* queue entries, so pruning a resolved entry (which
happens by design once a campaign pass consumes it) silently reset the
budget to full.

## Guidance

**Lifecycle:** model the queue as an explicit state machine with a real
"claimed" state, not just "pending" and "done" — `pending -> claimed ->
completed | failed`, with a claim timestamp and a staleness TTL so a crashed
worker's claim gets re-offered rather than stalling the entry forever.

**Locking:** every mutating function must hold an exclusive, *blocking*
file lock spanning its entire read -> verify-expected-state -> write cycle,
not just the final write:

```python
@contextmanager
def _locked(work_dir: Path) -> Iterator[None]:
    lock_path = work_dir / "state" / "rewrite-queue.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
```

A separate lock file (not the data file itself) avoids interfering with
`atomic_write_json`'s own tmp-write-then-rename. Use a *blocking* lock
(`LOCK_EX`, not `LOCK_EX | LOCK_NB`) so a losing writer waits and then
re-reads fresh state, rather than failing outright — a try-lock forces every
caller to implement its own retry loop for what should be routine contention.

**Durable budget accounting:** if a caller enforces "at most N requests per
function," and entries get pruned after being consumed, track the count in a
field that is *only ever incremented*, separate from the live entry map —
never derive remaining budget by counting what currently exists in the
queue:

```python
queue["requestCounts"][function_name] = (
    queue["requestCounts"].get(function_name, 0) + 1
)
```

**Shared write primitive:** if multiple independent files/modules write to
the same coordination file concurrently (this pattern's producer and
consumer are separate processes, but a shared low-level `atomic_write_json`
helper is common across a codebase), give every writer a unique intermediate
filename (`pid + random suffix`), not one fixed `.tmp` name — concurrent
writers sharing one intermediate file can have one writer's in-progress
`.tmp` replaced out from under it.

**Fulfillment-subagent model tier:** the dispatched `Agent` subagent that
actually produces the rewrite (`.claude/skills/agentdecompile-rewrite-worker/SKILL.md`
step 4) must always be dispatched on a small/cheap model (Haiku), regardless
of what model the orchestrating `/loop` session itself is running. The task
is a single bounded text transformation (rewrite one already-compiling
function into an alternate spelling) with no benefit from a larger model, and
a real campaign can trigger this dispatch many times — the cost/latency
difference compounds. This is easy to get wrong specifically because it is
tempting to have the subagent "inherit" the parent's model; don't.

## Why This Matters

A queue described as "compare-and-swap" that is actually a bare
read-then-write is a correctness bug waiting for the exact concurrency
scenario the design exists to handle — in this case, a `/loop`-driven worker
polling faster than a subagent's turnaround time, which is the expected
steady state, not an edge case. Sequential-call tests (single process, calls
made one after another) do not catch this class of bug; only real
multi-process tests do.

## When to Apply

- Any time a Python (or other headless) process needs to hand work to an
  out-of-process LLM/agent session rather than holding its own API
  credential.
- Any shared JSON/state file two or more independently-scheduled processes
  might read-modify-write concurrently.
- Any budget/rate-limit counter derived from a collection that items get
  removed from after being consumed.

## Examples

`src/agentdecompile_recovery/rewrite_queue.py` — full reference
implementation: `_locked()` context manager, `claim_pending_entry()` (claim
compare-and-swap), `write_claimed_result()` (discards a write if the claim
no longer matches the caller), `count_requests_for_function()` (durable
counter, not a live scan). `.claude/skills/agentdecompile-rewrite-worker/SKILL.md`
is the consumer side — note its explicit caveat that the *skill's* manual
JSON read/edit is a strictly weaker guarantee than the Python-side lock,
since there is no CLI/MCP entry point yet for the skill to shell out to the
locked primitive directly (a documented gap, not a fixed one).

Real regression coverage using actual separate OS processes (not just
sequential same-process calls) lives in `tests/test_rewrite_queue.py`:
`test_concurrent_claims_from_separate_processes_only_one_wins` and
`test_write_rewrite_request_survives_concurrent_writes_to_different_entries`
use `multiprocessing.Process` to prove the lock actually serializes
concurrent writers.

## Related

- `docs/plans/2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md`
  — origin design and the code-review findings that drove this pattern.
- `src/agentdecompile_recovery/autonomy_budget.py`'s `ensure_vacuum_queue()`
  — the closest prior async-handoff precedent in this codebase (a
  Python-writes/external-process-consumes queue), which this pattern
  deliberately diverges from by adding real locking and a claim state that
  precedent didn't need.
