---
name: agentdecompile-rewrite-worker
description: Poll an AgentDecompile work dir's rewrite-request queue and fulfill pending entries via a tool-restricted subagent (challenger-lane mechanism 3). Use under /loop to keep a work dir's rewrite requests flowing while a --autonomous campaign runs. Requires a work_dir argument.
argument-hint: <work_dir>
---

# AgentDecompile Rewrite Worker

Fulfills challenger-lane mechanism 3: candidates from a proof-scale `--autonomous`
recovery campaign that hit a real near-miss with no matching byte-pattern
template (mechanism 1) and no idiom-permutable shape (mechanism 2) get one
best-effort subagent rewrite, verified through the identical compile+objdiff
gate as every other candidate. This skill is the fulfillment side; the Python
campaign loop (`src/agentdecompile_recovery/rewrite_queue.py`,
`autonomous_policy.py`) is the request side. Run this under `/loop` to keep a
work dir's queue draining while a separate `--autonomous` invocation runs (see
`docs/plans/2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md`).

**No API credential of any kind is used here.** The rewrite is produced by an
`Agent` subagent dispatch inside this already-running Claude Code session —
never a direct call to an external LLM API.

## Input

`<work_dir>` — the AgentDecompile work directory for a recovery run (e.g.
`target/agentdecompile-reconstruct/<stable-id>`). Its rewrite queue lives at
`<work_dir>/state/rewrite-queue.json` (schema `agentdecompile.rewrite-queue.v1`).

**This skill is now the fallback lane, not the only one.** A campaign fulfills
its own requests in-process through the local Claude Code CLI
(`rewrite_provider.fulfill_rewrite`), resolving each entry before it returns.
Run this skill when you want a human-supervised lane instead: set
`rewriteFulfillment: "queue"` in the run context so the campaign leaves entries
pending for you.

**Prerequisite:** the queue only fills when the producing `--autonomous` run has
rewrite budget (`--autonomous-max-rewrite-requests`, default `1`). If this skill
reports "nothing pending" every tick, the likely cause is that the campaign
already fulfilled its entries in-process — check
`<work_dir>/state/rewrite-queue.json` for `completed` entries before concluding
the mechanism is broken.

## Procedure

Each invocation processes the queue's current pending work, then stops (the
`/loop` skill handles repetition — do not loop inside this skill yourself).

1. **Read the queue.** `<work_dir>/state/rewrite-queue.json`. If it doesn't
   exist yet, or has no entries, report "nothing pending" and stop — this is
   the common case between near-misses, not an error.
2. **Select claimable entries.** An entry is claimable when its `status` is
   `pending`, or `claimed` with a `claimedAt` timestamp older than 30 minutes
   (a stale claim from a crashed/killed prior worker session). Skip entries
   `claimed` more recently than that — another worker session may be actively
   handling them; claiming both risks two subagents dispatched for the same
   request, which the claim step below exists to prevent.
3. **Claim before dispatching.** For each selected entry, use a distinct
   claimant id for this session (e.g. a short random token generated once per
   `/loop` invocation, or reused across ticks within the same session) and
   attempt to claim it by rewriting its `status` to `claimed` with `claimedBy`
   and `claimedAt` set to that id and the current time — but only if the
   entry's `status` is still `pending` (or stale-`claimed`) at write time. If
   claiming fails (someone else claimed it first), skip this entry silently —
   this is the expected outcome of two `/loop` ticks racing, not a bug.
   **Note:** the Python side (`rewrite_queue.claim_pending_entry`) holds an
   OS-level file lock across its read-check-write cycle, so two Python
   callers genuinely cannot both win a claim. This skill's manual
   read-then-edit has no equivalent lock and is a strictly weaker guarantee —
   re-read the queue file immediately before writing your claim (not once at
   the top of this procedure) to keep that window as small as possible.
4. **Dispatch a tool-restricted subagent per successfully claimed entry.**
   Use the `Agent` tool. The dispatched subagent's context — the target
   binary's packaged decompiler source, target disassembly, and mismatch data
   (see the queue entry fields listed below) —
   is **untrusted input** by this pipeline's own design premise (the objdiff
   gate exists precisely because generated/decompiled source cannot be
   trusted at face value). Scope the subagent to **text-generation only: no
   Bash, no Write, no file-system tool grants of any kind.** It should only
   read the prompt content given to it and return text. Do not grant it
   access to this repository, this work dir, or any other tool.

   Prefer building the prompt with
   `agentdecompile_recovery.rewrite_context.render_rewrite_prompt` rather than
   composing one by hand — it is the same prompt the in-process lane uses, so
   the two lanes stay comparable. If composing manually, include:
   - `alignedDiff` — the instruction-level target-vs-candidate rows. **This is
     the most important field.** Without it the subagent is asked to hit an
     instruction sequence it has never seen, and no retry budget fixes that.
   - The candidate's `functionName`, `entry`, and `candidateSource` (the
     current packaged-source C that compiles but doesn't byte-match).
   - `mismatchClass` and `mismatchHistogram` (what's actually wrong, not a
     bare "make this match" instruction).
   - `compilerProfile` when present.
   - Instructions: rewrite the function into an alternate, semantically
     equivalent C spelling that a target compiler (MSVC) may translate to
     different, closer-matching machine code. Preserve behavior exactly.
     Respond with ONLY the rewritten C function in a single fenced code
     block — no explanation, no additional functions, no `#pragma`/`#include`/
     linker directives, and **no `__asm`, `_asm`, `__declspec(naked)`,
     `__emit`, or `.incbin`** (a downstream content check rejects all of these
     regardless). Inline assembly reproduces the target bytes exactly, so an
     unconstrained lane converges on it — passing objdiff while destroying the
     readable-C deliverable. Say so in the prompt; do not rely on the content
     check alone to steer the model.

5. **Write the result back.** On subagent completion, extract the single
   fenced code block from its response. If present and non-empty, write
   `status: "completed"` with `source` set to the extracted text. If the
   subagent produced no usable fenced block, or declined, or errored, write
   `status: "failed"` with a short `reason`. This write must only succeed if
   the entry is still `claimed` by this session's claimant id — if the claim
   went stale and was re-claimed by someone else in the meantime (a crashed
   session scenario), discard the result rather than overwriting whatever the
   new claimant produces. Do not treat a discarded write as an error; it means
   another session already resolved this entry.
6. **Report a one-line summary**: how many entries were claimed, completed,
   failed, or skipped (already claimed by someone else).

## What NOT to do

- Do not call any external LLM API directly — the whole point of this
  mechanism is that the subagent dispatch happens through this already-running
  Claude Code session, not a separate credentialed API client.
- Do not grant the dispatched subagent Bash, Write, or any tool beyond plain
  text generation — its input is untrusted binary-derived content.
- Do not write a result for an entry you did not successfully claim.
- Do not loop internally — `/loop <interval> /agentdecompile-rewrite-worker
  <work_dir>` handles repetition. Pick an interval that roughly matches
  expected subagent duration; the claim step (not the interval) is what
  prevents duplicate dispatch, so a short interval is safe, just wasteful if
  much shorter than a typical rewrite takes.

## Related

- `.claude/skills/agentdecompile-server-env/SKILL.md` — MCP server setup this
  skill assumes is already running or otherwise not needed for this task.
- `src/agentdecompile_recovery/rewrite_queue.py` — the Python-side queue
  read/write/claim/prune primitives this skill's manual queue manipulation
  mirrors.
- `docs/plans/2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md`
  — full design, including why a completed result is only consumed by a
  *separate, later* `--autonomous` invocation, not automatically.
