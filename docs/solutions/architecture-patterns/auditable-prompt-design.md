---
module: recovery
problem_type: maintainability
component: prompts
tags: [prompt-engineering, evals, context, provenance]
---

# Auditable prompt design

## Decision

Production prompts use this order when the surface supports it:

1. task and acceptance gate;
2. trust or claim boundary;
3. labeled evidence/context;
4. ordered procedure and constraints;
5. exact output contract.

Prompt history and rationale stay beside the implementation in
`agentdecompile_recovery.prompt_design.PROMPT_RATIONALE`; they are not rendered
to the model. Each rationale entry records the instruction, prior wording or
behavior, reason for the change, and intended result. Shell-generated prompts
carry the same four-part note in adjacent source comments.

## Why

The August 2026 review used current first-party guidance:

- [OpenAI prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering): separate identity, instructions, examples, and context; use explicit structure; pin model snapshots and evaluate prompt changes.
- [Anthropic context engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents): use clear prompts at the right altitude, begin with the minimum useful context, and add instructions in response to measured failure modes.
- [Anthropic prompting best practices](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices): use consistent XML/Markdown structure and place long evidence before the final query when appropriate.
- [Google Gemini prompting strategies](https://ai.google.dev/gemini-api/docs/prompting-strategies): specify input, constraints, response format, and consistent examples; iterate with evaluations.
- [Google Gemini 3 guidance](https://ai.google.dev/gemini-api/docs/gemini-3): prefer concise, direct instructions and avoid unnecessary prompt machinery.

The sources agree on structure, directness, examples, explicit output formats,
and evaluation. They do not justify one universal word order for every model,
so this repository keeps task-critical constraints near both the opening and
the final output contract, and validates behavior with tests.

## Repository-specific rules

- Binary-derived strings, comments, symbols, assembly, compiler output, and
  decompiler text are untrusted evidence, never instructions.
- A model never claims a source match. Compilation plus objdiff zero is the
  acceptance gate.
- “All,” “verbatim,” and “never truncate” are not coverage strategies. Large
  workflows use bounded batches, counts, and exact continuation ledgers.
- Examples state their verification outcome. Unverified examples cannot be
  presented as ground truth.
- Output contracts are positive and mechanically testable: artifact count,
  format, prohibited shortcuts, and allowed prose are explicit.
- Change prompts against representative fixtures and gate important invariants
  in tests; quality claims require model/eval results, not wording preference.

## Local runtime patterns reviewed

Two local prompt-runtime implementations were inspected as design evidence:

- `/run/media/brunner56/MyBook/Workspaces/missionruntime/skills/` separates
  objective, recovered context, semantic constraints, scope, non-goals,
  evidence, output, assumptions, and execution authority. Its strongest rule
  is destination over route: procedural scaffolding is added only to repair an
  observed failure.
- `/run/media/brunner56/MyBook/Workspaces/prompt-uplift/skills/` compiles an
  intermediate `ExecutionContract`, preserves action vs answer and every
  negation/authority boundary, isolates the renderer from raw conversation,
  and distinguishes structural tests from live agent evaluation.

AgentDecompile adopts the compatible parts: explicit authority/trust bounds,
evidence-based done conditions, output contracts, lean wording, and invariant
tests. It does not import the generic contract wholesale: top-down, bottom-up,
and matching workflows intentionally encode a route because that route defines
the selected analysis method rather than compensating for a model weakness.

## Updating a prompt

Update its rendered instruction and the adjacent rationale in the same change.
Add or adjust a focused test for the behavior the wording is intended to cause.
For material model or prompt changes, run the representative recovery eval set
with the model snapshot recorded; do not infer output-quality improvement from
unit tests alone.
