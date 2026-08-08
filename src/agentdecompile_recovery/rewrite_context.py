"""Context-pack assembly and prompt rendering for challenger-lane mechanism 3.

Mechanism 3 is the only stage that reconstructs C rather than searching a fixed
space of compiler flags and idiom permutations. Two properties decide whether it
works at all:

1. **The prompt must carry the target.** A rewrite request that reports only
   "2 replacements" asks the model to hit an instruction sequence it has never
   seen. `objdiff_verification.extract_aligned_diff` recovers that sequence from
   data the pipeline already computes; this module puts it in front of the model.

2. **The output space must exclude the cheat.** `__asm` reproduces any target
   exactly and passes objdiff, so an unconstrained loop converges on it
   immediately -- satisfying the proof gate while destroying the readable-C
   deliverable. Inline assembly is therefore banned in the prompt *and* rejected
   by `check_rewrite_content`, because a prompt rule alone is not a gate.
"""

from __future__ import annotations

import re
from typing import Any

from .rewrite_queue import coerce_histogram

SCHEMA = "agentdecompile.rewrite-context-pack.v1"
CLAIM_BOUNDARY = (
    "a rewrite context pack is advisory input only; compile + objdiff zero "
    "remains the sole acceptance gate for any candidate it produces"
)

BANNED_CONSTRUCT_REASON = (
    "candidate uses a banned construct (inline assembly, naked function, byte "
    "emission, or a preprocessor/linker directive); the deliverable is readable C"
)

# Word-boundary anchored so ordinary identifiers that merely contain these
# letters (plasmaCount, disassembler) are not mistaken for inline assembly.
_BANNED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b__asm\b", "__asm"),
    (r"\b_asm\b", "_asm"),
    (r"\basm\s*\(", "asm("),
    (r"__declspec\s*\(\s*naked", "__declspec(naked)"),
    (r"\b__emit\b", "__emit"),
    (r"\.incbin\b", ".incbin"),
    (r"(?m)^\s*#\s*include\b", "#include"),
    (r"(?m)^\s*#\s*pragma\b", "#pragma"),
)

_FENCE_RE = re.compile(r"```[ \t]*[A-Za-z0-9+#_-]*[ \t]*\r?\n(.*?)```", re.DOTALL)


def build_context_pack(
    *,
    function_name: str,
    entry: str,
    candidate_source: str,
    aligned_diff: list[dict[str, Any]] | None = None,
    mismatch_class: str | None = None,
    mismatch_histogram: dict[str, int] | None = None,
    compiler_profile: str | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    exemplars: list[dict[str, Any]] | None = None,
    codebase_exemplars: list[dict[str, Any]] | None = None,
    callee_protos: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble everything a rewrite needs into one serializable payload."""

    return {
        "schema": SCHEMA,
        "functionName": function_name,
        "entry": entry,
        "candidateSource": candidate_source,
        "alignedDiff": list(aligned_diff or []),
        "mismatchClass": mismatch_class,
        "mismatchHistogram": coerce_histogram(mismatch_histogram),
        "compilerProfile": compiler_profile,
        "priorAttempts": list(prior_attempts or []),
        "exemplars": list(exemplars or []),
        # Structural neighbours from decomp-function-index.json (near-miss /
        # verified C), distinct from pattern_memory mismatch-class exemplars.
        "codebaseExemplars": list(codebase_exemplars or []),
        "calleeProtos": list(callee_protos or []),
        "claimBoundary": CLAIM_BOUNDARY,
    }


def _render_aligned(rows: list[dict[str, Any]]) -> str:
    from .objdiff_verification import render_aligned_diff

    return render_aligned_diff(rows)


def render_rewrite_prompt(pack: dict[str, Any]) -> str:
    """Render a context pack into the mechanism-3 rewrite prompt."""

    sections: list[str] = []
    name = pack.get("functionName") or "the function"
    compiler = pack.get("compilerProfile") or "the target compiler (MSVC, 32-bit x86)"

    sections.append(
        "You are doing matching decompilation on a 32-bit x86 PE binary.\n\n"
        f"Rewrite `{name}` so that {compiler} compiles it to the target "
        "instruction sequence below. Observable behavior must stay identical."
    )

    rows = pack.get("alignedDiff") or []
    if rows:
        sections.append(
            "## Target vs your current candidate\n\n"
            "Left column is the target; right column is what the current source "
            "compiles to. `!` marks an instruction that differs.\n\n"
            f"```\n{_render_aligned(rows)}\n```"
        )

    if pack.get("candidateSource"):
        sections.append(f"## Current source\n\n```c\n{pack['candidateSource'].rstrip()}\n```")

    mismatch_bits: list[str] = []
    if pack.get("mismatchClass"):
        mismatch_bits.append(f"class: {pack['mismatchClass']}")
    histogram = pack.get("mismatchHistogram") or {}
    if histogram:
        counts = ", ".join(f"{key}={value}" for key, value in sorted(histogram.items()))
        mismatch_bits.append(f"counts: {counts}")
    if mismatch_bits:
        sections.append("## Mismatch\n\n" + "\n".join(f"- {bit}" for bit in mismatch_bits))

    protos = pack.get("calleeProtos") or []
    if protos:
        sections.append("## Callee prototypes\n\n```c\n" + "\n".join(protos) + "\n```")

    attempts = pack.get("priorAttempts") or []
    if attempts:
        lines = []
        for attempt in attempts:
            differences = attempt.get("differences")
            source = str(attempt.get("source") or "").strip()
            lines.append(f"- {differences} difference(s):\n```c\n{source}\n```")
        sections.append(
            "## Previous attempts\n\nThese were already tried and did not match. "
            "Do not repeat them.\n\n" + "\n".join(lines)
        )

    exemplars = pack.get("exemplars") or []
    if exemplars:
        lines = []
        for exemplar in exemplars:
            before = str(exemplar.get("sourceBefore") or "").strip()
            after = str(exemplar.get("sourceAfter") or "").strip()
            if not before and not after:
                continue
            lines.append(f"- `{before}` -> `{after}`")
        if lines:
            sections.append(
                "## Verified transformations for this mismatch class\n\n"
                "These shape changes produced byte-exact matches on other "
                "functions.\n\n" + "\n".join(lines)
            )

    codebase_exemplars = pack.get("codebaseExemplars") or []
    if codebase_exemplars:
        lines = []
        for sample in codebase_exemplars:
            name = str(sample.get("name") or "neighbour").strip()
            c_code = str(sample.get("cCode") or "").strip()
            if not c_code:
                continue
            match_pct = sample.get("matchPercent")
            match_note = (
                f" ({float(match_pct):.1f}% match)"
                if isinstance(match_pct, (int, float))
                else ""
            )
            lines.append(f"### `{name}`{match_note}\n\n```c\n{c_code}\n```")
        if lines:
            sections.append(
                "## Worked examples from similar functions\n\n"
                "These are structurally similar functions from the indexed "
                "corpus. Prefer their source *shape* when it fits; do not copy "
                "identifiers that belong to another function.\n\n" + "\n\n".join(lines)
            )

    sections.append(
        "## Rules\n\n"
        "- Preserve behavior exactly.\n"
        "- Change the source *shape* -- expression form, operator choice, "
        "temporaries, control-flow spelling, evaluation order -- so the compiler "
        "selects different encodings. That is the only lever you have.\n"
        "- Write plain, readable C. Do NOT use `__asm`, `_asm`, "
        "`__declspec(naked)`, `__emit`, `.incbin`, `#pragma`, `#include`, or "
        "linker directives. Inline assembly reproduces the target bytes exactly "
        "and would pass the byte gate while defeating the deliverable, which is "
        "readable source. A content check rejects these regardless.\n"
        "- Emit one function only -- no helpers, no declarations.\n"
        "- Respond with ONLY the rewritten function in a single fenced code "
        "block. No explanation."
    )

    return "\n\n".join(sections)


def check_rewrite_content(source: str) -> str | None:
    """Reject a rewrite result. Returns a reason, or None when acceptable."""

    if not source or not source.strip():
        return "candidate is empty"
    for pattern, label in _BANNED_PATTERNS:
        if re.search(pattern, source):
            return f"{BANNED_CONSTRUCT_REASON} (found {label})"
    return None


def extract_code_block(response: str) -> str | None:
    """Pull the first fenced code block out of a model response."""

    if not isinstance(response, str):
        return None
    match = _FENCE_RE.search(response)
    if match is None:
        return None
    block = match.group(1).strip()
    return block or None
