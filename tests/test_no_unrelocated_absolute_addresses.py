"""U4 of docs/plans/2026-07-30-001-fix-generalize-relocation-evidence-plan.md.

**Scope correction (documented in the plan's amended Key Technical
Decisions):** the plan originally set out to guard against rule generators
that embed a raw absolute address in generated C source *without* populating
`absoluteAddressRelocations`. Real-toolchain investigation (real MSVC8/wine
compile + real objdiff) overturned that premise: `absoluteAddressRelocations`
only helps when the candidate's own compiled object references the address
through a compiler-emitted relocation (a named `extern` symbol) -- not a raw
literal pointer cast (`*(unsigned int *)0x...`), which MSVC compiles as a bare
immediate with no relocation. Adding the evidence to a literal-cast candidate
was A/B tested and found to make matching *worse* (spurious
`ARGUMENT_MISMATCH` entries), not better -- confirmed for
`global_and_global_bool` and for one of the ten single-address rules this
plan's U2 originally (and incorrectly) wired up, then reverted.

This test guards the corrected, real anti-pattern instead: a rule generator
must never populate `absoluteAddressRelocations` for an address its own
generated source only references via a literal pointer cast. `inc_abs_global`
is exempt from this check -- its own literal-cast candidates are unaffected
either way (real-toolchain A/B testing showed identical results with and
without the evidence), and the evidence field exists there specifically so a
*different*, later-constructed candidate for the same target (e.g. a
subagent rewrite referencing a named `DAT_<addr>` symbol, per
docs/solutions/architecture-patterns/rewrite-queue-subagent-fulfillment.md)
can carry matching relocation evidence of its own. Extending that
inheritance to fire automatically for every packaged-source/rewrite
candidate is a distinct, deferred piece of work -- see the plan's Scope
Boundaries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from agentdecompile_recovery.source_parity_synthesize import (
    BINK_BUFFER_SET_DIRECT_DRAW_FORWARDER,
    bink_buffer_set_direct_draw_forwarder,
)

SOURCE_PATH = Path(__file__).resolve().parent.parent / "src" / "agentdecompile_recovery" / "source_parity_synthesize.py"

# Rules exempt from this check: their own literal-cast candidate is
# unaffected by the evidence (verified real-toolchain neutral, not harmful),
# and the evidence exists to serve a different, later-constructed candidate.
EXEMPT_RULE_FUNCTIONS = {"inc_abs_global"}

LITERAL_CAST_RE = re.compile(r"\([^)]*\*\)\s*0x\{[a-zA-Z_]+")


def _iter_rule_generator_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    functions = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        args = [a.arg for a in node.args.args]
        if args[:3] == ["row", "c_name", "data"]:
            functions.append(node)
    return functions


def _function_source(source_lines: list[str], node: ast.FunctionDef) -> str:
    return "\n".join(source_lines[node.lineno - 1 : node.end_lineno])


def test_no_rule_generator_pairs_relocation_evidence_with_a_literal_cast() -> None:
    text = SOURCE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(text)
    source_lines = text.splitlines()

    violations = []
    for node in _iter_rule_generator_functions(tree):
        if node.name in EXEMPT_RULE_FUNCTIONS:
            continue
        body = _function_source(source_lines, node)
        if "absoluteAddressRelocations" not in body:
            continue
        if LITERAL_CAST_RE.search(body):
            violations.append(node.name)

    assert violations == [], (
        f"Rule generator(s) {violations} populate absoluteAddressRelocations "
        "while their generated source only references the address via a "
        "literal pointer cast -- real-toolchain testing showed this makes "
        "objdiff matching worse, not better (see this test's module "
        "docstring). Either remove the evidence, or change the generated "
        "source to reference the address through a named extern symbol."
    )


def test_legitimate_named_symbol_usage_is_not_flagged() -> None:
    """Positive-path case: bink_buffer_set_direct_draw_forwarder is the one
    pre-existing rule that genuinely needs absoluteAddressRelocations -- it
    references its addresses through named extern symbols, not a literal
    cast. Deliberately targets this function (rather than relying on the
    whole-file scan's incidental pass) so the check's "allowed pattern"
    branch has its own coverage, not just the negative case.
    """

    candidates = bink_buffer_set_direct_draw_forwarder({}, "FUN_test", BINK_BUFFER_SET_DIRECT_DRAW_FORWARDER)
    assert len(candidates) == 2
    relocations = candidates[0].evidence.get("absoluteAddressRelocations")
    assert relocations == [
        {"offset": 0x14, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c6c", "decodedAddress": "0x30068c6c"},
        {"offset": 0x19, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c70", "decodedAddress": "0x30068c70"},
        {"offset": 0x1F, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c68", "decodedAddress": "0x30068c68"},
        {"offset": 0x36, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c6c", "decodedAddress": "0x30068c6c"},
        {"offset": 0x3C, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c70", "decodedAddress": "0x30068c70"},
        {"offset": 0x42, "type": "IMAGE_REL_I386_DIR32", "symbol": "_recovery_global_30068c68", "decodedAddress": "0x30068c68"},
    ]

    text = SOURCE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(text)
    source_lines = text.splitlines()
    functions = {node.name: node for node in _iter_rule_generator_functions(tree)}
    body = _function_source(source_lines, functions["bink_buffer_set_direct_draw_forwarder"])
    assert "absoluteAddressRelocations" in body
    assert LITERAL_CAST_RE.search(body) is None


_ANTI_PATTERN_SOURCE_LINES = {
    "dereferenced-cast": '    source = f"*(unsigned int *)0x{addr:08x} = 1;"\n',
    "indexed-store": '    source = f"((unsigned int *)0x{addr:08x})[index] = value;"\n',
    "assign-then-deref": (
        '    source = f"unsigned int *slot = (unsigned int *)0x{addr:08x}; *slot = 1;"\n'
    ),
}


@pytest.mark.parametrize("source_line", _ANTI_PATTERN_SOURCE_LINES.values(), ids=_ANTI_PATTERN_SOURCE_LINES.keys())
def test_check_actually_detects_the_anti_pattern(source_line: str) -> None:
    """Regression guard on the check itself: prove it fires on a synthetic
    function shaped exactly like the mistake this test exists to prevent --
    covering all three literal-cast idioms LITERAL_CAST_RE was broadened to
    catch (dereferenced cast, indexed-store, assign-then-deref), not just the
    first one. Without this, a future narrowing of the regex back to only the
    first idiom would pass every test in this file silently.
    """

    synthetic_source = (
        "def fake_rule(row: dict[str, Any], c_name: str, data: bytes) -> list[GeneratedCandidate]:\n"
        "    addr = u32(data[2:6])\n"
        + source_line
        + "    return [GeneratedCandidate(\n"
        '        rule="fake", variant="fake", c_name=c_name, symbol=c_name,\n'
        "        source=source, callconv=\"cdecl\", return_type=\"void\",\n"
        '        evidence={"absoluteAddressRelocations": [{"offset": 2}]},\n'
        "    )]\n"
    )
    tree = ast.parse(synthetic_source)
    source_lines = synthetic_source.splitlines()
    functions = _iter_rule_generator_functions(tree)
    assert len(functions) == 1
    body = _function_source(source_lines, functions[0])
    assert "absoluteAddressRelocations" in body
    assert LITERAL_CAST_RE.search(body) is not None
