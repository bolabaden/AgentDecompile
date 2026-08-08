"""Cross-build symbol identity map for stripped targets.

A stripped target (for example `k1_win_gog_swkotor.exe`) can borrow real
function identity from a *donor* build of the same program that still carries a
symbol table (for example `k1_mac_swkotor.app`), and can borrow parameter types
from a *signature* build whose symbols retain Itanium mangling (for example the
K2 `armeabi-v7a` shared object).

This module holds the pure data handling for that transfer: how to tell a real
name from a mechanically derived one, how to score the evidence behind a name,
and how to serialise the result.  Reading the programs themselves is the
caller's job; every entry point here takes plain dicts.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# --------------------------------------------------------------------------
# Name shapes
# --------------------------------------------------------------------------

#: Prefixes Ghidra (or a prior tool) generates from an address.  ``Unwind@`` and
#: ``FrameHandler_`` are not Ghidra defaults but dominate the Windows builds in
#: this corpus; see mission note 11 finding F1.
AUTOGEN_PREFIXES: tuple[str, ...] = (
    "FUN_",
    "SUB_",
    "sub_",
    "thunk_FUN_",
    "thunk_sub_",
    "DAT_",
    "PTR_",
    "LAB_",
    "UNK_",
    "EXT_",
    "caseD_",
    "switchD_",
    "Unwind@",
    "FrameHandler_",
    "Catch@",
)

#: A trailing address, however it is joined on: ``foo_00401000``, ``Unwind@401000``.
ADDRESS_SUFFIX_RE = re.compile(r"[@_](?:0x)?[0-9a-fA-F]{6,16}$")

#: Compiler and standard-library namespaces, which are never engine identity.
NON_ENGINE_ROOTS = frozenset(
    {
        "std",
        "stdext",
        "__gnu_cxx",
        "__cxxabiv1",
        "ATL",
        "operator",
        "__ndk1",
    }
)

#: MSVC C++ exception handling emits one small funclet per `try` scope and one
#: frame handler per function.  They are compiler plumbing, not engine methods,
#: and no donor built by a different compiler can ever supply a name for them.
EH_FUNCLET_PREFIXES: tuple[str, ...] = ("Unwind@", "FrameHandler_", "Catch@")


def is_autogen_name(name: str) -> bool:
    """True when *name* carries no knowledge beyond an address."""
    if not name:
        return True
    if name.startswith(AUTOGEN_PREFIXES):
        return True
    return bool(ADDRESS_SUFFIX_RE.search(name))


def is_eh_funclet(name: str) -> bool:
    """True when *name* is an MSVC exception-handling funclet."""
    return bool(name) and name.startswith(EH_FUNCLET_PREFIXES)


def qualified_name(namespace: Sequence[str], name: str) -> str:
    """``['CSWSCreature'], 'AIUpdate'`` -> ``CSWSCreature::AIUpdate``."""
    return "::".join([*namespace, name]) if namespace else name


def root_class(namespace: Sequence[str]) -> str | None:
    return namespace[0] if namespace else None


def corroborated_engine_classes(
    target_classes: Iterable[str],
    *corroborating_class_sets: Iterable[str],
) -> set[str]:
    """Target classes that also appear in at least one independent build.

    A class an analyst invented while annotating the target appears only in the
    target.  A class that is really part of the engine appears in every build of
    the engine, so requiring corroboration keeps the "engine class" count
    evidence-based rather than regex-based.
    """
    corroborating: set[str] = set()
    for group in corroborating_class_sets:
        corroborating.update(group)
    return {c for c in target_classes if c not in NON_ENGINE_ROOTS and c in corroborating}


# --------------------------------------------------------------------------
# Signatures borrowed from a mangled build
# --------------------------------------------------------------------------

_DEMANGLED_RE = re.compile(r"^(?P<name>[^(]+?)\s*\((?P<params>.*)\)\s*(?P<trailer>const)?$")


def parse_demangled(demangled: str) -> tuple[str, str] | None:
    """Split ``Class::Method(int, float) const`` into (qualified, "(int, float) const").

    Returns ``None`` for symbols that carry no parameter list (data symbols,
    vtables, typeinfo), which the caller should skip.
    """
    text = demangled.strip()
    if "(" not in text or not text.endswith((")", "const")):
        return None
    depth = 0
    open_at = -1
    for i, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                open_at = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and text[i + 1 :].strip() in ("", "const"):
                params = text[open_at : i + 1]
                trailer = text[i + 1 :].strip()
                name = text[:open_at].strip()
                if not name:
                    return None
                return name, params + (" const" if trailer == "const" else "")
    if open_at < 0:
        return None
    return None


_EIGHT_BYTE = frozenset({"double", "long long", "unsigned long long", "long double"})
_FOUR_BYTE = frozenset(
    {
        "int",
        "unsigned int",
        "unsigned",
        "long",
        "unsigned long",
        "float",
        "bool",
        "char",
        "unsigned char",
        "signed char",
        "short",
        "unsigned short",
        "wchar_t",
    }
)


def _split_top_level(text: str) -> list[str]:
    depth = 0
    parts: list[str] = []
    cur = ""
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def msvc_stack_arg_bytes(params: str) -> int | None:
    """Stack bytes a 32-bit MSVC caller pushes for *params*.

    Returns ``None`` when the answer depends on a type whose size is not visible
    from the name alone (a class passed by value, an enum, varargs).  Refusing to
    guess is the point: a wrong arity is worse than no arity.
    """
    inner = params.strip()
    if inner.endswith(" const"):
        inner = inner[: -len(" const")].strip()
    if not (inner.startswith("(") and inner.endswith(")")):
        return None
    inner = inner[1:-1].strip()
    if inner in ("", "void"):
        return 0
    if "..." in inner:
        return None
    total = 0
    for part in _split_top_level(inner):
        p = part.strip()
        if p.endswith(("*", "&")):
            total += 4
            continue
        base = p.replace("const", "").replace("volatile", "").strip()
        if base in _EIGHT_BYTE:
            total += 8
            continue
        if base in _FOUR_BYTE:
            total += 4
            continue
        return None
    return total


#: ``Function.UNKNOWN_STACK_DEPTH_CHANGE``
UNKNOWN_PURGE = 0x7FFFFFFF

ARITY_MATCH = "match"
ARITY_MATCH_DTOR = "match-msvc-dtor-flag"
ARITY_CONTRADICTED = "contradicted"
ARITY_UNDECIDABLE = "undecidable"


def check_signature_arity(
    params: str,
    method_name: str,
    stack_purge: int,
    calling_convention: str,
) -> str:
    """Does a borrowed parameter list agree with what the target's own `ret N` says?

    Only ``__thiscall``/``__stdcall`` callees clean their own argument bytes, so
    only those carry arity information.  MSVC gives a scalar-deleting destructor
    a hidden ``int`` flag argument, which shows up as ``ret 4`` on a destructor
    the donor declares as taking nothing.
    """
    if calling_convention == "__cdecl" or stack_purge in (UNKNOWN_PURGE, None) or stack_purge < 0:
        return ARITY_UNDECIDABLE
    expected = msvc_stack_arg_bytes(params)
    if expected is None:
        return ARITY_UNDECIDABLE
    if stack_purge == expected:
        return ARITY_MATCH
    if method_name.startswith("~") and expected == 0 and stack_purge == 4:
        return ARITY_MATCH_DTOR
    if stack_purge == 0 and expected > 0 and calling_convention != "__thiscall":
        return ARITY_UNDECIDABLE
    return ARITY_CONTRADICTED


def build_signature_index(demangled_symbols: Iterable[str]) -> dict[str, list[str]]:
    """``Class::Method`` -> sorted distinct parameter lists seen in the donor.

    More than one entry means the donor has overloads and the parameter list
    cannot be attributed to a single target function by name alone.
    """
    index: dict[str, set[str]] = {}
    for sym in demangled_symbols:
        parsed = parse_demangled(sym)
        if parsed is None:
            continue
        name, params = parsed
        index.setdefault(name, set()).add(params)
    return {k: sorted(v) for k, v in index.items()}


# --------------------------------------------------------------------------
# Evidence and confidence
# --------------------------------------------------------------------------


#: Why a target function does or does not have a donor counterpart.  "absent"
#: and "ambiguous" both leave the name unconfirmed but mean different things:
#: absent says the donor has never heard of this name, ambiguous says the donor
#: has several functions with it and none can be singled out.
DONOR_STATUSES = ("paired", "ambiguous", "absent", "unknown")


@dataclass(frozen=True)
class Evidence:
    """Everything independently known about one proposed name."""

    donor_ea: int | None = None
    donor_name: str | None = None
    donor_status: str = "unknown"
    name_identity_pair: bool = False
    callgraph_agreement: float | None = None
    callgraph_callees_checked: int = 0
    shared_strings: int = 0
    strings_comparable: bool = False
    bsim_similarity: float | None = None
    bsim_significance: float | None = None
    bsim_mutual_best: bool = False
    bsim_agrees: bool | None = None
    signature_source: str | None = None
    signature_overloads: int = 0
    signature_arity_check: str = ARITY_UNDECIDABLE


#: Operating point measured on this corpus: BSim mutual-best matches at
#: significance >= 30 reproduce the analyst's own name for 1128 of 1147 checkable
#: Windows functions (98.3%).  Below 30 precision falls off a cliff (76.5% in
#: [20,30), 36.1% in [10,20)).
BSIM_TRUSTED_SIGNIFICANCE = 30.0

#: A pair whose callees disagree completely is contradicted by the call graph.
#: Requires enough callees for the statistic to mean anything.
CALLGRAPH_MIN_CALLEES = 2
CALLGRAPH_STRONG = 0.8


def score_confidence(ev: Evidence) -> tuple[str, float]:
    """Return ``(tier, confidence)`` for one proposed name.

    Tiers are defined by which independent channels corroborate the name, not by
    any single similarity number:

    ``high``
        The donor agrees *and* at least one channel that BSim cannot see (call
        graph, shared string literals) or a trusted BSim mutual-best match
        confirms it.
    ``medium``
        The donor agrees but nothing else could be checked.
    ``low``
        No donor counterpart, or a channel actively contradicts the name.
    """
    corroborations = 0
    contradicted = False

    if (
        ev.callgraph_callees_checked >= CALLGRAPH_MIN_CALLEES
        and ev.callgraph_agreement is not None
    ):
        if ev.callgraph_agreement >= CALLGRAPH_STRONG:
            corroborations += 1
        elif ev.callgraph_agreement == 0.0:
            contradicted = True

    if ev.strings_comparable:
        if ev.shared_strings > 0:
            corroborations += 1
        else:
            contradicted = True

    trusted_bsim = (
        ev.bsim_mutual_best
        and ev.bsim_significance is not None
        and ev.bsim_significance >= BSIM_TRUSTED_SIGNIFICANCE
    )
    if trusted_bsim:
        if ev.bsim_agrees:
            corroborations += 1
        elif ev.bsim_agrees is False:
            contradicted = True

    if not ev.name_identity_pair:
        # The donor knowing the name but not being able to single out which of
        # its functions carries it is weaker than a pairing and stronger than
        # the donor never having heard of it.
        return "low", 0.60 if ev.donor_status == "ambiguous" else 0.30
    if contradicted:
        return "low", 0.55
    if corroborations >= 2:
        return "high", 0.99
    if corroborations == 1:
        return "high", 0.97
    return "medium", 0.85


@dataclass
class SymbolRecord:
    """One target function and whatever identity could be established for it."""

    ea: int
    name: str | None
    cls: str | None
    qualified: str | None
    params: str | None
    signature: str | None
    identity: str
    name_source: str
    symbol_source: str
    size: int
    tier: str
    confidence: float
    evidence: Evidence = field(default_factory=Evidence)

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        out["ea"] = f"0x{self.ea:08x}"
        out["ea_int"] = self.ea
        # Drop only unknowns.  A zero call-graph agreement, zero shared strings
        # or ``bsim_agrees: false`` are the contradictions this map exists to
        # surface, and they must survive serialisation.
        out["evidence"] = {k: v for k, v in out["evidence"].items() if v is not None}
        return out


CSV_COLUMNS = (
    "ea",
    "qualified",
    "class",
    "name",
    "signature",
    "identity",
    "tier",
    "confidence",
    "name_source",
    "donor_ea",
    "callgraph_agreement",
    "bsim_significance",
)


def record_to_csv_row(rec: SymbolRecord) -> list[str]:
    ev = rec.evidence
    return [
        f"0x{rec.ea:08x}",
        rec.qualified or "",
        rec.cls or "",
        rec.name or "",
        rec.signature or "",
        rec.identity,
        rec.tier,
        f"{rec.confidence:.2f}",
        rec.name_source,
        f"0x{ev.donor_ea:08x}" if ev.donor_ea is not None else "",
        "" if ev.callgraph_agreement is None else f"{ev.callgraph_agreement:.3f}",
        "" if ev.bsim_significance is None else f"{ev.bsim_significance:.1f}",
    ]


def write_jsonl(records: Iterable[SymbolRecord], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_json(), sort_keys=True) + "\n")
            n += 1
    return n


def summarise(records: Sequence[SymbolRecord]) -> dict[str, Any]:
    """Counts a reader can check against the raw map."""
    by_identity: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    named = 0
    engine = 0
    with_signature = 0
    for rec in records:
        by_identity[rec.identity] = by_identity.get(rec.identity, 0) + 1
        by_tier[rec.tier] = by_tier.get(rec.tier, 0) + 1
        if rec.qualified:
            named += 1
        if rec.identity == "engine":
            engine += 1
        if rec.signature:
            with_signature += 1
    return {
        "functions": len(records),
        "named": named,
        "engine_class_named": engine,
        "with_parameter_signature": with_signature,
        "by_identity": dict(sorted(by_identity.items())),
        "by_tier": dict(sorted(by_tier.items())),
    }


def callgraph_agreement(
    target_callees: Iterable[int],
    donor_callees: Iterable[int],
    pairing: Mapping[int, int],
) -> tuple[float | None, int]:
    """Fraction of the target's *mapped* callees that are also donor callees.

    Returns ``(score, n_checked)``; ``score`` is ``None`` when no callee of the
    target has a known counterpart, in which case the check says nothing.
    """
    donor = set(donor_callees)
    checked = [c for c in target_callees if c in pairing]
    if not checked:
        return None, 0
    hits = sum(1 for c in checked if pairing[c] in donor)
    return hits / len(checked), len(checked)
