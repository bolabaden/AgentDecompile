"""Single-session PyGhidra enrich-then-decompile orchestration.

The heavy Ghidra/PyGhidra work is optional at import time so unit tests can
exercise ordering and fact shaping with fakes. Production callers inject a
real program session via ``EnrichSession``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from .reference_corpus import ReferenceCorpus, CorpusClass
from .rtti_recover import RttiClass, demangle_typeinfo_name


SCHEMA = "agentdecompile.pyghidra-enrich-facts.v1"


class EnrichProgram(Protocol):
    """Minimal program surface used by enrichment."""

    def ensure_function(self, entry: int, length: int | None) -> None: ...

    def apply_name(self, entry: int, name: str, provenance: str) -> None: ...

    def apply_struct(self, class_name: str, fields: list[dict[str, str]]) -> None: ...

    def apply_signature(self, entry: int, signature: dict[str, Any]) -> bool: ...

    def decompile(self, entry: int) -> dict[str, Any]: ...

    def close(self) -> None: ...


@dataclass
class FakeEnrichProgram:
    """Test double that records ordering and returns canned decompiles."""

    calls: list[str] = field(default_factory=list)
    names: dict[int, str] = field(default_factory=dict)
    structs: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    signatures: dict[int, dict[str, Any]] = field(default_factory=dict)
    decompile_text: str = "void FUN_stub(void) {\n  return;\n}\n"
    closed: bool = False

    def ensure_function(self, entry: int, length: int | None) -> None:
        self.calls.append(f"ensure:{entry}:{length}")

    def apply_name(self, entry: int, name: str, provenance: str) -> None:
        self.calls.append(f"name:{entry}:{name}:{provenance}")
        self.names[entry] = name

    def apply_struct(self, class_name: str, fields: list[dict[str, str]]) -> None:
        self.calls.append(f"struct:{class_name}")
        self.structs[class_name] = fields

    def apply_signature(self, entry: int, signature: dict[str, Any]) -> bool:
        self.calls.append(f"signature:{entry}:{signature.get('callingConvention')}")
        self.signatures[entry] = signature
        return True

    def decompile(self, entry: int) -> dict[str, Any]:
        self.calls.append(f"decompile:{entry}")
        name = self.names.get(entry, f"FUN_{entry:08x}")
        text = self.decompile_text
        if class_fields := next(iter(self.structs.values()), None):
            # Simulate member access once a struct is applied.
            field_name = class_fields[0]["name"]
            text = f"int {name}(void* this) {{\n  return this->{field_name};\n}}\n"
        return {
            "entry": entry,
            "name": name,
            "decompiled": text,
            "decompilationStatus": "complete",
            "prototype": f"undefined {name}(void)",
        }

    def close(self) -> None:
        self.calls.append("close")
        self.closed = True


class PyGhidraEnrichProgram:
    """Thin adapter over one live ``FlatProgramAPI`` and one decompiler."""

    def __init__(self, flat_api: Any, *, decompile_timeout: int = 60) -> None:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions

        self.api = flat_api
        self.program = flat_api.getCurrentProgram()
        self.decompile_timeout = max(1, int(decompile_timeout))
        self.decompiler = DecompInterface()
        self.decompiler.setOptions(DecompileOptions())
        if not self.decompiler.openProgram(self.program):
            raise RuntimeError("Ghidra decompiler could not open the current program")

    def _address(self, entry: int) -> Any:
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(entry)

    def ensure_function(self, entry: int, length: int | None) -> None:
        address = self._address(entry)
        manager = self.program.getFunctionManager()
        if manager.getFunctionAt(address) is not None:
            return
        # FDE ranges are authoritative inventory boundaries. Creating the entry
        # here lets Ghidra discover its body from existing instructions.
        self.api.createFunction(address, None)

    def apply_name(self, entry: int, name: str, provenance: str) -> None:
        from ghidra.program.model.symbol import SourceType

        function = self.program.getFunctionManager().getFunctionAt(self._address(entry))
        if function is None:
            return
        # Namespace construction is separate work; keep a valid symbol while
        # preserving the fully-qualified evidence in facts/provenance.
        symbol_name = re.sub(r"[^A-Za-z0-9_.$?@]", "_", name)
        function.setName(symbol_name, SourceType.USER_DEFINED)

    def apply_struct(self, class_name: str, fields: list[dict[str, str]]) -> None:
        from ghidra.program.model.data import (
            ByteDataType,
            CategoryPath,
            DataTypeConflictHandler,
            DWordDataType,
            PointerDataType,
            StructureDataType,
            WordDataType,
        )

        manager = self.program.getDataTypeManager()
        structure = StructureDataType(CategoryPath("/recovered"), class_name, 0, manager)
        primitive = {
            "char": ByteDataType.dataType,
            "byte": ByteDataType.dataType,
            "short": WordDataType.dataType,
            "int": DWordDataType.dataType,
            "long": DWordDataType.dataType,
            "float": DWordDataType.dataType,
        }
        for field_info in fields:
            raw_type = str(field_info.get("type") or "int").strip()
            data_type = primitive.get(raw_type.replace("const ", "").strip())
            if "*" in raw_type or "&" in raw_type:
                data_type = PointerDataType()
            if data_type is None:
                data_type = DWordDataType.dataType
            structure.add(data_type, str(field_info.get("name") or "field"), None)
        tx = self.program.startTransaction(f"Create recovered type {class_name}")
        commit = False
        try:
            manager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER)
            commit = True
        finally:
            self.program.endTransaction(tx, commit)

    def _resolve_type(self, type_name: str | None) -> Any:
        """Best-effort Ghidra `DataType` for a curated type name, or None.

        Curated engine types (`CExoString`, `Vector`) do not exist in a freshly
        imported program, so an exact lookup usually fails. What has to survive
        that failure is the *width and shape* of the parameter, because that is
        what decides where an argument lands: a pointer becomes a generic
        pointer, anything else falls back to `undefined4`. Getting the exact
        struct back would improve readability, not the ABI.
        """

        from ghidra.program.model.data import (
            BuiltInDataTypeManager,
            PointerDataType,
            Undefined4DataType,
        )

        text = str(type_name or "").strip()
        if not text:
            return None
        if text.endswith("*") or text.endswith("&"):
            return PointerDataType()
        managers = (self.program.getDataTypeManager(), BuiltInDataTypeManager.getDataTypeManager())
        for manager in managers:
            for path in (f"/{text}", text):
                try:
                    found = manager.getDataType(path)
                except Exception:  # noqa: BLE001 - malformed path is a miss, not a failure
                    found = None
                if found is not None:
                    return found
        return Undefined4DataType.dataType

    def apply_signature(self, entry: int, signature: dict[str, Any]) -> bool:
        """Apply a curated prototype to one function; True when it took effect.

        Only called for signatures that already passed the `ret N` arity gate in
        `curated_enrichment` -- this method does no validation of its own and
        must not be handed an unchecked prototype.

        Failures are swallowed and reported as False rather than raised: a
        prototype the target program will not accept (an unknown calling
        convention for its compiler spec, a parameter that will not fit its
        storage model) must degrade to "decompile without it", not abort a run
        over thousands of functions.
        """

        from ghidra.program.model.data import Undefined4DataType
        from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl
        from ghidra.program.model.symbol import SourceType
        # `updateFunction`'s two overloads take `List` or `Variable[]`; a Python
        # list matches neither, so JPype raises "no matching overloads" and the
        # prototype silently never lands.
        from java.util import ArrayList

        function = self.program.getFunctionManager().getFunctionAt(self._address(entry))
        if function is None:
            return False

        convention = str(signature.get("callingConvention") or "").strip() or None
        return_type = self._resolve_type(signature.get("returnType"))
        parameters = ArrayList()
        for index, raw in enumerate(signature.get("parameters") or []):
            if not isinstance(raw, dict):
                continue
            data_type = self._resolve_type(raw.get("type")) or Undefined4DataType.dataType
            label = str(raw.get("name") or "").strip() or f"param_{index + 1}"
            parameters.add(ParameterImpl(label, data_type, self.program))

        tx = self.program.startTransaction(f"Apply curated prototype at {entry:#x}")
        commit = False
        try:
            function.updateFunction(
                convention,
                None if return_type is None else ReturnParameterImpl(return_type, self.program),
                parameters,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )
            commit = True
        except Exception:  # noqa: BLE001 - see docstring: degrade, never abort the run
            return False
        finally:
            self.program.endTransaction(tx, commit)
        return True

    def decompile(self, entry: int) -> dict[str, Any]:
        from ghidra.util.task import TaskMonitor

        function = self.program.getFunctionManager().getFunctionAt(self._address(entry))
        if function is None:
            return {
                "entry": entry,
                "name": f"FUN_{entry:08x}",
                "decompiled": "",
                "decompilationStatus": "missing-function",
                "prototype": None,
            }
        result = self.decompiler.decompileFunction(
            function,
            self.decompile_timeout,
            TaskMonitor.DUMMY,
        )
        if not result.decompileCompleted():
            return {
                "entry": entry,
                "name": str(function.getName()),
                "decompiled": "",
                "decompilationStatus": "failed",
                "prototype": str(function.getPrototypeString(False, False)),
                "error": str(result.getErrorMessage() or ""),
            }
        decompiled = result.getDecompiledFunction()
        return {
            "entry": entry,
            "name": str(function.getName()),
            "decompiled": str(decompiled.getC()) if decompiled is not None else "",
            "decompilationStatus": "complete",
            "prototype": (
                str(decompiled.getSignature())
                if decompiled is not None
                else str(function.getPrototypeString(False, False))
            ),
        }

    def close(self) -> None:
        self.decompiler.dispose()


@dataclass
class EnrichSession:
    program: EnrichProgram
    corpus: ReferenceCorpus | None = None
    rtti_classes: list[RttiClass] = field(default_factory=list)
    boundaries: list[dict[str, Any]] = field(default_factory=list)
    module_by_entry: dict[int, str] = field(default_factory=dict)
    names_by_entry: dict[int, tuple[str, str]] = field(default_factory=dict)
    #: Curated prototypes keyed by entry VA, as loaded from
    #: `curated_project.load_curated_signatures`. Only records that already
    #: passed the `ret N` arity gate belong here.
    signatures_by_entry: dict[int, dict[str, Any]] = field(default_factory=dict)


def readability_score(*, name: str, module: str | None, provenance: str | None) -> float:
    """Advisory 0–1 heuristic; Port inclusion uses ``passes_readability_gate`` only."""
    score = 0.0
    if name and not name.startswith("FUN_"):
        score += 0.5
    if module and module != "recovered/unmapped":
        score += 0.3
    if provenance and provenance not in {"", "unknown"}:
        score += 0.2
    return round(min(score, 1.0), 3)


_DEFAULT_FUN_RE = re.compile(r"^(?:FUN_|LAB_|SUB_|thunk_|FID_conflict:)", re.IGNORECASE)


def is_default_ghidra_name(name: str | None) -> bool:
    text = str(name or "").strip()
    if not text:
        return True
    return bool(_DEFAULT_FUN_RE.match(text))


def build_names_by_entry(
    *,
    discovered: list[dict[str, Any]],
    rtti_classes: list[RttiClass] | None = None,
    corpus: ReferenceCorpus | None = None,
    curated_names: dict[int, str] | None = None,
) -> dict[int, tuple[str, str]]:
    """Ranked naming evidence applied before decompile.

    Priority (last write wins only within a lower priority; higher wins):
    1. Ghidra non-default symbol names (imports, FLIRT, user labels)
    2. Corpus class methods matched by simple name when RTTI class is present
    3. Curated names from a real curated Ghidra project database (highest)

    `curated_names` defaults to `None`, in which case this tier is skipped
    entirely and behavior is identical to before it existed -- callers that
    do not pass it are unaffected.
    """

    names: dict[int, tuple[str, str]] = {}
    for row in discovered:
        try:
            entry = int(row["entry"])
        except (KeyError, TypeError, ValueError):
            continue
        name = str(row.get("name") or "").strip()
        if is_default_ghidra_name(name):
            continue
        names[entry] = (name, "ghidra-symbol")

    if corpus is not None and rtti_classes:
        class_names = {cls.name for cls in rtti_classes}
        method_to_qualified: dict[str, str] = {}
        for class_name, cls in corpus.classes.items():
            if class_name not in class_names:
                continue
            for method in cls.methods:
                simple = method.split("::")[-1] if "::" in method else method
                method_to_qualified.setdefault(simple, f"{class_name}::{simple}")

        for row in discovered:
            try:
                entry = int(row["entry"])
            except (KeyError, TypeError, ValueError):
                continue
            if entry in names:
                continue
            name = str(row.get("name") or "").strip()
            if is_default_ghidra_name(name):
                continue
            qualified = method_to_qualified.get(name)
            if qualified:
                names[entry] = (qualified, "rtti-corpus")

    if curated_names:
        for entry, name in curated_names.items():
            text = str(name or "").strip()
            if is_default_ghidra_name(text):
                continue
            names[int(entry)] = (text, "curated-project")

    return names


def curated_fact_fields(curated: dict[str, Any] | None) -> dict[str, Any]:
    """Fact columns carrying an applied curated prototype, or `{}` when none.

    `callingConvention` and `locals` are the two fields
    `sourcegen.normalize_function_fact` already reads, so filling them here is
    what puts the prototype in front of candidate generation; the rest is
    provenance for a reader auditing where a candidate's shape came from.
    """

    if not curated:
        return {}
    fields: dict[str, Any] = {"curatedSignature": curated.get("signature")}
    if curated.get("callingConvention"):
        fields["callingConvention"] = curated["callingConvention"]
    if curated.get("qualifiedName"):
        fields["qualifiedName"] = curated["qualifiedName"]
    named_params = [
        {"name": item["name"], "slot": item["slot"]}
        for item in (curated.get("parameters") or [])
        if isinstance(item, dict) and item.get("name") and item.get("slot")
    ]
    if named_params:
        fields["locals"] = named_params
    return fields


def iter_enriched_facts(session: EnrichSession) -> Iterator[dict[str, Any]]:
    """Apply boundaries → RTTI/corpus names/types → decompile. Order is load-bearing."""
    program = session.program
    try:
        for row in session.boundaries:
            entry = int(row["entry"] if not isinstance(row.get("entry"), str) else int(str(row["entry"]), 16))
            length = row.get("length") or row.get("bodyBytes")
            length_i = int(length) if length is not None else None
            program.ensure_function(entry, length_i)

        if session.corpus:
            for rtti in session.rtti_classes:
                cls: CorpusClass | None = session.corpus.classes.get(rtti.name)
                fields = [{"name": f.name, "type": f.type} for f in (cls.fields if cls else [])]
                if fields:
                    program.apply_struct(rtti.name, fields)
                else:
                    # Placeholder class DT so PE MSVC RTTI still shapes decompiles.
                    program.apply_struct(
                        rtti.name,
                        [{"name": "vftable", "type": "void *"}],
                    )
        else:
            for rtti in session.rtti_classes:
                program.apply_struct(
                    rtti.name,
                    [{"name": "vftable", "type": "void *"}],
                )
        for entry, (name, provenance) in session.names_by_entry.items():
            program.apply_name(entry, name, provenance)

        # Prototypes go on after names and before decompile: the calling
        # convention decides where arguments live, so the decompiler has to see
        # it to emit `this->field` instead of a read of an uninitialised
        # `in_ECX`, and applying it afterwards would change nothing.
        applied_signatures: set[int] = set()
        for entry, signature in session.signatures_by_entry.items():
            if program.apply_signature(int(entry), signature):
                applied_signatures.add(int(entry))

        for row in session.boundaries:
            entry = int(row["entry"] if not isinstance(row.get("entry"), str) else int(str(row["entry"]), 16))
            result = program.decompile(entry)
            # Prefer the ranked naming tier over whatever the decompiler echoed.
            # apply_name can fail to stick; curated/ghidra tiers must still reach facts.
            if entry in session.names_by_entry:
                name, provenance = session.names_by_entry[entry]
            else:
                name = str(result.get("name") or f"FUN_{entry:08x}")
                provenance = str(row.get("provenance") or "eh-frame")
            module = session.module_by_entry.get(entry) or row.get("module")
            score = readability_score(name=name, module=module, provenance=provenance)
            curated = session.signatures_by_entry.get(entry) if entry in applied_signatures else None
            yield {
                "entry": f"{entry:08x}",
                "entryOffset": entry,
                "name": name,
                "prototype": result.get("prototype"),
                "decompiled": result.get("decompiled"),
                "decompilationStatus": result.get("decompilationStatus") or "complete",
                "module": module,
                "provenance": provenance,
                "readabilityScore": score,
                "section": row.get("section"),
                "length": row.get("length") or row.get("bodyBytes"),
                **curated_fact_fields(curated),
                **({"error": result["error"]} if result.get("error") else {}),
            }
    finally:
        program.close()


def enrich_and_decompile(session: EnrichSession) -> list[dict[str, Any]]:
    """Materialize facts for tests/small callers; production writes incrementally."""
    return list(iter_enriched_facts(session))


def write_facts_jsonl(path: Path, facts: list[dict[str, Any]], *, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in facts:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    summary = {
        "schema": SCHEMA,
        "factsPath": str(path),
        "functionCount": len(facts),
        "namedCount": sum(
            1 for f in facts if not is_default_ghidra_name(str(f.get("name") or ""))
        ),
        **(receipt or {}),
    }
    (path.parent / "enrich-receipt.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def run_enrich_pipeline(
    *,
    boundaries: list[dict[str, Any]],
    corpus: ReferenceCorpus | None,
    rtti_classes: list[RttiClass],
    out_facts: Path,
    program_factory: Callable[[], EnrichProgram],
    module_by_entry: dict[int, str] | None = None,
    names_by_entry: dict[int, tuple[str, str]] | None = None,
    signatures_by_entry: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    session = EnrichSession(
        program=program_factory(),
        corpus=corpus,
        rtti_classes=rtti_classes,
        boundaries=boundaries,
        module_by_entry=module_by_entry or {},
        names_by_entry=names_by_entry or {},
        signatures_by_entry=signatures_by_entry or {},
    )
    out_facts.parent.mkdir(parents=True, exist_ok=True)
    function_count = 0
    named_count = 0
    prototyped_count = 0
    with out_facts.open("w", encoding="utf-8") as handle:
        for fact in iter_enriched_facts(session):
            handle.write(json.dumps(fact, sort_keys=True) + "\n")
            function_count += 1
            if not is_default_ghidra_name(str(fact.get("name") or "")):
                named_count += 1
            if fact.get("curatedSignature"):
                prototyped_count += 1
    summary = {
        "schema": SCHEMA,
        "factsPath": str(out_facts),
        "functionCount": function_count,
        "namedCount": named_count,
        "curatedPrototypeCount": prototyped_count,
    }
    (out_facts.parent / "enrich-receipt.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


# Re-export demangle for callers/tests
__all__ = [
    "EnrichSession",
    "FakeEnrichProgram",
    "PyGhidraEnrichProgram",
    "build_names_by_entry",
    "demangle_typeinfo_name",
    "enrich_and_decompile",
    "is_default_ghidra_name",
    "iter_enriched_facts",
    "readability_score",
    "run_enrich_pipeline",
    "write_facts_jsonl",
]
