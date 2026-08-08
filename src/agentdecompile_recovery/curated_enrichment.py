"""Curated parameter names, comments and prototypes, read from a Ghidra program database.

Ghidra curates three disjoint kinds of per-function knowledge that never reach
the source_cleanup/source_dump pipeline today: curated parameter names
(stored as `Symbols` rows parented to the function), Plate/EOL/Pre
comments (stored in the `Comments` table), and the function *prototype* --
calling convention, return type and parameter types (stored across
`Function Data` and the data-type tables). All three are read here directly
from the `.gbf` database via `GhidraProgram` -- this module never opens a
PyGhidra/live-Ghidra session and never re-parses the database itself; it is
a thin join on top of `GhidraProgram.locals_by_function()`,
`GhidraProgram.comments()` and `GhidraProgram.functions()`.

Scope for *names*: PARAMETER names only, not local variables. Measured on the
curated Odyssey project, curated names cover 2,232 of 16,981 parameter symbols
but only 4 of 147,543 local-variable symbols -- a local-variable rename pass
fed from this data source would touch a handful of functions project-wide,
so it is deliberately left out. Callers that want the honest picture should
report coverage as "curated names applied to N of M parameters", not as a
general local-variable naming feature.

Scope for *prototypes*: the calling convention is the load-bearing field. A
32-bit MSVC `__thiscall` method passes `this` in ECX; decompiled without that
knowledge it surfaces as a read of an uninitialised `in_ECX` local, and a
candidate compiled from that text cannot match the target. Emitting the
prototype is gated on the target's own `ret N` epilogue agreeing with the
declared parameter list (`symbol_map.check_signature_arity`): a contradicted
function keeps its name and gets **no** signature, because a wrong prototype
silently produces wrong candidates and is worse than none.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .ghidra_db.program import GhidraProgram, LocalVariable, SymbolType
from .symbol_map import ARITY_CONTRADICTED, check_signature_arity

# Preferred order when combining multiple stored comment kinds into one header.
_HEADER_COMMENT_KINDS = ("Plate", "EOL", "Pre")
# EOL/Pre comments are per-line and often long or code-shaped; only short ones
# read sanely as a one-line function header note.
_SHORT_COMMENT_MAX_LEN = 120


@dataclass(frozen=True)
class CuratedFunctionHints:
    """Curated knowledge for one function, keyed by its entry VA by the caller."""

    entry: int
    header_comment: str | None
    params: list[dict[str, str]]

    def to_locals_fact(self) -> list[dict[str, str]]:
        """The exact `fact['locals']` shape `clean_source_text` substitutes."""

        return list(self.params)


def normalize_entry_key(value: Any) -> str | None:
    """Bare lowercase 8-hex-digit entry key, matching `source_dump.normalize_entry_hex`.

    Duplicated rather than imported: `source_dump` imports from
    `source_cleanup`, and `source_cleanup` needs this same normalization, so
    importing `source_dump` here would create a cycle. Both must keep
    producing identical keys for the same address for hint lookups to match.
    """

    if value is None:
        return None
    if isinstance(value, int):
        return f"{value:08x}"
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if text and all(c in "0123456789abcdef" for c in text):
        return text
    try:
        return f"{int(text):08x}"
    except (TypeError, ValueError):
        return text or None


def param_slot_name(ordinal: int | None) -> str | None:
    """Ghidra's decompiler-emitted identifier for a parameter ordinal.

    Ghidra numbers parameters 1-based in emitted C (`param_1` is the first
    parameter, stored ordinal 0). Returns None for ordinals it cannot place,
    so callers skip rather than guess a slot name.
    """

    if ordinal is None or ordinal < 0:
        return None
    return f"param_{ordinal + 1}"


def curated_params_for_function(variables: list[LocalVariable]) -> list[dict[str, str]]:
    """Curated parameter name/slot pairs, in declaration order.

    Only `SymbolType.PARAMETER` entries are used -- see module docstring for
    why local variables are excluded. Entries whose ordinal cannot be mapped
    to a `param_N` slot, or whose name is empty, are skipped.
    """

    pairs: list[dict[str, str]] = []
    for variable in variables:
        if variable.symbol_type != SymbolType.PARAMETER or not variable.name:
            continue
        slot = param_slot_name(variable.ordinal)
        if slot is None:
            continue
        pairs.append({"name": variable.name, "slot": slot})
    return pairs


def sanitize_header_comment_text(text: str) -> str:
    """Flatten a curated comment so it is safe to embed in a `/* ... */` header.

    A curated comment containing a literal `*/` would otherwise close the
    surrounding C block comment early and corrupt the emitted file; a
    multi-line comment would break the `" * "`-per-line header convention.
    Both are neutralised rather than rejected, so real content still shows.
    """

    flattened = " ".join(text.split())
    return flattened.replace("*/", "* /")


def header_comment_for_function(comments: dict[str, str]) -> str | None:
    """Pick one stored comment to surface in a generated header, preferring Plate.

    Plate comments are Ghidra's per-function annotation and are used
    whichever length. EOL/Pre are per-line and often long or code-shaped;
    they are used only when short enough to read as a one-line header note.
    """

    plate = comments.get("Plate")
    if plate and plate.strip():
        return sanitize_header_comment_text(plate)
    for kind in ("EOL", "Pre"):
        text = comments.get(kind)
        if text and text.strip() and len(text.strip()) <= _SHORT_COMMENT_MAX_LEN:
            return sanitize_header_comment_text(text)
    return None


def build_curated_hints(program: GhidraProgram) -> dict[int, CuratedFunctionHints]:
    """Curated per-function hints keyed by function entry VA.

    Joins `program.locals_by_function()` (parameter names) and
    `program.comments()` (Plate/EOL/Pre) onto function entry addresses via
    `program.functions()`. Functions with neither curated parameters nor a
    usable comment are omitted -- callers should treat a missing key as
    "nothing curated for this function", not as an error.
    """

    locals_by_symbol = program.locals_by_function()
    comments_by_entry: dict[int, dict[str, str]] = {}
    for comment_set in program.comments():
        comments_by_entry[comment_set.entry] = comment_set.comments

    hints: dict[int, CuratedFunctionHints] = {}
    for function in program.functions():
        if function.entry is None:
            continue
        params = curated_params_for_function(locals_by_symbol.get(function.symbol_id, []))
        header_comment = header_comment_for_function(comments_by_entry.get(function.entry, {}))
        if not params and not header_comment:
            continue
        hints[function.entry] = CuratedFunctionHints(
            entry=function.entry,
            header_comment=header_comment,
            params=params,
        )
    return hints


def curated_hints_to_json(hints: dict[int, CuratedFunctionHints]) -> dict[str, dict[str, Any]]:
    """Entry-hex-keyed view consumed by `source_dump.dump_source_tree` and
    `source_cleanup.cleanup_recovered_source_package` (`curated_hints=`).

    Keys are built with `normalize_entry_key`, the exact function the lookup
    call sites use on the other end (`source_dump.normalize_entry_hex` and
    this module's own `normalize_entry_key` produce identical output for
    identical input, but are two separately-maintained implementations that
    could drift). Building both sides from one function removes the
    possibility of drift entirely, rather than relying on both sides agreeing
    to zero-pad the same way. A source `entry` was always an int here (from
    `GhidraProgram.functions()`), so this was never reachable with a
    non-canonical key -- this closes the gap for any future caller that
    constructs hints from a differently-typed entry.
    """

    keyed: dict[str, dict[str, Any]] = {}
    for entry, hint in hints.items():
        key = normalize_entry_key(entry)
        if key is None:
            continue
        keyed[key] = {
            "plateComment": hint.header_comment,
            "locals": hint.to_locals_fact(),
        }
    return keyed


def merge_curated_locals_into_fact(fact: dict[str, Any], curated: dict[str, Any] | None) -> dict[str, Any]:
    """`fact` with curated parameter names folded into `fact['locals']`.

    Existing entries win on slot collision -- curated names only add
    coverage `clean_source_text` did not already have, they do not override
    an already-populated locals producer.
    """

    if not curated:
        return fact
    curated_locals = curated.get("locals") if isinstance(curated.get("locals"), list) else []
    if not curated_locals:
        return fact
    existing = fact.get("locals") if isinstance(fact.get("locals"), list) else []
    existing_slots = {item.get("slot") for item in existing if isinstance(item, dict)}
    merged = list(existing) + [item for item in curated_locals if item.get("slot") not in existing_slots]
    return {**fact, "locals": merged}


# ---------------------------------------------------------------------------
# Curated prototypes
# ---------------------------------------------------------------------------

# ``ghidra.program.database.data.DataTypeManagerDB`` packs the table a data type
# lives in into the top byte of its id. Only the tables a function signature can
# reference are decoded; anything else resolves to None rather than a guess.
DT_TABLE_SHIFT = 56
DT_BUILT_IN = 0
DT_COMPOSITE = 1
DT_ARRAY = 3
DT_POINTER = 4
DT_TYPEDEF = 5
DT_FUNCTION_DEF = 6
DT_ENUM = 8

#: ``DataTypeManagerDB.DEFAULT_DATATYPE_ID`` -- Ghidra's `undefined`, which is
#: the absence of a curated type rather than a type.
DEFAULT_DATATYPE_ID = 0
#: ``DataTypeManagerDB.NULL_DATATYPE_ID``.
NULL_DATATYPE_ID = -1

UNDEFINED_TYPE_NAME = "undefined"

# Data-type table names, as written by the DataTypeManagerDB adapters.
BUILTIN_TYPES_TABLE = "Built-in datatypes"
COMPOSITE_TYPES_TABLE = "Composite Data Types"
ARRAY_TYPES_TABLE = "Arrays"
POINTER_TYPES_TABLE = "Pointers"
TYPEDEF_TYPES_TABLE = "Typedefs"
FUNCTION_DEF_TYPES_TABLE = "Function Definitions"
ENUM_TYPES_TABLE = "Enumeration Data Types"
CALLING_CONVENTIONS_TABLE = "Calling Conventions"

# A pointer with no resolvable target type still has a known width and a known
# shape, so it is reported rather than dropped.
GENERIC_POINTER_NAME = "void *"

# Guards a cyclic typedef/pointer chain; real chains are two or three deep.
_MAX_TYPE_DEPTH = 8


class CuratedTypeIndex:
    """Data-type ids resolved to source-level type names, for one program.

    Built once per program: the six data-type tables together are ~3,000 rows
    on the curated KOTOR project, against 24,242 functions and 22,578 parameter
    symbols that reference them, so a streaming lookup per reference would
    re-scan the tables tens of thousands of times.
    """

    def __init__(
        self,
        *,
        builtin: dict[int, str],
        composite: dict[int, str],
        typedef: dict[int, str],
        enum: dict[int, str],
        function_def: dict[int, str],
        pointer: dict[int, int | None],
        array: dict[int, tuple[int | None, int | None]],
        calling_conventions: dict[int, str],
    ) -> None:
        self.builtin = builtin
        self.composite = composite
        self.typedef = typedef
        self.enum = enum
        self.function_def = function_def
        self.pointer = pointer
        self.array = array
        self.calling_conventions = calling_conventions

    @classmethod
    def from_program(cls, program: GhidraProgram) -> "CuratedTypeIndex":
        """Read the data-type and calling-convention tables of `program`.

        Every table is optional: a program database written by another Ghidra
        version, or one with no user data types at all, simply resolves fewer
        ids. A missing table must not turn "no curated prototype" into an
        exception, because prototypes are an enhancement on top of names.
        """

        def _read(table: str, key: str, value: str) -> dict[int, str]:
            if program.table(table) is None:
                return {}
            rows: dict[int, str] = {}
            for row in program.rows(table):
                identifier = row.get(key)
                name = row.get(value)
                if identifier is None or not name:
                    continue
                rows[int(identifier)] = str(name)
            return rows

        pointer: dict[int, int | None] = {}
        if program.table(POINTER_TYPES_TABLE) is not None:
            for row in program.rows(POINTER_TYPES_TABLE):
                identifier = row.get("Pointer ID")
                if identifier is None:
                    continue
                target = row.get("Data Type ID")
                pointer[int(identifier)] = None if target is None else int(target)

        array: dict[int, tuple[int | None, int | None]] = {}
        if program.table(ARRAY_TYPES_TABLE) is not None:
            for row in program.rows(ARRAY_TYPES_TABLE):
                identifier = row.get("Array ID")
                if identifier is None:
                    continue
                element = row.get("Data Type ID")
                dimension = row.get("Dimension")
                array[int(identifier)] = (
                    None if element is None else int(element),
                    None if dimension is None else int(dimension),
                )

        return cls(
            builtin=_read(BUILTIN_TYPES_TABLE, "Data Type ID", "Name"),
            composite=_read(COMPOSITE_TYPES_TABLE, "Data Type ID", "Name"),
            typedef=_read(TYPEDEF_TYPES_TABLE, "Typedef ID", "Name"),
            enum=_read(ENUM_TYPES_TABLE, "Enum ID", "Name"),
            function_def=_read(FUNCTION_DEF_TYPES_TABLE, "Data Type ID", "Name"),
            pointer=pointer,
            array=array,
            calling_conventions=_read(CALLING_CONVENTIONS_TABLE, "ID", "Name"),
        )

    def type_name(self, datatype_id: Any, *, _depth: int = 0) -> str | None:
        """Source-level name for a stored data-type id, or None when unknown.

        `undefined` is returned verbatim for `DEFAULT_DATATYPE_ID` so callers
        can distinguish "Ghidra's placeholder" from "this database does not
        contain that id" -- only the latter is None.
        """

        if datatype_id is None or _depth > _MAX_TYPE_DEPTH:
            return None
        identifier = int(datatype_id)
        if identifier == DEFAULT_DATATYPE_ID:
            return UNDEFINED_TYPE_NAME
        if identifier == NULL_DATATYPE_ID or identifier < 0:
            return None
        table = (identifier >> DT_TABLE_SHIFT) & 0xFF
        if table == DT_BUILT_IN:
            return self.builtin.get(identifier)
        if table == DT_COMPOSITE:
            return self.composite.get(identifier)
        if table == DT_TYPEDEF:
            return self.typedef.get(identifier)
        if table == DT_ENUM:
            return self.enum.get(identifier)
        if table == DT_FUNCTION_DEF:
            return self.function_def.get(identifier)
        if table == DT_POINTER:
            if identifier not in self.pointer:
                return None
            inner = self.type_name(self.pointer[identifier], _depth=_depth + 1)
            return GENERIC_POINTER_NAME if inner is None else f"{inner} *"
        if table == DT_ARRAY:
            element, dimension = self.array.get(identifier, (None, None))
            inner = self.type_name(element, _depth=_depth + 1)
            if inner is None or dimension is None:
                return None
            return f"{inner}[{dimension}]"
        return None

    def calling_convention(self, convention_id: Any) -> str | None:
        """`__thiscall` / `__stdcall` / ... for a stored id, else None.

        Ghidra reserves the low ids for "unknown" and "default"; they are not
        in the table and are reported as None rather than invented, because a
        wrong calling convention changes the ABI of every generated candidate.
        """

        if convention_id is None:
            return None
        return self.calling_conventions.get(int(convention_id))


@dataclass(frozen=True)
class CuratedParameter:
    """One curated parameter: its declared type, and its name when curated."""

    ordinal: int
    name: str | None
    type_name: str | None

    @property
    def slot(self) -> str | None:
        return param_slot_name(self.ordinal)

    def to_json(self) -> dict[str, Any]:
        return {"ordinal": self.ordinal, "name": self.name, "type": self.type_name, "slot": self.slot}


@dataclass(frozen=True)
class CuratedSignature:
    """A function's curated identity and prototype, keyed by entry VA.

    `signature` is None whenever the prototype must not be trusted -- either
    nothing was curated, or `arity_check` came back contradicted. `name` and
    `qualified_name` survive in both cases: a name is evidence even when a
    prototype is not.
    """

    entry: int
    name: str
    qualified_name: str
    namespace: str | None
    calling_convention: str | None
    return_type: str | None
    parameters: tuple[CuratedParameter, ...]
    stack_purge: int | None
    arity_check: str
    signature: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualifiedName": self.qualified_name,
            "namespace": self.namespace,
            "callingConvention": self.calling_convention,
            "returnType": self.return_type,
            "parameters": [item.to_json() for item in self.parameters],
            "stackPurge": self.stack_purge,
            "arityCheck": self.arity_check,
            "signature": self.signature,
        }


def parameter_list_text(parameters: Iterable[CuratedParameter]) -> str:
    """`(int, CExoString *)` -- the shape `symbol_map.msvc_stack_arg_bytes` parses.

    An unresolved parameter type becomes `undefined`, which that parser does
    not recognise, so the arity check degrades to "undecidable" instead of
    silently assuming four bytes.
    """

    inner = ", ".join(item.type_name or UNDEFINED_TYPE_NAME for item in parameters)
    return f"({inner})"


def signature_text(
    *,
    qualified_name: str,
    calling_convention: str | None,
    return_type: str | None,
    parameters: Iterable[CuratedParameter],
) -> str:
    """A C-style prototype line for a curated function.

    The return type is omitted when Ghidra stored its `undefined` placeholder:
    printing `undefined` would assert a type the curator never chose.
    """

    params = ", ".join(
        " ".join(part for part in (item.type_name or UNDEFINED_TYPE_NAME, item.name) if part)
        for item in parameters
    )
    prefix = "" if return_type in (None, UNDEFINED_TYPE_NAME) else f"{return_type} "
    convention = f"{calling_convention} " if calling_convention else ""
    return f"{prefix}{convention}{qualified_name}({params})"


def namespace_paths(program: GhidraProgram) -> dict[int, str]:
    """`{namespaceSymbolId: "Outer::Inner"}` for class and namespace symbols.

    Ghidra parents a class method's function symbol to the class symbol, so the
    engine class of a method is only recoverable through this join -- the
    function row itself stores the bare method name.
    """

    raw: dict[int, tuple[str, int]] = {}
    for symbol in program.symbols(types=(SymbolType.CLASS, SymbolType.NAMESPACE), named_only=True):
        raw[symbol.symbol_id] = (symbol.name, symbol.namespace_id)

    resolved: dict[int, str] = {}

    def resolve(symbol_id: int, seen: frozenset[int]) -> str | None:
        if symbol_id in resolved:
            return resolved[symbol_id]
        entry = raw.get(symbol_id)
        if entry is None or symbol_id in seen:
            return None
        name, parent_id = entry
        parent = resolve(parent_id, seen | {symbol_id}) if parent_id else None
        path = f"{parent}::{name}" if parent else name
        resolved[symbol_id] = path
        return path

    for symbol_id in raw:
        resolve(symbol_id, frozenset())
    return resolved


def build_curated_signature(
    function: Any,
    *,
    parameters: list[CuratedParameter],
    namespace: str | None,
    types: CuratedTypeIndex,
) -> CuratedSignature:
    """One `CuratedSignature`, with the arity gate applied.

    The gate is `symbol_map.check_signature_arity`, the same rule mission note
    14 established for borrowed signatures: a 32-bit MSVC `__thiscall` or
    `__stdcall` callee cleans its own argument bytes, so the target's own
    `ret N` is an independent statement of its arity. When that contradicts the
    stored parameter list the prototype is dropped and only the name survives.
    """

    name = str(function.name or "")
    qualified = f"{namespace}::{name}" if namespace else name
    convention = types.calling_convention(function.calling_convention_id)
    return_type = types.type_name(function.return_datatype_id)
    purge = function.stack_purge
    # `check_signature_arity` already reports None/unknown purge as undecidable;
    # substituting 0 here would read "cleans no arguments" and manufacture
    # contradictions on every function whose purge Ghidra never determined.
    arity = check_signature_arity(parameter_list_text(parameters), name, purge, convention or "")
    has_prototype = bool(convention or parameters or (return_type not in (None, UNDEFINED_TYPE_NAME)))
    signature = None
    if has_prototype and arity != ARITY_CONTRADICTED:
        signature = signature_text(
            qualified_name=qualified,
            calling_convention=convention,
            return_type=return_type,
            parameters=parameters,
        )
    return CuratedSignature(
        entry=int(function.entry),
        name=name,
        qualified_name=qualified,
        namespace=namespace,
        calling_convention=convention,
        return_type=None if return_type == UNDEFINED_TYPE_NAME else return_type,
        parameters=tuple(parameters),
        stack_purge=None if purge is None else int(purge),
        arity_check=arity,
        signature=signature,
    )


def build_curated_signatures(program: GhidraProgram) -> dict[int, CuratedSignature]:
    """Curated prototypes keyed by function entry VA.

    Functions with an empty stored name are skipped: Ghidra synthesises their
    `FUN_00401000` label at display time, so there is no curated identity to
    carry and the prototype alone would rename nothing.
    """

    types = CuratedTypeIndex.from_program(program)
    namespaces = namespace_paths(program)
    parameters_by_symbol = parameter_symbols_by_function(program)

    signatures: dict[int, CuratedSignature] = {}
    for function in program.functions():
        if function.entry is None or not function.name:
            continue
        parameters = curated_parameters_for_function(parameters_by_symbol.get(function.symbol_id, []), types)
        signatures[function.entry] = build_curated_signature(
            function,
            parameters=parameters,
            namespace=namespaces.get(function.namespace_id),
            types=types,
        )
    return signatures


def parameter_symbols_by_function(program: GhidraProgram) -> dict[int, list[LocalVariable]]:
    """Every PARAMETER symbol grouped by owning function symbol id, named or not.

    `GhidraProgram.locals_by_function` filters to *named* symbols, which is
    right for its purpose (renaming `param_1` in emitted source) and wrong for
    this one: on the curated KOTOR project only 2,962 of 22,578 parameters
    carry a curated name, but 22,551 carry a curated *type*. Dropping the
    unnamed ones would erase almost the whole prototype and, worse, would make
    a `__thiscall` with one stack argument look like it took none -- which the
    arity gate would then read as a contradiction and discard.
    """

    grouped: dict[int, list[LocalVariable]] = {}
    for symbol in program.symbols(types=(SymbolType.PARAMETER,)):
        grouped.setdefault(symbol.namespace_id, []).append(
            LocalVariable(
                symbol_id=symbol.symbol_id,
                name=symbol.name,
                function_symbol_id=symbol.namespace_id,
                symbol_type=symbol.symbol_type,
                ordinal=symbol.variable_offset,
                datatype_id=symbol.datatype_id,
            )
        )
    return grouped


def curated_parameters_for_function(
    variables: list[LocalVariable],
    types: CuratedTypeIndex,
) -> list[CuratedParameter]:
    """Declared parameters in ordinal order, typed via `types`.

    Unlike `curated_params_for_function` (names only, for source rewriting)
    this keeps unnamed parameters: an unnamed but *typed* parameter still
    carries the ABI shape, which is the part a candidate has to get right.
    """

    parameters: list[CuratedParameter] = []
    for variable in variables:
        if variable.symbol_type != SymbolType.PARAMETER:
            continue
        ordinal = variable.ordinal
        if ordinal is None or ordinal < 0:
            continue
        parameters.append(
            CuratedParameter(
                ordinal=int(ordinal),
                name=variable.name or None,
                type_name=types.type_name(variable.datatype_id),
            )
        )
    parameters.sort(key=lambda item: item.ordinal)
    return parameters


def curated_signatures_to_json(signatures: dict[int, CuratedSignature]) -> dict[str, dict[str, Any]]:
    """Entry-hex-keyed view, the on-disk shape `curated_project` persists."""

    keyed: dict[str, dict[str, Any]] = {}
    for entry, signature in signatures.items():
        key = normalize_entry_key(entry)
        if key is None:
            continue
        keyed[key] = signature.to_json()
    return keyed


# ---------------------------------------------------------------------------
# Making a curated __thiscall decompile compilable
# ---------------------------------------------------------------------------

#: Ghidra opens a decompiled function body with a bare `{` at column 0, which is
#: the only reliable boundary between a (possibly line-wrapped) signature and a
#: body that may itself mention `__thiscall` inside a function-pointer cast.
_BODY_ANCHOR = "\n{"

#: The dead EDX argument that turns MSVC `__fastcall` into `__thiscall`.
THISCALL_SHIM_PARAMETER = "int __edx_unused"


def _matching_paren(text: str, open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def msvc_thiscall_to_fastcall(text: str) -> str:
    """Rewrite a Ghidra `__thiscall` signature into something MSVC will compile.

    MSVC rejects `__thiscall` on a free function -- in C with
    ``error C2061: syntax error``, in C++ with ``error C3865: '__thiscall' :
    can only be used on native member functions`` -- so the decompiler's own
    text for a `__thiscall` method never reaches the objdiff gate at all.

    32-bit `__fastcall` with a dead second parameter has the identical ABI:
    `this` in ECX, the dead argument in EDX, every real argument on the stack
    in order, callee-cleaned `ret N`. Verified byte-identical against a C++
    member function and against the shipped target bytes for
    `CAppManager::GetObjectTableManager` (0x401060).

    Returns `text` unchanged when it declares no `__thiscall` function, so this
    is safe to apply to every candidate.
    """

    anchor = text.find(_BODY_ANCHOR)
    head = text if anchor < 0 else text[:anchor]
    convention_at = head.find("__thiscall")
    if convention_at < 0:
        return text
    open_index = head.find("(", convention_at)
    if open_index < 0:
        return text
    close_index = _matching_paren(head, open_index)
    if close_index is None:
        return text
    inner = head[open_index + 1 : close_index]
    parameters = _split_top_level_commas(inner)
    if not parameters or parameters[0].strip() in ("", "void"):
        # A `__thiscall` with no parameters has no `this` to keep in ECX; the
        # rewrite would invent one, so leave the text alone and let it fail
        # honestly at compile time rather than silently change its meaning.
        return text
    rest = ", ".join(part.strip() for part in parameters[1:])
    tail = f", {rest}" if rest else ""
    rewritten_head = (
        head[:convention_at]
        + "__fastcall"
        + head[convention_at + len("__thiscall") : open_index + 1]
        + f"{parameters[0].strip()}, {THISCALL_SHIM_PARAMETER}{tail}"
        + head[close_index:]
    )
    return rewritten_head + (text[anchor:] if anchor >= 0 else "")


def _split_top_level_commas(text: str) -> list[str]:
    """Split a C parameter list on top-level commas.

    Kept separate from `symbol_map`'s splitter: that one parses *demangled*
    parameter lists, this one parses emitted C declarators, which can carry
    array brackets and function-pointer parentheses.
    """

    parts: list[str] = []
    depth = 0
    current = ""
    for char in text:
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts
