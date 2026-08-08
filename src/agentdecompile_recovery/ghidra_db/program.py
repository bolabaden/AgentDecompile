"""Typed accessors over a Ghidra program database.

Mirrors the read paths of ``ghidra.program.database.ProgramDB``,
``ghidra.program.database.symbol.SymbolDatabaseAdapter``,
``ghidra.program.database.function.FunctionAdapter``,
``ghidra.program.database.code.CommentsDBAdapter`` and
``ghidra.program.database.mem.MemoryMapDBAdapter`` (Apache-2.0).

Everything below is a join over tables the lower layers already read. It exists
so that no consumer re-implements the join itself -- in particular the address
decode, which is the one step where a plausible-looking mistake produces wrong
answers instead of errors.

The hazard, concretely: `Symbols.Address` is an encoded long whose top nibble is
an address *type*. Type 5 (external) stores an import ordinal, not an offset. In
the curated Odyssey project 343 of 27,318 function symbols are OpenGL/WGL
imports with ordinals like 0x4 and 0xa. Added to the image base they look like
valid `.text` addresses and would silently attach `glDepthMask` to whatever real
function happens to live at 0x400004. So a virtual address is produced only for
`DecodedAddress.is_memory`; everything else is excluded from the joins and
counted separately rather than quietly dropped.

Observed on the curated Odyssey database (swkotor2.exe, image base 0x400000):

    27,318  Function Data rows, one per function symbol
    26,975  function symbols whose address decodes to real memory
       343  function symbols that are externals (excluded)
    25,586  of the 26,975 that carry a curated name; the other 1,389 store an
            empty name and get a `FUN_<address>` label synthesised by Ghidra at
            display time, so they are not curated knowledge
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Iterable, Iterator

from .address_map import AddressMap, DecodedAddress
from .buffer_file import BufferFile
from .master_table import TableRecord, find_table, iter_rows

# Table names, as written by ProgramDB and its adapters.
PROGRAM_TABLE = "Program"
ADDRESS_MAP_TABLE = "ADDRESS MAP"
SYMBOLS_TABLE = "Symbols"
FUNCTION_DATA_TABLE = "Function Data"
COMMENTS_TABLE = "Comments"
MEMORY_BLOCKS_TABLE = "Memory Blocks"
COMPOSITE_DATA_TYPES_TABLE = "Composite Data Types"

# ProgramDB string-map keys.
IMAGE_OFFSET_KEY = "Image Offset"
PROGRAM_NAME_KEY = "Program Name"
LANGUAGE_ID_KEY = "Language ID"
COMPILER_SPEC_KEY = "Compiler Spec ID"
DB_VERSION_KEY = "DB Version"

# ghidra.program.database.code.CommentsDBAdapter column order.
COMMENT_KINDS = ("EOL", "Pre", "Post", "Plate", "Repeatable")


class GhidraProgramError(Exception):
    """Raised when a program database is missing something the join needs."""


class SymbolType(IntEnum):
    """Symbol type ids, from ``ghidra.program.model.symbol.SymbolType``.

    The ids are not contiguous -- there is no 2 -- because the enum's numbering
    is historical. They are read from the file, so they are transcribed rather
    than renumbered.
    """

    LABEL = 0
    LIBRARY = 1
    NAMESPACE = 3
    CLASS = 4
    FUNCTION = 5
    PARAMETER = 6
    LOCAL_VAR = 7
    GLOBAL_VAR = 8


def comment_texts(row: dict[str, Any]) -> dict[str, str]:
    """The non-empty comments in one Comments row.

    A row survives the deletion of its comments, so most stored kinds are None
    and some are the empty string; both mean "no comment" and are dropped rather
    than carried into emitted source as blank `/* */`.
    """

    return {kind: row[kind] for kind in COMMENT_KINDS if row.get(kind)}


def symbol_type_name(value: int | None) -> str:
    """Readable name for a symbol type id, without hiding unknown ids."""

    if value is None:
        return "none"
    try:
        return SymbolType(value).name.lower()
    except ValueError:
        return f"unknown({value})"


@dataclass(frozen=True)
class ProgramMetadata:
    """The `Program` string-map table: how to interpret every address below."""

    image_base: int
    program_name: str | None
    language_id: str | None
    compiler_spec_id: str | None
    db_version: str | None
    raw: dict[str, str]

    def to_json(self) -> dict[str, Any]:
        return {
            "imageBase": f"0x{self.image_base:x}",
            "programName": self.program_name,
            "languageId": self.language_id,
            "compilerSpecId": self.compiler_spec_id,
            "dbVersion": self.db_version,
        }


@dataclass(frozen=True)
class Symbol:
    """One row of the Symbols table with its address already decoded."""

    symbol_id: int
    name: str
    symbol_type: int
    namespace_id: int
    flags: int
    address: DecodedAddress | None
    entry: int | None
    datatype_id: int | None
    variable_offset: int | None

    @property
    def type_name(self) -> str:
        return symbol_type_name(self.symbol_type)

    @property
    def is_external(self) -> bool:
        """An import: it has an address long, but not one that denotes memory."""

        return self.address is not None and not self.address.is_memory

    @property
    def has_curated_name(self) -> bool:
        """Whether a human (or an analyzer) actually stored a name.

        An empty name means Ghidra synthesises `FUN_00401000` / `LAB_...` at
        display time. Carrying that forward would be worse than useless: it
        looks like curated knowledge and says nothing.
        """

        return bool(self.name)


@dataclass(frozen=True)
class Function:
    """A function symbol joined to its Function Data row.

    `entry` is None only when `include_external=True` was passed to
    `GhidraProgram.functions()`; by default such rows are not produced at all.
    """

    symbol_id: int
    name: str
    entry: int | None
    namespace_id: int
    return_datatype_id: int | None
    stack_purge: int | None
    stack_return_offset: int | None
    stack_local_size: int | None
    flags: int | None
    calling_convention_id: int | None
    address: DecodedAddress | None

    @property
    def is_external(self) -> bool:
        return self.entry is None

    @property
    def has_curated_name(self) -> bool:
        return bool(self.name)

    def to_json(self) -> dict[str, Any]:
        return {
            "symbolId": self.symbol_id,
            "name": self.name,
            "entry": None if self.entry is None else f"0x{self.entry:x}",
            "isExternal": self.is_external,
            "returnDataTypeId": self.return_datatype_id,
            "stackPurge": self.stack_purge,
            "callingConventionId": self.calling_convention_id,
        }


@dataclass(frozen=True)
class CommentSet:
    """Every comment kind stored at one address; empty kinds are dropped."""

    entry: int
    comments: dict[str, str]

    def get(self, kind: str) -> str | None:
        return self.comments.get(kind)


@dataclass(frozen=True)
class LocalVariable:
    """A curated parameter or local-variable name and its owning function.

    The owning function is the symbol's *namespace*: Ghidra parents variable
    symbols to the function symbol rather than storing a function column.
    """

    symbol_id: int
    name: str
    function_symbol_id: int
    symbol_type: int
    ordinal: int | None
    datatype_id: int | None

    @property
    def is_parameter(self) -> bool:
        return self.symbol_type == SymbolType.PARAMETER

    @property
    def type_name(self) -> str:
        return symbol_type_name(self.symbol_type)


@dataclass(frozen=True)
class MemoryBlock:
    """One row of the Memory Blocks table, start address resolved to a VA."""

    name: str
    start: int
    length: int
    permissions: int
    comment: str | None

    @property
    def end(self) -> int:
        """Exclusive end address."""

        return self.start + self.length

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": f"0x{self.start:x}",
            "length": self.length,
            "permissions": self.permissions,
        }


@dataclass(frozen=True)
class CompositeDataType:
    """A struct or union declared in the program's own data type manager."""

    datatype_id: int
    name: str
    is_union: bool
    length: int | None
    component_count: int | None
    comment: str | None


class GhidraProgram:
    """Read-only façade over one program database (`db.N.gbf`).

    Tables are located and read lazily: opening a program touches only the
    buffer-file header, and each accessor streams the rows it needs. The one
    deliberate exception is `functions()`, which must materialise the Function
    Data keys (27,318 ints on the curated project) because the join runs the
    other way -- Function Data is keyed by symbol id, and the Symbols table is
    the side worth streaming, being eight times larger.

    Nothing here writes. The file is opened read-only and closed by `close()`
    or the context manager.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.buffer_file = BufferFile(self.path)
        self._tables: dict[str, TableRecord | None] = {}
        self._metadata: ProgramMetadata | None = None
        self._address_map: AddressMap | None = None

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.buffer_file.close()

    def __enter__(self) -> "GhidraProgram":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"GhidraProgram({str(self.path)!r})"

    # -- table lookup ------------------------------------------------------

    def table(self, name: str) -> TableRecord | None:
        """Locate a table by name, caching the (linear) catalogue scan."""

        if name not in self._tables:
            self._tables[name] = find_table(self.buffer_file, name)
        return self._tables[name]

    def require_table(self, name: str) -> TableRecord:
        table = self.table(name)
        if table is None:
            raise GhidraProgramError(f"{self.path}: no {name!r} table; not a program database?")
        return table

    def rows(self, name: str) -> Iterator[dict[str, Any]]:
        """Stream decoded rows of a table by name."""

        return iter_rows(self.buffer_file, self.require_table(name))

    # -- metadata ----------------------------------------------------------

    @property
    def metadata(self) -> ProgramMetadata:
        if self._metadata is None:
            self._metadata = self._read_metadata()
        return self._metadata

    def _read_metadata(self) -> ProgramMetadata:
        table = self.require_table(PROGRAM_TABLE)
        schema = table.schema()
        raw: dict[str, str] = {}
        for row in iter_rows(self.buffer_file, table):
            key = row.get(schema.key_name)
            value = row.get("Value")
            if key is not None:
                raw[str(key)] = "" if value is None else str(value)

        image_text = raw.get(IMAGE_OFFSET_KEY)
        if image_text is None:
            raise GhidraProgramError(
                f"{self.path}: Program table has no {IMAGE_OFFSET_KEY!r}; every "
                "relocatable address would be off by the image base"
            )
        try:
            # Stored as hex text without an 0x prefix, e.g. "400000".
            image_base = int(image_text, 16)
        except ValueError as exc:
            raise GhidraProgramError(
                f"{self.path}: {IMAGE_OFFSET_KEY} {image_text!r} is not hexadecimal"
            ) from exc

        return ProgramMetadata(
            image_base=image_base,
            program_name=raw.get(PROGRAM_NAME_KEY),
            language_id=raw.get(LANGUAGE_ID_KEY),
            compiler_spec_id=raw.get(COMPILER_SPEC_KEY),
            db_version=raw.get(DB_VERSION_KEY),
            raw=raw,
        )

    @property
    def image_base(self) -> int:
        return self.metadata.image_base

    @property
    def program_name(self) -> str | None:
        return self.metadata.program_name

    @property
    def language_id(self) -> str | None:
        return self.metadata.language_id

    @property
    def address_map(self) -> AddressMap:
        if self._address_map is None:
            table = self.require_table(ADDRESS_MAP_TABLE)
            self._address_map = AddressMap.from_rows(iter_rows(self.buffer_file, table))
        return self._address_map

    # -- addresses ---------------------------------------------------------

    def decode_address(self, value: int | None) -> DecodedAddress | None:
        return self.address_map.decode(value)

    def virtual_address(self, value: int | None) -> int | None:
        """Virtual address for an encoded long, or None when it is not memory.

        This is the single chokepoint the module docstring is about: registers,
        stack slots, externals, variables and hashes all return None here.
        """

        return self.address_map.absolute_of(value, self.image_base)

    # -- symbols -----------------------------------------------------------

    def symbols(self, types: Iterable[int] | None = None, *, named_only: bool = False) -> Iterator[Symbol]:
        """Stream symbols, optionally restricted to given `SymbolType` values."""

        wanted = None if types is None else {int(value) for value in types}
        for row in self.rows(SYMBOLS_TABLE):
            symbol_type = row.get("Symbol Type")
            if wanted is not None and symbol_type not in wanted:
                continue
            name = row.get("Name") or ""
            if named_only and not name:
                continue
            address = self.decode_address(row.get("Address"))
            yield Symbol(
                symbol_id=int(row["Key"]),
                name=name,
                symbol_type=int(symbol_type or 0),
                namespace_id=int(row.get("Namespace") or 0),
                flags=int(row.get("Flags") or 0),
                address=address,
                entry=None if address is None else address.absolute(self.image_base),
                datatype_id=row.get("Datatype"),
                variable_offset=row.get("Variable Offset"),
            )

    # -- functions ---------------------------------------------------------

    def functions(self, *, include_external: bool = False) -> Iterator[Function]:
        """Stream every function: its symbol, entry VA, and Function Data row.

        Externals are omitted by default. They are real rows in the database but
        they have no address in this program, so including them in a
        VA-keyed map would either lose them or corrupt it.

        A function symbol with no Function Data row still yields a Function with
        the signature fields set to None: the name and entry are the curated
        knowledge worth carrying, and dropping the row would silently shrink the
        result on databases written by other Ghidra versions.
        """

        function_data = self._read_function_data()
        for symbol in self.symbols(types=(SymbolType.FUNCTION,)):
            entry = symbol.entry if symbol.address is not None and symbol.address.is_memory else None
            if entry is None and not include_external:
                continue
            data = function_data.get(symbol.symbol_id)
            yield Function(
                symbol_id=symbol.symbol_id,
                name=symbol.name,
                entry=entry,
                namespace_id=symbol.namespace_id,
                return_datatype_id=None if data is None else data[0],
                stack_purge=None if data is None else data[1],
                stack_return_offset=None if data is None else data[2],
                stack_local_size=None if data is None else data[3],
                flags=None if data is None else data[4],
                calling_convention_id=None if data is None else data[5],
                address=symbol.address,
            )

    def _read_function_data(self) -> dict[int, tuple[Any, ...]]:
        """Function Data keyed by function *symbol* id.

        Only the six columns callers need are kept; holding whole row dicts for
        27,318 functions costs an order of magnitude more memory for nothing.
        """

        data: dict[int, tuple[Any, ...]] = {}
        for row in self.rows(FUNCTION_DATA_TABLE):
            data[int(row["ID"])] = (
                row.get("Return DataType ID"),
                row.get("StackPurge"),
                row.get("StackReturnOffset"),
                row.get("StackLocalSize"),
                row.get("Flags"),
                row.get("Calling Convention ID"),
            )
        return data

    def names_by_entry(self, *, curated_only: bool = True) -> dict[int, str]:
        """`{virtualAddress: functionName}` -- the map the naming tier consumes.

        With `curated_only` (the default) functions that store an empty name are
        left out, because their displayed `FUN_00401000` is generated, not
        curated, and would overwrite nothing useful downstream.
        """

        names: dict[int, str] = {}
        for function in self.functions():
            if curated_only and not function.name:
                continue
            if function.entry is not None:
                names[function.entry] = function.name
        return names

    # -- comments ----------------------------------------------------------

    def comments(self) -> Iterator[CommentSet]:
        """Stream `{VA: {kind: text}}`, skipping addresses with nothing stored.

        A row exists for every address that ever held a comment, including ones
        whose comments were later deleted; those decode to all-None and are
        dropped rather than emitted as empty strings.
        """

        table = self.require_table(COMMENTS_TABLE)
        key_name = table.schema().key_name
        for row in iter_rows(self.buffer_file, table):
            entry = self.virtual_address(row.get(key_name))
            if entry is None:
                continue
            texts = comment_texts(row)
            if not texts:
                continue
            yield CommentSet(entry=entry, comments=texts)

    # -- locals ------------------------------------------------------------

    def locals_by_function(self) -> dict[int, list[LocalVariable]]:
        """Curated parameter and local names grouped by owning function symbol id.

        Unnamed variable symbols are excluded. They dominate the table -- on the
        curated Odyssey project 147,539 of 147,543 local-var symbols and 14,749
        of 16,981 parameter symbols store an empty name -- and an empty name
        carries no information the decompiler does not already invent.
        """

        grouped: dict[int, list[LocalVariable]] = {}
        variable_types = (SymbolType.PARAMETER, SymbolType.LOCAL_VAR)
        for symbol in self.symbols(types=variable_types, named_only=True):
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
        for variables in grouped.values():
            # Parameters first, in declaration order; locals after, by name.
            variables.sort(key=lambda item: (not item.is_parameter, item.ordinal if item.ordinal is not None else 0, item.name))
        return grouped

    # -- memory ------------------------------------------------------------

    def memory_blocks(self) -> list[MemoryBlock]:
        """Named memory blocks with start addresses resolved to VAs.

        Blocks whose start does not decode to memory are skipped: an overlay or
        an unmapped block has no VA to report and inventing one would produce a
        range that silently swallows address lookups.
        """

        blocks: list[MemoryBlock] = []
        for row in self.rows(MEMORY_BLOCKS_TABLE):
            start = self.virtual_address(row.get("Start Address"))
            if start is None:
                continue
            blocks.append(
                MemoryBlock(
                    name=str(row.get("Name") or ""),
                    start=start,
                    length=int(row.get("Length") or 0),
                    permissions=int(row.get("Permissions") or 0),
                    comment=row.get("Comments") or None,
                )
            )
        blocks.sort(key=lambda block: block.start)
        return blocks

    # -- data types --------------------------------------------------------

    def composite_data_types(self) -> Iterator[CompositeDataType]:
        """Structs and unions defined in this program's data type manager."""

        table = self.require_table(COMPOSITE_DATA_TYPES_TABLE)
        key_name = table.schema().key_name
        for row in iter_rows(self.buffer_file, table):
            yield CompositeDataType(
                datatype_id=int(row[key_name]),
                name=str(row.get("Name") or ""),
                is_union=bool(row.get("Is Union")),
                length=row.get("Length"),
                component_count=row.get("Number Of Components"),
                comment=row.get("Comment") or None,
            )

    # -- summary -----------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """A cheap description: metadata and memory layout, no full-table scans."""

        return {
            "path": str(self.path),
            "metadata": self.metadata.to_json(),
            "memoryBlocks": [block.to_json() for block in self.memory_blocks()],
        }


def open_program(path: Path | str) -> GhidraProgram:
    """Open a `db.N.gbf` as a program database."""

    return GhidraProgram(path)
