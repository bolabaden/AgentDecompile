"""Pure-Python reader for Ghidra project databases -- no JVM, no PyGhidra.

Why this exists: every other path into a Ghidra project in this repo requires a
JVM, and `ghidra_context.py` explicitly refuses to read `.rep` internals. That
means a curated project -- years of manual naming, typing and commenting -- is
invisible to the recovery loop, which re-derives everything from raw bytes on
every run and emits `undefined4 sub_12abe0(...)` as a result.

Reading is deliberately one-way. Nothing in this package writes to a project.

Layering (each depends only on the ones above it):

    buffer_file    .gbf container: header, block addressing, free list
    chained_buffer records too large for one buffer, incl. XOR de-obfuscation
    fields         field codecs, schemas, sparse records
    master_table   DBParms -> master table -> table catalogue
    btree          node layouts, leaf-chain table scans
    address_map    encoded address longs -> real addresses
    program        typed accessors (symbols, comments, functions, memory)
    project        .gpr/.rep layout walking
    packed         .gzf front-end (same core: a .gbf inside a ZIP)

Format constants and layouts are derived from Ghidra's own Java sources
(Apache-2.0), read from the shipped `*-src.zip` files in a local install. Each
module cites the specific class it mirrors.
"""

from __future__ import annotations

from .buffer_file import BufferFile, BufferFileError, BufferFileHeader
from .packed import (
    PackedFileError,
    PackedItemHeader,
    extract_database,
    is_packed_file,
    open_packed_database,
    read_packed_header,
)
from .program import (
    CommentSet,
    CompositeDataType,
    Function,
    GhidraProgram,
    GhidraProgramError,
    LocalVariable,
    MemoryBlock,
    ProgramMetadata,
    Symbol,
    SymbolType,
    open_program,
)
from .project import (
    ProgramEntry,
    ProjectLayoutError,
    VersionInfo,
    find_program,
    iter_program_entries,
    list_programs,
    open_project_program,
    resolve_project_root,
)

__all__ = [
    "BufferFile",
    "BufferFileError",
    "BufferFileHeader",
    "CommentSet",
    "CompositeDataType",
    "Function",
    "GhidraProgram",
    "GhidraProgramError",
    "LocalVariable",
    "MemoryBlock",
    "PackedFileError",
    "PackedItemHeader",
    "ProgramEntry",
    "ProgramMetadata",
    "ProjectLayoutError",
    "VersionInfo",
    "Symbol",
    "SymbolType",
    "extract_database",
    "find_program",
    "is_packed_file",
    "iter_program_entries",
    "list_programs",
    "open_packed_database",
    "open_program",
    "open_project_program",
    "read_packed_header",
    "resolve_project_root",
]
