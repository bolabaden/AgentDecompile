from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    """Represents a single function decompiled by Ghidra."""

    name: str = Field(..., description="The name of the function.")
    code: str = Field(..., description="The decompiled pseudo-C code of the function.")
    signature: str | None = Field(None, description="The signature of the function.")


class ProgramBasicInfo(BaseModel):
    """Basic information about a program: name and analysis status"""

    name: str = Field(..., description="The name of the program.")
    analysis_complete: bool = Field(
        ...,
        description="Indicates if program is ready to be used.",
    )


class ProgramBasicInfos(BaseModel):
    """A container for a list of basic program information objects."""

    programs: list[ProgramBasicInfo] = Field(
        ...,
        description="A list of basic program information.",
    )


class ProgramInfo(BaseModel):
    """Detailed information about a program (binary) loaded in Ghidra."""

    name: str = Field(..., description="The name of the program in Ghidra.")
    file_path: str | None = Field(
        None,
        description="The file path of the program on disk.",
    )
    load_time: float | None = Field(
        None,
        description="The time it took to load the program in seconds.",
    )
    analysis_complete: bool = Field(
        ...,
        description="Indicates if Ghidra's analysis of the program has completed.",
    )
    metadata: dict = Field(
        ...,
        description="A dictionary of metadata associated with the program.",
    )
    code_collection: bool = Field(
        ...,
        description="True if the chromadb code collection is ready",
    )
    strings_collection: bool = Field(
        ...,
        description="True if the chromadb strings collection is ready",
    )


class ProgramInfos(BaseModel):
    """A container for a list of program information objects."""

    programs: list[ProgramInfo] = Field(
        ...,
        description="A list of program information objects.",
    )


class ExportInfo(BaseModel):
    """Represents a single exported function or symbol from a binary."""

    name: str = Field(..., description="The name of the export.")
    address: str = Field(..., description="The address of the export.")


class ExportInfos(BaseModel):
    """A container for a list of exports from a binary."""

    exports: list[ExportInfo] = Field(..., description="A list of exports.")


class ImportInfo(BaseModel):
    """Represents a single imported function or symbol."""

    name: str = Field(..., description="The name of the import.")
    library: str = Field(
        ...,
        description="The name of the library from which the symbol is imported.",
    )


class ImportInfos(BaseModel):
    """A container for a list of imports."""

    imports: list[ImportInfo] = Field(..., description="A list of imports.")


class SymbolInfo(BaseModel):
    """Represents a single symbol in a binary."""

    name: str = Field(..., description="The name of the symbol.")
    address: str = Field(..., description="The address of the symbol.")
    type: str = Field(..., description="The type of the symbol (e.g., FUNCTION, LABEL, etc.).")


class SymbolInfos(BaseModel):
    """A container for a list of symbol information objects."""

    symbols: list[SymbolInfo] = Field(..., description="A list of symbol information objects.")


class CrossReferenceInfo(BaseModel):
    """Represents a cross-reference (xref) to or from an address."""

    from_address: str = Field(..., description="The address where the reference originates.")
    to_address: str = Field(..., description="The address being referenced.")
    reference_type: str = Field(..., description="The type of reference (e.g., FLOW, READ, WRITE).")
    is_primary: bool = Field(..., description="Whether this is a primary reference.")


class CrossReferenceInfos(BaseModel):
    """A container for a list of cross-reference information objects."""

    cross_references: list[CrossReferenceInfo] = Field(..., description="A list of cross-reference information.")


class CodeSearchResult(BaseModel):
    """Represents a single code search result."""

    function_name: str = Field(..., description="The name of the function containing the match.")
    code_preview: str = Field(..., description="A preview of the code containing the match.")
    match_snippet: str = Field(..., description="The matched code snippet.")
    similarity: float | None = Field(None, description="The similarity score (0-1) for semantic searches.")
    address: str = Field(..., description="The address of the function.")


class CodeSearchResults(BaseModel):
    """A container for a list of code search results."""

    results: list[CodeSearchResult] = Field(..., description="A list of code search results.")
    total_matches: int = Field(..., description="Total number of matches found.")


class SearchMode(str, Enum):
    """Represents the mode of code search."""

    LITERAL = "literal"
    SEMANTIC = "semantic"
    REGEX = "regex"


class StringInfo(BaseModel):
    """Represents a string found within the binary."""

    value: str = Field(..., description="The value of the string.")
    address: str = Field(..., description="The address of the string.")


class StringSearchResult(StringInfo):
    """Represents a string search result found within the binary."""

    similarity: float = Field(
        ...,
        description="The similarity score of the search result.",
    )


class StringSearchResults(BaseModel):
    """A container for a list of string search results."""

    strings: list[StringSearchResult] = Field(
        ...,
        description="A list of string search results.",
    )


class BytesReadResult(BaseModel):
    """Represents the result of reading raw bytes from memory."""

    address: str = Field(
        ...,
        description="The normalized address where bytes were read from.",
    )
    size: int = Field(..., description="The actual number of bytes read.")
    data: str = Field(..., description="The raw bytes as a hexadecimal string.")


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    """Represents the result of a mermaidjs call graph generation."""

    function_name: str = Field(
        ...,
        description="The name of the function for which the call graph was generated.",
    )
    direction: CallGraphDirection = Field(
        ...,
        description="The direction of the call graph (calling or called).",
    )
    display_type: CallGraphDisplayType = Field(
        ...,
        description="The type of the call graph visualization.",
    )
    graph: str = Field(
        ...,
        description="The MermaidJS markdown string for the call graph.",
    )
    mermaid_url: str = Field(..., description="The MermaidJS image url")
