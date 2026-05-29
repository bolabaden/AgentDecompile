"""MCP tool providers – Python implementations of MCP tools.

Each provider registers HANDLERS (normalized tool name → method) and list_tools();
ToolProviderManager dispatches tools/call to the appropriate provider. Import
order here does not affect registration; all are collected by the manager.
"""

from .decompiler import DecompilerToolProvider
from .functions import FunctionToolProvider
from .symbols import SymbolToolProvider
from .memory import MemoryToolProvider
from .data import DataToolProvider
from .strings import StringToolProvider
from .structures import StructureToolProvider
from .enums import EnumToolProvider
from .xrefs import CrossReferencesToolProvider
from .comments import CommentToolProvider
from .conflict_resolution import ConflictResolutionToolProvider
from .bookmarks import BookmarkToolProvider
from .project import ProjectToolProvider
from .callgraph import CallGraphToolProvider
from .getfunction import GetFunctionToolProvider
from .import_export import ImportExportToolProvider
from .dataflow import DataFlowToolProvider
from .constants import ConstantSearchToolProvider
from .vtable import VtableToolProvider
from .script import ScriptToolProvider
from .search_everything import SearchEverythingToolProvider
from .suggestions import SuggestionToolProvider
from .datatypes import DataTypeToolProvider
from .dissect import GetFunctionAioToolProvider
from .batch_analysis import BatchAnalysisToolProvider
from .prompts import PromptToolProvider
from .static_analysis import StaticAnalysisToolProvider

__all__ = [
    "BookmarkToolProvider",
    "BatchAnalysisToolProvider",
    "CallGraphToolProvider",
    "CommentToolProvider",
    "ConflictResolutionToolProvider",
    "ConstantSearchToolProvider",
    "CrossReferencesToolProvider",
    "DataFlowToolProvider",
    "DataToolProvider",
    "DataTypeToolProvider",
    "DecompilerToolProvider",
    "FunctionToolProvider",
    "GetFunctionAioToolProvider",
    "GetFunctionToolProvider",
    "ImportExportToolProvider",
    "MemoryToolProvider",
    "ProjectToolProvider",
    "ScriptToolProvider",
    "StaticAnalysisToolProvider",
    "PromptToolProvider",
    "SearchEverythingToolProvider",
    "StringToolProvider",
    "StructureToolProvider",
    "EnumToolProvider",
    "SuggestionToolProvider",
    "SymbolToolProvider",
    "VtableToolProvider",
]
