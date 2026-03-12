"""MCP resource providers – Python implementations for resources/list and resources/read.

ProgramListResource (ghidra://programs), StaticAnalysisResultsResource (SARIF),
DebugInfoResource (unified debug/session state), AnalysisDumpResource (bulk analysis JSON).
ResourceProviderManager registers these and dispatches read_resource by URI.
"""

from .programs import ProgramListResource
from .static_analysis import StaticAnalysisResultsResource
from .debug_info import DebugInfoResource
from .analysis_dump import AnalysisDumpResource

__all__ = [
    "AnalysisDumpResource",
    "DebugInfoResource",
    "ProgramListResource",
    "StaticAnalysisResultsResource",
]
