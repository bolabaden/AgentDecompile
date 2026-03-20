"""MCP resource providers – Python implementations for resources/list and resources/read.

ProgramListResource (ghidra://programs), StaticAnalysisResultsResource (SARIF),
DebugInfoResource (unified debug/session state), AnalysisDumpResource (bulk analysis JSON),
ToolOutputResource (agentdecompile://<tool-name> for no-arg / program_path-only tools),
MermaidFlowchartResource (agentdecompile://mermaid-flowchart for function/call flowchart).
ResourceProviderManager registers these and dispatches read_resource by URI.
"""

from .programs import ProgramListResource
from .static_analysis import StaticAnalysisResultsResource
from .debug_info import DebugInfoResource
from .analysis_dump import AnalysisDumpResource
from .tool_resources import ToolOutputResource
from .mermaid_flowchart import MermaidFlowchartResource

__all__ = [
    "AnalysisDumpResource",
    "DebugInfoResource",
    "MermaidFlowchartResource",
    "ProgramListResource",
    "StaticAnalysisResultsResource",
    "ToolOutputResource",
]
