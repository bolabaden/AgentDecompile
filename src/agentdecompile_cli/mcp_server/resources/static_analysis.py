"""Static Analysis Results Resource Provider - ghidra://static-analysis-results.

Returns static analysis results for the current program as a SARIF 2.1.0 JSON report.
Used by IDEs/tools that consume SARIF for security or quality dashboards. When no
program is loaded, returns an empty SARIF report so the client always gets valid JSON.
"""

from __future__ import annotations

import json
import logging

from datetime import datetime, timezone
from itertools import islice
from typing import Any

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider

logger = logging.getLogger(__name__)


class StaticAnalysisResultsResource(ResourceProvider):
    """MCP resource provider for static analysis results formatted as SARIF 2.1.0."""

    def list_resources(self) -> list[types.Resource]:
        """Return list of static analysis resources."""
        return [
            types.Resource(
                uri=AnyUrl(url="ghidra://static-analysis-results"),
                name="Static Analysis Results",
                description="Results from static analysis of the current program (SARIF 2.1.0)",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the static analysis results resource as SARIF 2.1.0 JSON."""
        if str(uri) != "ghidra://static-analysis-results":
            raise NotImplementedError(f"Unknown resource: '{uri}'")

        logger.info("StaticAnalysisResultsResource: reading resource for URI %s", uri)
        logger.info(f"  program_info: '{self.program_info}'")
        logger.info(f"  program_info.program: '{self.program_info.program if self.program_info else 'N/A'}'")

        # Check if program is loaded using correct attribute name
        has_program: bool = self.program_info is not None and getattr(self.program_info, "program", None) is not None
        logger.info("  has_program: '%s'", str(has_program))

        if not has_program:
            # Return empty SARIF report when no program is loaded
            logger.info("No program loaded for static analysis results, returning empty SARIF report")
            return json.dumps(self._empty_sarif_report(), indent=2)

        try:
            logger.info("Program loaded, generating SARIF report")
            sarif_report: dict[str, Any] = await self._generate_sarif_report()
            logger.info(f"SARIF report generated successfully, '{len(json.dumps(sarif_report))}' bytes length")
            return json.dumps(sarif_report, indent=2)
        except Exception as e:
            logger.error(f"Error generating SARIF report: '{e.__class__.__name__}: {e}'", exc_info=True)
            # Return empty SARIF with error information instead of raising
            empty_report: dict[str, Any] = self._empty_sarif_report()
            empty_report["runs"][0]["properties"]["error"] = f"'{e.__class__.__name__}: {e}'"
            empty_report["runs"][0]["properties"]["status"] = "error"
            return json.dumps(empty_report, indent=2)

    def _empty_sarif_report(self) -> dict[str, Any]:
        """Generate an empty SARIF 2.1.0 report when no program is loaded."""
        now: str = datetime.now(timezone.utc).isoformat() + "Z"

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentDecompile",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/bolabaden/agentdecompile",
                            "rules": [],
                        },
                    },
                    "artifacts": [],
                    "results": [],
                    "properties": {
                        "analysisComplete": False,
                        "generatedAt": now,
                        "programPath": None,
                        "status": "no_program_loaded",
                        "message": "No program loaded. Results will be available after loading a program.",
                    },
                },
            ],
        }

    def _is_analysis_complete(self, program: Any) -> bool:
        """Return True if program analysis is complete; safe for ProgramDB and headless."""
        try:
            get_state = getattr(program, "getAnalysisState", None)
            if get_state is not None:
                state = get_state()
                if state is not None and hasattr(state, "isDone"):
                    return bool(state.isDone())
        except Exception:
            pass
        try:
            from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

            return bool(GhidraProgramUtilities.isAnalyzed(program))
        except Exception:
            return False

    async def _generate_sarif_report(self) -> dict[str, Any]:
        """Generate a SARIF 2.1.0 compliant static analysis report."""
        assert self.program_info is not None, "Program info is required to generate SARIF report"
        program: Any = self.program_info.program
        results: list[dict[str, Any]] = []

        # Collect various analysis results
        results.extend(await self._collect_undefined_references())
        results.extend(await self._collect_bookmarks())
        results.extend(await self._collect_analysis_warnings())

        now: str = datetime.now(timezone.utc).isoformat() + "Z"

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentDecompile",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/bolabaden/agentdecompile",
                            "rules": [
                                {
                                    "id": "undefined-reference",
                                    "name": "Undefined Reference",
                                    "shortDescription": {
                                        "text": "Reference to undefined function or symbol",
                                    },
                                    "defaultConfiguration": {"level": "warning"},
                                },
                                {
                                    "id": "analysis-bookmark",
                                    "name": "Analysis Bookmark",
                                    "shortDescription": {
                                        "text": "Code location marked with bookmark during analysis",
                                    },
                                    "defaultConfiguration": {"level": "note"},
                                },
                                {
                                    "id": "analysis-warning",
                                    "name": "Analysis Warning",
                                    "shortDescription": {
                                        "text": "Warning generated during program analysis",
                                    },
                                    "defaultConfiguration": {"level": "warning"},
                                },
                            ],
                        },
                    },
                    "artifacts": [
                        {
                            "uri": str(program.getName()),
                            "sourceLanguage": "asm",
                            "properties": {
                                "imageBase": hex(program.getImageBase().getOffset()),
                            },
                        },
                    ],
                    "results": results,
                    "properties": {
                        "analysisComplete": self._is_analysis_complete(program),
                        "generatedAt": now,
                        "programPath": str(self.program_info.file_path) if self.program_info.file_path else "unknown",
                    },
                },
            ],
        }

    async def _collect_undefined_references(self) -> list[dict[str, Any]]:
        """Collect results for undefined references."""
        results: list[dict[str, Any]] = []
        assert self.program_info is not None, "Program info is required to collect undefined references"
        program: Any = self.program_info.program
        ref_mgr: Any = program.getReferenceManager()

        try:
            # Iterate through references to find undefined references
            for ref in islice(ref_mgr.getExternalReferences(), 50):  # Limit results
                if ref and ref.getToAddress():
                    results.append(
                        {
                            "ruleId": "undefined-reference",
                            "kind": "fail",
                            "level": "warning",
                            "message": {
                                "text": f"External reference at {hex(ref.getFromAddress().getOffset())} to {ref.getLabel()}",
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactIndex": 0,
                                        "address": hex(ref.getFromAddress().getOffset()),
                                    },
                                },
                            ],
                        },
                    )
        except Exception as e:
            logger.debug(f"Error collecting undefined references: '{e.__class__.__name__}: {e}'")

        return results

    async def _collect_bookmarks(self) -> list[dict[str, Any]]:
        """Collect results from bookmarks added during analysis."""
        results: list[dict[str, Any]] = []
        assert self.program_info is not None, "Program info is required to collect bookmarks"
        program: Any = self.program_info.program
        bookmark_mgr = program.getBookmarkManager()

        try:
            # Get all bookmarks
            bookmarks: Any = bookmark_mgr.getBookmarks("Analysis")
            if bookmarks:
                for bookmark in islice(bookmarks, 30):  # Limit results
                    if bookmark:
                        address: Any = bookmark.getAddress()
                        category: Any = bookmark.getCategory()
                        comment: Any = bookmark.getComment()

                        results.append(
                            {
                                "ruleId": "analysis-bookmark",
                                "kind": "informational",
                                "level": "note",
                                "message": {
                                    "text": f"Bookmark: {comment or category}",
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactIndex": 0,
                                            "address": hex(address.getOffset()),
                                        },
                                    },
                                ],
                            },
                        )
        except Exception as e:
            logger.debug(f"Error collecting bookmarks: '{e.__class__.__name__}: {e}'")

        return results

    async def _collect_analysis_warnings(self) -> list[dict[str, Any]]:
        """Collect analysis warnings (functions with issues, etc.)."""
        results: list[dict[str, Any]] = []
        assert self.program_info is not None, "Program info is required to collect analysis warnings"
        program: Any = self.program_info.program

        try:
            func_mgr: Any = program.getFunctionManager()
            func_count: int = 0

            # Scan for problematic functions
            for func in func_mgr.getFunctions(True):
                func_count += 1
                if func_count > 50:  # Limit scan
                    break

                # Check for thunk functions (often generated)
                if func.isThunk():
                    results.append(
                        {
                            "ruleId": "analysis-warning",
                            "kind": "pass",
                            "level": "note",
                            "message": {
                                "text": f"Thunk function: {func.getName()}",
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactIndex": 0,
                                        "address": hex(func.getEntryPoint().getOffset()),
                                    },
                                },
                            ],
                        },
                    )

                # Check for external functions
                if func.isExternal():
                    results.append(
                        {
                            "ruleId": "analysis-warning",
                            "kind": "pass",
                            "level": "note",
                            "message": {
                                "text": f"External function: {func.getName()}",
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactIndex": 0,
                                        "address": hex(func.getEntryPoint().getOffset()),
                                    },
                                },
                            ],
                        },
                    )
        except Exception as e:
            logger.debug(f"Error collecting analysis warnings: '{e.__class__.__name__}: {e}'")

        return results
