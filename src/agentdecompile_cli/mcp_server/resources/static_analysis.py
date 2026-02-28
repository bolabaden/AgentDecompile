"""Static Analysis Results Resource Provider - Python MCP implementation."""

from __future__ import annotations

import json
import logging
import re

from datetime import datetime
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
        if uri != "ghidra://static-analysis-results":
            raise NotImplementedError(f"Unknown resource: {uri}")

        if self.program_info is None or self.program_info.program is None:
            raise ValueError(
                "No program loaded. Use tool 'open' to load a program first.",
            )

        try:
            sarif_report = await self._generate_sarif_report()
            return json.dumps(sarif_report, indent=2)
        except Exception as e:
            logger.error(f"Error generating SARIF report: {e!s}")
            raise

    async def _generate_sarif_report(self) -> dict:
        """Generate a SARIF 2.1.0 compliant static analysis report."""
        program = self.program_info.program
        results = []

        # Collect various analysis results
        results.extend(await self._collect_undefined_references())
        results.extend(await self._collect_bookmarks())
        results.extend(await self._collect_analysis_warnings())

        now = datetime.utcnow().isoformat() + "Z"

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
                        "analysisComplete": program.getAnalysisState().isDone(),
                        "generatedAt": now,
                        "programPath": str(self.program_info.file_path)
                        if self.program_info.file_path
                        else "unknown",
                    },
                },
            ],
        }

    async def _collect_undefined_references(self) -> list[dict]:
        """Collect results for undefined references."""
        results = []
        program = self.program_info.program
        ref_mgr = program.getReferenceManager()
        sym_table = program.getSymbolTable()

        try:
            # Iterate through references to find undefined references
            for ref in list(ref_mgr.getExternalReferences())[:50]:  # Limit results
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
            logger.debug(f"Error collecting undefined references: {e!s}")

        return results

    async def _collect_bookmarks(self) -> list[dict]:
        """Collect results from bookmarks added during analysis."""
        results = []
        program = self.program_info.program
        bookmark_mgr = program.getBookmarkManager()

        try:
            # Get all bookmarks
            bookmarks = bookmark_mgr.getBookmarks("Analysis")
            if bookmarks:
                for bookmark in list(bookmarks)[:30]:  # Limit results
                    if bookmark:
                        address = bookmark.getAddress()
                        category = bookmark.getCategory()
                        comment = bookmark.getComment()

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
            logger.debug(f"Error collecting bookmarks: {e!s}")

        return results

    async def _collect_analysis_warnings(self) -> list[dict]:
        """Collect analysis warnings (functions with issues, etc.)."""
        results = []
        program = self.program_info.program

        try:
            func_mgr = program.getFunctionManager()
            func_count = 0

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
            logger.debug(f"Error collecting analysis warnings: {e!s}")

        return results
