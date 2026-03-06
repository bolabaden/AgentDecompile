"""Constant Search Tool Provider - search-constants.

Modes: specific, range, common.
Scans instructions for scalar operands matching search criteria.
"""

from __future__ import annotations

import logging

from collections.abc import Callable
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_constants
from agentdecompile_cli.mcp_server.tool_providers import (
    DEFAULT_LARGE_PAGE_LIMIT,
    DEFAULT_MAX_INSTRUCTIONS,
    DEFAULT_SAMPLES_PER_CONSTANT,
    ToolProvider,
)

logger = logging.getLogger(__name__)


class ConstantSearchToolProvider(ToolProvider):
    HANDLERS = {"searchconstants": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="search-constants",
                description="Scan the assembly instructions of the program to find a specific hardcoded number, a range of numbers, or a list of commonly used magic numbers (like crypto signatures or checksums). Use this to locate where a known algorithm or specific value is configured in code.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the binary program in Ghidra."},
                        "mode": {
                            "type": "string",
                            "enum": ["specific", "range", "common"],
                            "default": "common",
                            "description": "Type of search: 'specific' (exact match), 'range' (between min and max), or 'common' (find well-known crypto/magic values).",
                        },
                        "value": {"type": "integer", "description": "The exact numeric value to search for when mode is 'specific'."},
                        "minValue": {"type": "integer", "description": "The lowest numeric value to match when mode is 'range'."},
                        "maxValue": {"type": "integer", "description": "The highest numeric value to match when mode is 'range'."},
                        "limit": {"type": "integer", "default": 1000, "description": "Number of constants to return. Typical values are 500–2000. Do not set this below 200 unless the user explicitly asks for only a small sample."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination text offset."},
                        "maxInstructions": {
                            "type": "integer",
                            "default": 2000000,
                            "description": "Maximum number of assembly instructions to scan before timing out, preventing massive slowdowns on huge binaries.",
                        },
                        "samplesPerConstant": {
                            "type": "integer",
                            "default": 5,
                            "description": "For each constant found, how many examples of the code that uses it to include in the output.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="common")

        return await self._dispatch_handler(
            args,
            mode,
            {
                "specific": "_handle_specific",
                "range": "_handle_range",
                "common": "_handle_common",
            },
        )

    def _collect_constants(self, args: dict[str, Any], value_filter: Callable[[int], bool]) -> tuple[list[dict], int]:
        """Collect constants from instructions using the provided filter.

        Scans program instructions to find scalar values that pass the filter.
        Returns formatted results sorted by occurrence frequency, and instruction count.

        Performance: O(max_instructions) scan with O(samples_per_constant * unique_values) storage.
        Uses heapq.nlargest implicitly via sorting for top-K by frequency.
        """
        offset, max_results = self._get_pagination_params(args, default_limit=DEFAULT_LARGE_PAGE_LIMIT)
        max_instr = self._get_int(args, "maxinstructions", default=DEFAULT_MAX_INSTRUCTIONS)
        samples_per = self._get_int(args, "samplesperconstant", default=DEFAULT_SAMPLES_PER_CONSTANT)

        assert self.program_info is not None  # for type checker
        program = self.program_info.program

        all_results, instr_count = collect_constants(
            program,
            value_filter=value_filter,
            max_instructions=max_instr,
            samples_per_constant=samples_per,
        )

        return all_results, instr_count

    async def _handle_specific(self, args: dict[str, Any]) -> list[types.TextContent]:
        target = self._get_int(args, "value", default=0)
        all_results, instr_count = self._collect_constants(args, lambda v: v == target)
        offset, max_results = self._get_pagination_params(args, default_limit=DEFAULT_LARGE_PAGE_LIMIT)
        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="specific", instructionsScanned=instr_count)

    async def _handle_range(self, args: dict[str, Any]) -> list[types.TextContent]:
        min_v = self._get_int(args, "minvalue", default=0)
        max_v = self._get_int(args, "maxvalue", default=0xFFFFFFFF)
        all_results, instr_count = self._collect_constants(args, lambda v: min_v <= v <= max_v)
        offset, max_results = self._get_pagination_params(args, default_limit=DEFAULT_LARGE_PAGE_LIMIT)
        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="range", instructionsScanned=instr_count)

    async def _handle_common(self, args: dict[str, Any]) -> list[types.TextContent]:
        all_results, instr_count = self._collect_constants(args, lambda v: True)
        offset, max_results = self._get_pagination_params(args, default_limit=DEFAULT_LARGE_PAGE_LIMIT)
        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="common", instructionsScanned=instr_count)
