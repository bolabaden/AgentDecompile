"""Constant Search Tool Provider - search-constants.

Modes: specific, range, common.
Scans instructions for scalar operands matching search criteria.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
    DEFAULT_LARGE_PAGE_LIMIT,
    DEFAULT_MAX_INSTRUCTIONS,
    DEFAULT_SAMPLES_PER_CONSTANT,
)

logger = logging.getLogger(__name__)


class ConstantSearchToolProvider(ToolProvider):
    HANDLERS = {"searchconstants": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="search-constants",
                description="Search for constant values used in instructions",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {"type": "string", "enum": ["specific", "range", "common"], "default": "common"},
                        "value": {"type": "integer", "description": "Specific value to search (specific mode)"},
                        "minValue": {"type": "integer", "description": "Min value (range mode)"},
                        "maxValue": {"type": "integer", "description": "Max value (range mode)"},
                        "limit": {"type": "integer", "default": 1000},
                        "offset": {"type": "integer", "default": 0},
                        "maxInstructions": {"type": "integer", "default": 2000000},
                        "samplesPerConstant": {"type": "integer", "default": 5},
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

        program = self.program_info.program
        listing = self._get_listing(program)

        # Gather constants from instructions
        constants: dict[int, list[dict]] = {}
        instr_count = 0

        try:
            instr_iter = listing.getInstructions(True)
            while instr_iter.hasNext() and instr_count < max_instr:
                instr = instr_iter.next()
                instr_count += 1
                num_ops = instr.getNumOperands()
                for i in range(num_ops):
                    for obj in instr.getOpObjects(i):
                        try:
                            scalar_val = obj.getValue() if hasattr(obj, "getValue") else None
                            if scalar_val is None:
                                continue
                            val = int(scalar_val)
                            if val == 0 or not value_filter(val):
                                continue

                            if val not in constants:
                                constants[val] = []
                            if len(constants[val]) < samples_per:
                                constants[val].append(
                                    {
                                        "address": str(instr.getAddress()),
                                        "instruction": str(instr),
                                    },
                                )
                        except Exception:
                            continue
        except Exception as e:
            logger.warning(f"Instruction scan error: {e}")

        # Format results
        sorted_vals = sorted(constants.keys(), key=lambda v: len(constants[v]), reverse=True)
        all_results = []
        for val in sorted_vals:
            all_results.append(
                {
                    "value": val,
                    "hex": hex(val),
                    "occurrences": len(constants[val]),
                    "samples": constants[val],
                },
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
