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
        from agentdecompile_cli.registry import normalize_identifier as n

        mode = n(self._get_str(args, "mode", default="common"))
        max_results = self._get_int(args, "maxresults", "limit", default=1000)
        offset = self._get_int(args, "offset", "startindex", default=0)
        max_instr = self._get_int(args, "maxinstructions", default=2000000)
        samples_per = self._get_int(args, "samplesperconstant", default=5)

        program = self.program_info.program
        listing = program.getListing()

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
                            if val == 0:
                                continue  # Skip zero, too common

                            if mode in ("specific",):
                                target = self._get_int(args, "value", default=0)
                                if val != target:
                                    continue
                            elif mode in ("range",):
                                min_v = self._get_int(args, "minvalue", default=0)
                                max_v = self._get_int(args, "maxvalue", default=0xFFFFFFFF)
                                if val < min_v or val > max_v:
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
        results = []
        count = 0
        for val in sorted_vals:
            if count < offset:
                count += 1
                continue
            if len(results) >= max_results:
                break
            results.append(
                {
                    "value": val,
                    "hex": hex(val),
                    "occurrences": len(constants[val]),
                    "samples": constants[val],
                },
            )
            count += 1

        return create_success_response(
            {
                "mode": mode,
                "results": results,
                "count": len(results),
                "instructionsScanned": instr_count,
                "hasMore": count < len(sorted_vals),
            },
        )
