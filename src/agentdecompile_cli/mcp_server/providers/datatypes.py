"""Data Types Tool Provider - manage-data-types.

Actions: archives, list, by_string, apply.
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


class DataTypeToolProvider(ToolProvider):
    HANDLERS = {"managedatatypes": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-data-types",
                description="Manage data types: list archives, list types by category, parse from string, apply at address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "action": {"type": "string", "enum": ["archives", "list", "by_string", "apply"], "default": "list"},
                        "categoryPath": {"type": "string", "description": "Category path (e.g., /MyTypes)"},
                        "dataTypeString": {"type": "string", "description": "Data type as string (e.g., int, char*)"},
                        "addressOrSymbol": {"type": "string"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._get_str(args, "action", "mode", default="list")

        from agentdecompile_cli.registry import normalize_identifier as n

        dispatch = {
            "archives": self._archives,
            "list": self._list,
            "bystring": self._by_string,
            "apply": self._apply,
        }
        handler = dispatch.get(n(action))
        if handler is None:
            raise ValueError(f"Unknown action: {action}. Valid: archives, list, by_string, apply")
        return await handler(args)

    async def _archives(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        archives = []
        try:
            # List data type manager info
            archives.append(
                {
                    "name": dtm.getName(),
                    "type": "program",
                    "categoryCount": dtm.getCategoryCount(),
                    "dataTypeCount": dtm.getDataTypeCount(True),
                },
            )
            # Try to get source archives
            for sa in dtm.getSourceArchives():
                archives.append(
                    {
                        "name": sa.getName(),
                        "type": "source",
                        "id": str(sa.getSourceArchiveID()),
                    },
                )
        except Exception as e:
            logger.warning(f"Archive listing error: {e}")

        return create_success_response({"action": "archives", "archives": archives, "count": len(archives)})

    async def _list(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        dtm = program.getDataTypeManager()
        cat_path = self._get_str(args, "categorypath", "category", "path")
        max_results = self._get_int(args, "maxresults", "limit", "maxcount", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)

        results = []
        if cat_path:
            from ghidra.program.model.data import CategoryPath

            cat = dtm.getCategory(CategoryPath(cat_path))
            if cat is None:
                raise ValueError(f"Category not found: {cat_path}")
            dts = cat.getDataTypes()
            for i, dt in enumerate(dts):
                if i < offset:
                    continue
                if len(results) >= max_results:
                    break
                results.append(
                    {
                        "name": dt.getName(),
                        "path": str(dt.getCategoryPath()),
                        "length": dt.getLength(),
                        "description": dt.getDescription() or "",
                    },
                )
        else:
            # List root categories
            root = dtm.getRootCategory()
            subcats = root.getCategories()
            for i, sc in enumerate(subcats):
                if i < offset:
                    continue
                if len(results) >= max_results:
                    break
                results.append(
                    {
                        "name": sc.getName(),
                        "path": str(sc.getCategoryPath()),
                        "isCategory": True,
                    },
                )
            # Also list root-level types
            for dt in root.getDataTypes():
                if len(results) >= max_results:
                    break
                results.append(
                    {
                        "name": dt.getName(),
                        "path": "/",
                        "length": dt.getLength(),
                    },
                )

        return create_success_response(
            {
                "action": "list",
                "category": cat_path or "/",
                "results": results,
                "count": len(results),
            },
        )

    async def _by_string(self, args: dict[str, Any]) -> list[types.TextContent]:
        dt_str = self._require_str(args, "datatypestring", "datatype", "typestring", "type", name="dataTypeString")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        try:
            from ghidra.util.data import DataTypeParser

            parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
            dt = parser.parse(dt_str)
            return create_success_response(
                {
                    "action": "by_string",
                    "input": dt_str,
                    "resolved": {
                        "name": dt.getName(),
                        "path": str(dt.getCategoryPath()),
                        "length": dt.getLength(),
                        "description": dt.getDescription() or "",
                        "displayName": dt.getDisplayName(),
                    },
                },
            )
        except Exception as e:
            raise ValueError(f"Could not parse data type '{dt_str}': {e}")

    async def _apply(self, args: dict[str, Any]) -> list[types.TextContent]:
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        dt_str = self._require_str(args, "datatypestring", "datatype", "type", name="dataTypeString")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        # Batch support
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        if addr_list and len(addr_list) > 1:
            # Batch mode
            from ghidra.util.data import DataTypeParser

            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
            dt = parser.parse(dt_str)
            results = []
            tx = program.startTransaction("batch-apply-datatype")
            try:
                listing = program.getListing()
                for a in addr_list:
                    try:
                        addr = AddressUtil.resolve_address_or_symbol(program, str(a))
                        listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
                        listing.createData(addr, dt)
                        results.append({"address": str(addr), "success": True})
                    except Exception as e:
                        results.append({"address": str(a), "success": False, "error": str(e)})
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "apply", "batch": True, "results": results, "count": len(results)})

        # Single
        from ghidra.util.data import DataTypeParser

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        dt = parser.parse(dt_str)
        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

        tx = program.startTransaction("apply-datatype")
        try:
            listing = program.getListing()
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response(
            {
                "action": "apply",
                "address": str(addr),
                "dataType": dt_str,
                "success": True,
            },
        )
