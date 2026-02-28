"""Structure Tool Provider - manage-structures.

Actions: parse, validate, create, add_field, modify_field, modify_from_c,
         info, list, apply, delete, parse_header.
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


class StructureToolProvider(ToolProvider):
    HANDLERS = {"managestructures": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-structures",
                description="Manage structures and unions (create, modify, apply, parse C headers)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "action": {
                            "type": "string",
                            "enum": [
                                "parse",
                                "validate",
                                "create",
                                "add_field",
                                "modify_field",
                                "modify_from_c",
                                "info",
                                "list",
                                "apply",
                                "delete",
                                "parse_header",
                            ],
                        },
                        "name": {"type": "string", "description": "Structure name"},
                        "structureName": {"type": "string"},
                        "categoryPath": {"type": "string", "default": "/"},
                        "size": {"type": "integer"},
                        "cDefinition": {"type": "string", "description": "C struct definition"},
                        "fieldName": {"type": "string"},
                        "fieldType": {"type": "string"},
                        "fieldOffset": {"type": "integer"},
                        "fieldComment": {"type": "string"},
                        "fields": {"type": "array", "items": {"type": "object"}},
                        "addressOrSymbol": {"type": "string"},
                        "isUnion": {"type": "boolean", "default": False},
                        "maxResults": {"type": "integer", "default": 100},
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
            "list": self._list,
            "info": self._info,
            "create": self._create,
            "addfield": self._add_field,
            "modifyfield": self._modify_field,
            "modifyfromc": self._modify_from_c,
            "parsec": self._modify_from_c,
            "parse": self._parse,
            "parseheader": self._parse_header,
            "validate": self._validate,
            "apply": self._apply,
            "delete": self._delete,
        }
        handler = dispatch.get(n(action))
        if handler is None:
            raise ValueError(f"Unknown action: {action}")
        return await handler(args)

    async def _list(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        dtm = program.getDataTypeManager()
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        cat_path = self._get_str(args, "categorypath", "category")

        results = []
        for dt in dtm.getAllStructures():
            if len(results) >= max_results:
                break
            if cat_path and str(dt.getCategoryPath()) != cat_path:
                continue
            results.append(
                {
                    "name": dt.getName(),
                    "path": str(dt.getCategoryPath()),
                    "length": dt.getLength(),
                    "numComponents": dt.getNumComponents(),
                    "isUnion": hasattr(dt, "isUnion") and dt.isUnion(),
                }
            )
        return create_success_response({"action": "list", "structures": results, "count": len(results)})

    async def _info(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", "structure", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = None
        for s in dtm.getAllStructures():
            if s.getName() == name:
                dt = s
                break
        if dt is None:
            raise ValueError(f"Structure not found: {name}")

        fields = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            fields.append(
                {
                    "offset": comp.getOffset(),
                    "name": comp.getFieldName() or f"field_{i}",
                    "type": str(comp.getDataType()),
                    "length": comp.getLength(),
                    "comment": comp.getComment() or "",
                }
            )

        return create_success_response(
            {
                "action": "info",
                "name": name,
                "length": dt.getLength(),
                "numComponents": dt.getNumComponents(),
                "fields": fields,
                "description": dt.getDescription() or "",
            }
        )

    async def _create(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", name="name")
        size = self._get_int(args, "size", default=0)
        cat_path = self._get_str(args, "categorypath", "category", default="/")
        is_union = self._get_bool(args, "isunion", default=False)

        program = self.program_info.program
        dtm = program.getDataTypeManager()

        from ghidra.program.model.data import CategoryPath

        tx = program.startTransaction("create-structure")
        try:
            if is_union:
                from ghidra.program.model.data import UnionDataType

                dt = UnionDataType(CategoryPath(cat_path), name, dtm)
            else:
                from ghidra.program.model.data import StructureDataType

                dt = StructureDataType(CategoryPath(cat_path), name, size, dtm)
            dtm.addDataType(dt, None)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise

        return create_success_response({"action": "create", "name": name, "size": size, "isUnion": is_union, "success": True})

    async def _add_field(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", "structure", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = None
        for s in dtm.getAllStructures():
            if s.getName() == struct_name:
                dt = s
                break
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        # Batch support
        batch = self._get_list(args, "fields")
        if batch:
            from agentdecompile_cli.registry import normalize_identifier as n

            results = []
            tx = program.startTransaction("batch-add-fields")
            try:
                for field in batch:
                    ni = {n(k): v for k, v in field.items()}
                    f_name = ni.get("fieldname") or ni.get("name") or f"field_{dt.getNumComponents()}"
                    f_type = ni.get("fieldtype") or ni.get("type") or "byte"
                    f_comment = ni.get("fieldcomment") or ni.get("comment") or ""
                    try:
                        from ghidra.util.data import DataTypeParser

                        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
                        fdt = parser.parse(f_type)
                        dt.add(fdt, fdt.getLength(), f_name, f_comment)
                        results.append({"name": f_name, "success": True})
                    except Exception as e:
                        results.append({"name": f_name, "success": False, "error": str(e)})
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "add_field", "structure": struct_name, "batch": True, "results": results})

        # Single field
        field_name = self._get_str(args, "fieldname", "field", default=f"field_{dt.getNumComponents()}")
        field_type = self._require_str(args, "fieldtype", "type", name="fieldType")
        field_comment = self._get_str(args, "fieldcomment", "comment", default="")

        from ghidra.util.data import DataTypeParser

        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        fdt = parser.parse(field_type)

        tx = program.startTransaction("add-field")
        try:
            dt.add(fdt, fdt.getLength(), field_name, field_comment)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "add_field", "structure": struct_name, "field": field_name, "type": field_type, "success": True})

    async def _modify_field(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", name="name")
        field_offset = self._get_int(args, "fieldoffset", "offset")
        field_name = self._get_str(args, "fieldname", "field")
        field_type = self._get_str(args, "fieldtype", "type")
        field_comment = self._get_str(args, "fieldcomment", "comment")

        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = None
        for s in dtm.getAllStructures():
            if s.getName() == struct_name:
                dt = s
                break
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        comp = dt.getComponentAt(field_offset)
        if comp is None:
            raise ValueError(f"No field at offset {field_offset}")

        tx = program.startTransaction("modify-field")
        try:
            if field_name:
                comp.setFieldName(field_name)
            if field_comment:
                comp.setComment(field_comment)
            if field_type:
                from ghidra.util.data import DataTypeParser

                parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
                new_dt = parser.parse(field_type)
                comp.setDataType(new_dt)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "modify_field", "structure": struct_name, "offset": field_offset, "success": True})

    async def _modify_from_c(self, args: dict[str, Any]) -> list[types.TextContent]:
        c_def = self._require_str(args, "cdefinition", "headercontent", "definition", "code", "c", name="cDefinition")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        try:
            from ghidra.app.util.cparser import CParser

            parser = CParser(dtm)
            tx = program.startTransaction("parse-c-struct")
            try:
                dt = parser.parse(c_def)
                program.endTransaction(tx, True)
                return create_success_response(
                    {
                        "action": "modify_from_c",
                        "parsed": True,
                        "name": dt.getName() if hasattr(dt, "getName") else str(dt),
                        "success": True,
                    }
                )
            except Exception:
                program.endTransaction(tx, False)
                raise
        except ImportError:
            raise ValueError("CParser not available in this environment")

    async def _parse(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._modify_from_c(args)

    async def _parse_header(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._modify_from_c(args)

    async def _validate(self, args: dict[str, Any]) -> list[types.TextContent]:
        c_def = self._require_str(args, "cdefinition", "headercontent", "definition", "code", name="cDefinition")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        try:
            from ghidra.app.util.cparser import CParser

            parser = CParser(dtm)
            dt = parser.parse(c_def)
            return create_success_response({"action": "validate", "valid": True, "name": str(dt.getName()) if hasattr(dt, "getName") else str(dt)})
        except Exception as e:
            return create_success_response({"action": "validate", "valid": False, "error": str(e)})

    async def _apply(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", "structure", name="name")
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = None
        for s in dtm.getAllStructures():
            if s.getName() == struct_name:
                dt = s
                break
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        # Batch
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        if addr_list and len(addr_list) > 1:
            results = []
            tx = program.startTransaction("batch-apply-struct")
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
            return create_success_response({"action": "apply", "batch": True, "results": results})

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        tx = program.startTransaction("apply-struct")
        try:
            listing = program.getListing()
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "apply", "structure": struct_name, "address": str(addr), "success": True})

    async def _delete(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = None
        for s in dtm.getAllStructures():
            if s.getName() == name:
                dt = s
                break
        if dt is None:
            raise ValueError(f"Structure not found: {name}")

        tx = program.startTransaction("delete-structure")
        try:
            dtm.remove(dt, None)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "delete", "name": name, "success": True})
