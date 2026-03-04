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
    n,
)

logger = logging.getLogger(__name__)


class StructureToolProvider(ToolProvider):
    HANDLERS = {"managestructures": "_handle"}

    def _find_structure(self, dtm: Any, name: str) -> Any:
        """Return a structure by exact name, or ``None`` when not found."""
        for struct in dtm.getAllStructures():
            if struct.getName() == name:
                return struct
        return None

    @staticmethod
    def _new_data_type_parser(dtm: Any) -> Any:
        """Create a ``DataTypeParser`` configured for broad type support."""
        from ghidra.util.data import DataTypeParser

        return DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-structures",
                description="Manage structures and unions (create, modify, apply, parse C headers)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {
                            "type": "string",
                            "description": "Operation mode",
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
                        "nameFilter": {"type": "string", "description": "Case-insensitive structure-name filter"},
                        "query": {"type": "string", "description": "Alias for nameFilter"},
                        "filter": {"type": "string", "description": "Alias for nameFilter"},
                        "maxResults": {"type": "integer", "default": 100},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._get_str(args, "mode", "action", "operation", default="list")

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
        handler = self._dispatch_handler(dispatch, action, "action")
        return await handler(args)

    async def _list(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        dtm = program.getDataTypeManager()
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        cat_path = self._get_str(args, "categorypath", "category")
        name_filter = self._get_str(args, "namefilter", "query", "filter", "search", "pattern").strip().lower()

        results = []
        for dt in dtm.getAllStructures():
            if len(results) >= max_results:
                break
            if cat_path and str(dt.getCategoryPath()) != cat_path:
                continue
            if name_filter and name_filter not in str(dt.getName()).lower():
                continue
            results.append(
                {
                    "name": dt.getName(),
                    "path": str(dt.getCategoryPath()),
                    "length": dt.getLength(),
                    "numComponents": dt.getNumComponents(),
                    "isUnion": hasattr(dt, "isUnion") and dt.isUnion(),
                },
            )
        return create_success_response({"action": "list", "structures": results, "count": len(results)})

    async def _info(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", "structure", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, name)
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
                },
            )

        return create_success_response(
            {
                "action": "info",
                "name": name,
                "length": dt.getLength(),
                "numComponents": dt.getNumComponents(),
                "fields": fields,
                "description": dt.getDescription() or "",
            },
        )

    async def _create(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", name="name")
        size = self._get_int(args, "size", default=0)
        cat_path = self._get_str(args, "categorypath", "category", default="/")
        is_union = self._get_bool(args, "isunion", default=False)

        program = self.program_info.program
        dtm = program.getDataTypeManager()

        from ghidra.program.model.data import CategoryPath

        def _create_structure() -> None:
            if is_union:
                from ghidra.program.model.data import UnionDataType

                dt = UnionDataType(CategoryPath(cat_path), name, dtm)
            else:
                from ghidra.program.model.data import StructureDataType

                dt = StructureDataType(CategoryPath(cat_path), name, size, dtm)
            dtm.addDataType(dt, None)

        self._run_program_transaction(program, "create-structure", _create_structure)

        return create_success_response({"action": "create", "name": name, "size": size, "isUnion": is_union, "success": True})

    async def _add_field(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", "structure", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, struct_name)
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        parser = self._new_data_type_parser(dtm)

        # Batch support
        batch = self._get_list(args, "fields")
        if batch:
            results = []

            def _batch_add_fields() -> None:
                for field in batch:
                    ni = {n(k): v for k, v in field.items()}
                    f_name = ni.get("fieldname") or ni.get("name") or f"field_{dt.getNumComponents()}"
                    f_type = ni.get("fieldtype") or ni.get("type") or "byte"
                    f_comment = ni.get("fieldcomment") or ni.get("comment") or ""
                    try:
                        fdt = parser.parse(f_type)
                        dt.add(fdt, fdt.getLength(), f_name, f_comment)
                        results.append({"name": f_name, "success": True})
                    except Exception as e:
                        results.append({"name": f_name, "success": False, "error": str(e)})

            self._run_program_transaction(program, "batch-add-fields", _batch_add_fields)
            return create_success_response({"action": "add_field", "structure": struct_name, "batch": True, "results": results})

        # Single field
        field_name = self._get_str(args, "fieldname", "field", default=f"field_{dt.getNumComponents()}")
        field_type = self._require_str(args, "fieldtype", "type", name="fieldType")
        field_comment = self._get_str(args, "fieldcomment", "comment", default="")
        fdt = parser.parse(field_type)

        def _add_field() -> None:
            dt.add(fdt, fdt.getLength(), field_name, field_comment)

        self._run_program_transaction(program, "add-field", _add_field)
        return create_success_response({"action": "add_field", "structure": struct_name, "field": field_name, "type": field_type, "success": True})

    async def _modify_field(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", name="name")
        field_offset = self._get_int(args, "fieldoffset", "offset")
        field_name = self._get_str(args, "fieldname", "field")
        field_type = self._get_str(args, "fieldtype", "type")
        field_comment = self._get_str(args, "fieldcomment", "comment")

        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, struct_name)
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        parser = self._new_data_type_parser(dtm)

        comp = dt.getComponentAt(field_offset)
        if comp is None:
            raise ValueError(f"No field at offset {field_offset}")

        def _modify_field() -> None:
            if field_name:
                comp.setFieldName(field_name)
            if field_comment:
                comp.setComment(field_comment)
            if field_type:
                new_dt = parser.parse(field_type)
                comp.setDataType(new_dt)

        self._run_program_transaction(program, "modify-field", _modify_field)
        return create_success_response({"action": "modify_field", "structure": struct_name, "offset": field_offset, "success": True})

    async def _modify_from_c(self, args: dict[str, Any]) -> list[types.TextContent]:
        c_def = self._require_str(args, "cdefinition", "headercontent", "definition", "code", "c", name="cDefinition")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        try:
            from ghidra.app.util.cparser import CParser

            parser = CParser(dtm)

            def _parse_c_struct() -> Any:
                dt = parser.parse(c_def)
                return dt

            dt = self._run_program_transaction(program, "parse-c-struct", _parse_c_struct)
            return create_success_response(
                {
                    "action": "modify_from_c",
                    "parsed": True,
                    "name": dt.getName() if hasattr(dt, "getName") else str(dt),
                    "success": True,
                },
            )
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

        dt = self._find_structure(dtm, struct_name)
        if dt is None:
            raise ValueError(f"Structure not found: {struct_name}")

        # Batch
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        if addr_list and len(addr_list) > 1:
            results = []

            def _batch_apply_struct() -> None:
                listing = self._get_listing(program)
                for a in addr_list:
                    try:
                        addr = self._resolve_address(str(a), program=program)
                        listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
                        listing.createData(addr, dt)
                        results.append({"address": str(addr), "success": True})
                    except Exception as e:
                        results.append({"address": str(a), "success": False, "error": str(e)})

            self._run_program_transaction(program, "batch-apply-struct", _batch_apply_struct)
            return create_success_response({"action": "apply", "batch": True, "results": results})

        addr = self._resolve_address(addr_str, program=program)

        def _apply_struct() -> None:
            listing = self._get_listing(program)
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)

        self._run_program_transaction(program, "apply-struct", _apply_struct)
        return create_success_response({"action": "apply", "structure": struct_name, "address": str(addr), "success": True})

    async def _delete(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", name="name")
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, name)
        if dt is None:
            raise ValueError(f"Structure not found: {name}")

        def _delete_structure() -> None:
            dtm.remove(dt, None)

        self._run_program_transaction(program, "delete-structure", _delete_structure)
        return create_success_response({"action": "delete", "name": name, "success": True})
