"""Structure Tool Provider - manage-structures.

Actions: parse, validate, create, add_field, modify_field, modify_from_c,
         info, list, apply, delete, parse_header.
"""

from __future__ import annotations

import logging

from typing import Any, cast

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_structure_fields,
    collect_structures,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class StructureToolProvider(ToolProvider):
    HANDLERS = {"managestructures": "_handle"}

    def _find_structure(self, dtm: Any, name: str) -> Any:
        """Return a structure by exact name, or ``None`` when not found.

        **Performance**: O(n) where n = number of structures in the data type manager.
        For programs with many structures, this may be slow. Consider caching if needed.
        """
        assert self.program_info is not None
        for row in collect_structures(self.program_info.program):
            struct = row.get("structure")
            if struct is not None and struct.getName() == name:
                return struct
        return None

    @staticmethod
    def _new_data_type_parser(dtm: Any) -> Any:
        """Create a ``DataTypeParser`` configured for broad type support."""
        from ghidra.util.data import DataTypeParser  # pyright: ignore[reportMissingModuleSource]

        return DataTypeParser(dtm, dtm, cast("Any", None), DataTypeParser.AllowedDataTypes.ALL)

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-structures",
                description="Create, list, apply, parse, and edit complex data structures (like C structs and unions) to map out memory layouts.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "mode": {
                            "type": "string",
                            "description": "What operation to perform on the structure data.",
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
                        "name": {"type": "string", "description": "The EXACT name of the structure you want to interact with."},
                        "structureName": {"type": "string", "description": "Alternative parameter for name."},
                        "categoryPath": {"type": "string", "default": "/", "description": "The organizational folder path where the structure is stored."},
                        "size": {"type": "integer", "description": "The total byte size of the structure when creating an empty block."},
                        "cDefinition": {"type": "string", "description": "A block of C-code text defining a struct (e.g., 'struct foo { int a; char b; };'). Used for parse and modify_from_c."},
                        "fieldName": {"type": "string", "description": "The name of a specific member field within the struct."},
                        "fieldType": {"type": "string", "description": "The data type of the member field (e.g., 'int', 'char *', 'void *')."},
                        "fieldOffset": {"type": "integer", "description": "The exact byte offset from the start of the struct where the field begins."},
                        "fieldComment": {"type": "string", "description": "An optional explanation attached to a specific member field."},
                        "fields": {"type": "array", "items": {"type": "object"}, "description": "An array of multiple field definitions to apply at once."},
                        "addressOrSymbol": {"type": "string", "description": "The memory address where you want to drop/apply the struct template."},
                        "isUnion": {"type": "boolean", "default": False, "description": "If true, treats the object as a C-union (all fields overlap at offset 0)."},
                        "nameFilter": {"type": "string", "description": "Case-insensitive text to filter the struct list by."},
                        "query": {"type": "string", "description": "Alternative parameter for nameFilter."},
                        "filter": {"type": "string", "description": "Alternative parameter for nameFilter."},
                        "maxResults": {"type": "integer", "default": 100, "description": "Number of structure results to return. Typical values are 100–500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
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
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        cat_path = self._get_str(args, "categorypath", "category")
        name_filter = self._get_str(args, "namefilter", "query", "filter", "search", "pattern").strip().lower()

        results = []
        for row in collect_structures(program):
            if len(results) >= max_results:
                break
            if cat_path and str(row.get("categoryPath", "")) != cat_path:
                continue
            if name_filter and name_filter not in str(row.get("name", "")).lower():
                continue
            results.append(
                {
                    "name": row.get("name", ""),
                    "path": row.get("categoryPath", ""),
                    "length": row.get("length", 0),
                    "numComponents": row.get("numComponents", 0),
                    "isUnion": row.get("isUnion", False),
                },
            )
        return create_success_response({"action": "list", "structures": results, "count": len(results)})

    async def _info(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "name", "structurename", "structure", name="name")
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, name)
        if dt is None:
            raise ValueError(f"Structure not found: {name}")

        fields = collect_structure_fields(dt)
        for i, field in enumerate(fields):
            if not field.get("name"):
                field["name"] = f"field_{i}"

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

        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        from ghidra.program.model.data import CategoryPath  # pyright: ignore[reportMissingModuleSource]

        def _create_structure() -> None:
            if is_union:
                from ghidra.program.model.data import UnionDataType  # pyright: ignore[reportMissingModuleSource]

                dt = UnionDataType(CategoryPath(cat_path), name, dtm)
            else:
                from ghidra.program.model.data import StructureDataType  # pyright: ignore[reportMissingModuleSource]

                dt = StructureDataType(CategoryPath(cat_path), name, size, dtm)
            dtm.addDataType(dt, None)

        self._run_program_transaction(program, "create-structure", _create_structure)

        return create_success_response({"action": "create", "name": name, "size": size, "isUnion": is_union, "success": True})

    async def _add_field(self, args: dict[str, Any]) -> list[types.TextContent]:
        struct_name = self._require_str(args, "name", "structurename", "structure", name="name")
        assert self.program_info is not None  # for type checker
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

        assert self.program_info is not None  # for type checker
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
        assert self.program_info is not None  # for type checker
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
        assert self.program_info is not None  # for type checker
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
        assert self.program_info is not None  # for type checker
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
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        dt = self._find_structure(dtm, name)
        if dt is None:
            raise ValueError(f"Structure not found: {name}")

        def _delete_structure() -> None:
            dtm.remove(dt, None)

        self._run_program_transaction(program, "delete-structure", _delete_structure)
        return create_success_response({"action": "delete", "name": name, "success": True})
