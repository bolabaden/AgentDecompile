"""Enum Tool Provider - manage-enums.

Single tool with modes list, info, create, add_member, edit_member, remove_member, delete.
Uses _collectors collect_enums / collect_enum_members.
"""

from __future__ import annotations

import logging
import re
import uuid

from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_enum_members,
    collect_enums,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    FORCE_APPLY_CONFLICT_ID_KEY,
    ToolProvider,
    create_conflict_response,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.program.model.data import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DataTypeManager as GhidraDataTypeManager,
        Enum as GhidraEnum,
    )

logger = logging.getLogger(__name__)

_COBRACASE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def is_cobra_case(name: str) -> bool:
    """Return True when ``name`` matches COBRA_CASE (SCREAMING_SNAKE) convention."""
    return bool(_COBRACASE_RE.match(name))


def require_cobra_case_member_name(name: str) -> None:
    """Raise ValueError when an enum member name is not COBRA_CASE."""
    if not is_cobra_case(name):
        raise ValueError(
            f"Enum member name must use COBRA_CASE (SCREAMING_SNAKE), got {name!r}. "
            "Example: SAVE_SLOT_EMPTY"
        )


def parse_enum_member_specs(
    raw_members: list[Any] | None,
    *,
    single_name: str | None = None,
    single_value: int | None = None,
) -> list[tuple[str, int]]:
    """Normalize member dicts or a single name/value pair into (name, value) tuples."""
    specs: list[tuple[str, int]] = []
    if raw_members:
        for item in raw_members:
            if not isinstance(item, dict):
                raise ValueError("Each member entry must be an object with name and value")
            ni = {n(k): v for k, v in item.items()}
            member_name = ni.get("membername") or ni.get("name")
            if not member_name:
                raise ValueError("Member entry missing name")
            value_raw = ni.get("membervalue")
            if value_raw is None:
                value_raw = ni.get("value")
            if value_raw is None:
                raise ValueError(f"Member '{member_name}' missing integer value")
            require_cobra_case_member_name(str(member_name))
            specs.append((str(member_name), int(value_raw)))
    if single_name:
        if single_value is None:
            raise ValueError("memberValue is required when memberName is provided")
        require_cobra_case_member_name(single_name)
        specs.append((single_name, int(single_value)))
    return specs


class EnumToolProvider(ToolProvider):
    HANDLERS = {
        "createenum": "_handle_create_alias",
        "deleteenum": "_handle_delete_alias",
        "editenum": "_handle_edit_alias",
        "getenuminfo": "_handle_info_alias",
        "listenums": "_handle_list_alias",
        "manageenums": "_handle",
    }

    def _find_enum(self, dtm: GhidraDataTypeManager, name: str) -> GhidraEnum | None:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._find_enum")
        assert self.program_info is not None
        for row in collect_enums(self.program_info.program):
            enum_dt = row.get("enum")
            if enum_dt is not None and enum_dt.getName() == name:
                return enum_dt
        return None

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.MANAGE_ENUMS.value,
                description=(
                    "Create, list, inspect, and edit enumerated types (C-style enums) with integer members. "
                    "Member names should use COBRA_CASE (SCREAMING_SNAKE)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "mode": {
                            "type": "string",
                            "description": "Enum operation to perform.",
                            "enum": [
                                "list",
                                "info",
                                "create",
                                "add_member",
                                "edit_member",
                                "remove_member",
                                "delete",
                            ],
                        },
                        "name": {"type": "string", "description": "Enum type name."},
                        "enumName": {"type": "string", "description": "Alternative parameter for name."},
                        "categoryPath": {
                            "type": "string",
                            "default": "/",
                            "description": "Category folder where the enum is stored.",
                        },
                        "description": {"type": "string", "description": "Optional enum description."},
                        "memberName": {"type": "string", "description": "Enum member name (COBRA_CASE)."},
                        "newMemberName": {"type": "string", "description": "Renamed member name for edit_member."},
                        "memberValue": {"type": "integer", "description": "Integer value for an enum member."},
                        "value": {"type": "integer", "description": "Alternative parameter for memberValue."},
                        "members": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Batch member definitions: [{name, value}, ...].",
                        },
                        "nameFilter": {"type": "string", "description": "Case-insensitive filter for list mode."},
                        "query": {"type": "string", "description": "Alternative parameter for nameFilter."},
                        "filter": {"type": "string", "description": "Alternative parameter for nameFilter."},
                        "maxResults": {
                            "type": "integer",
                            "default": 100,
                            "description": "Maximum enums returned by list mode.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._handle")
        self._require_program()
        action = self._get_str(args, "mode", "action", "operation", default="list")

        dispatch = {
            "list": self._list,
            "info": self._info,
            "create": self._create,
            "addmember": self._add_member,
            "editmember": self._edit_member,
            "removemember": self._remove_member,
            "delete": self._delete,
        }
        handler = self._dispatch_handler(dispatch, action, "action")
        return await handler(args)

    async def _handle_mode_alias(self, args: dict[str, Any], mode: str) -> list[types.TextContent]:
        forwarded_args = dict(args)
        forwarded_args.setdefault("mode", mode)
        return await self._handle(forwarded_args)

    async def _handle_create_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "create")

    async def _handle_list_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "list")

    async def _handle_info_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "info")

    async def _handle_delete_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "delete")

    async def _handle_edit_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "edit_member")

    async def _list(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._list")
        assert self.program_info is not None
        program = self.program_info.program
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        cat_path = self._get_str(args, "categorypath", "category")
        name_filter = self._get_str(args, "namefilter", "query", "filter", "search", "pattern").strip().lower()

        results: list[dict[str, Any]] = []
        for row in collect_enums(program):
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
                    "memberCount": row.get("memberCount", 0),
                },
            )
        return create_success_response({"action": "list", "enums": results, "count": len(results)})

    async def _info(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._info")
        name = self._require_str(args, "name", "enumname", "enum", name="name")
        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        enum_dt = self._find_enum(dtm, name)
        if enum_dt is None:
            raise ValueError(f"Enum not found: {name}")

        return create_success_response(
            {
                "action": "info",
                "name": name,
                "memberCount": enum_dt.getCount(),
                "members": collect_enum_members(enum_dt),
                "description": enum_dt.getDescription() or "",
            },
        )

    async def _create(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._create")
        name = self._require_str(args, "name", "enumname", name="name")
        cat_path = self._get_str(args, "categorypath", "category", default="/")
        description = self._get_str(args, "description", "comment", default="")
        members = parse_enum_member_specs(
            self._get_list(args, "members"),
            single_name=None,
            single_value=None,
        )

        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        if not args.get(FORCE_APPLY_CONFLICT_ID_KEY):
            existing = self._find_enum(dtm, name)
            if existing is not None:
                from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store
                from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id

                conflict_id = str(uuid.uuid4())
                conflict_summary = f"Create enum would overwrite existing enum with the same name:\n\nEnum **{name}** already exists."
                next_step = (
                    f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" '
                    'and `resolution` = "overwrite". To discard, use `resolution` = "skip".'
                )
                program_path = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(
                    self.program_info,
                    "file_path",
                    None,
                )
                store_args = dict(args)
                store_args["mode"] = "create"
                conflict_store_store(
                    get_current_mcp_session_id(),
                    conflict_id,
                    tool=Tool.MANAGE_ENUMS.value,
                    arguments=store_args,
                    program_path=str(program_path) if program_path else None,
                    summary=conflict_summary,
                )
                return create_conflict_response(conflict_id, Tool.MANAGE_ENUMS.value, conflict_summary, next_step)

        from ghidra.program.model.data import CategoryPath, EnumDataType  # pyright: ignore[reportMissingModuleSource]

        force_apply = bool(args.get(FORCE_APPLY_CONFLICT_ID_KEY))
        existing = self._find_enum(dtm, name) if force_apply else None

        def _create_enum() -> None:
            if existing is not None:
                dtm.remove(existing, None)
            enum_dt = EnumDataType(CategoryPath(cat_path), name, dtm)
            if description:
                enum_dt.setDescription(description)
            for member_name, member_value in members:
                enum_dt.add(member_name, member_value)
            dtm.addDataType(enum_dt, None)

        self._run_program_transaction(program, "create-enum", _create_enum)
        return create_success_response(
            {
                "action": "create",
                "name": name,
                "memberCount": len(members),
                "success": True,
            },
        )

    async def _add_member(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._add_member")
        enum_name = self._require_str(args, "name", "enumname", "enum", name="name")
        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        enum_dt = self._find_enum(dtm, enum_name)
        if enum_dt is None:
            raise ValueError(f"Enum not found: {enum_name}")

        batch = self._get_list(args, "members")
        if batch:
            member_specs = parse_enum_member_specs(batch)
            results: list[dict[str, Any]] = []

            def _batch_add_members() -> None:
                for member_name, member_value in member_specs:
                    try:
                        enum_dt.add(member_name, member_value)
                        results.append({"name": member_name, "value": member_value, "success": True})
                    except Exception as exc:
                        results.append({"name": member_name, "success": False, "error": str(exc)})

            self._run_program_transaction(program, "batch-add-enum-members", _batch_add_members)
            return create_success_response(
                {"action": "add_member", "enum": enum_name, "batch": True, "results": results},
            )

        member_name = self._require_str(args, "membername", "member", name="memberName")
        require_cobra_case_member_name(member_name)
        member_value = self._get_int(args, "membervalue", "value")
        if member_value is None:
            raise ValueError("memberValue is required for add_member")

        def _add_member() -> None:
            enum_dt.add(member_name, member_value)

        self._run_program_transaction(program, "add-enum-member", _add_member)
        return create_success_response(
            {
                "action": "add_member",
                "enum": enum_name,
                "member": member_name,
                "value": member_value,
                "success": True,
            },
        )

    async def _edit_member(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._edit_member")
        enum_name = self._require_str(args, "name", "enumname", name="name")
        member_name = self._require_str(args, "membername", "member", name="memberName")
        new_member_name = self._get_str(args, "newmembername", "newname")
        member_value = self._get_int(args, "membervalue", "value")

        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        enum_dt = self._find_enum(dtm, enum_name)
        if enum_dt is None:
            raise ValueError(f"Enum not found: {enum_name}")
        if not enum_dt.contains(member_name):
            raise ValueError(f"Enum member not found: {member_name}")

        if member_value is None:
            member_value = int(enum_dt.getValue(member_name))
        target_name = new_member_name or member_name
        if new_member_name:
            require_cobra_case_member_name(new_member_name)

        def _edit_member() -> None:
            if new_member_name and new_member_name != member_name:
                enum_dt.replace(member_name, target_name, member_value)
            elif member_value != int(enum_dt.getValue(member_name)):
                enum_dt.remove(member_name)
                enum_dt.add(target_name, member_value)

        self._run_program_transaction(program, "edit-enum-member", _edit_member)
        return create_success_response(
            {
                "action": "edit_member",
                "enum": enum_name,
                "member": target_name,
                "value": member_value,
                "success": True,
            },
        )

    async def _remove_member(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._remove_member")
        enum_name = self._require_str(args, "name", "enumname", name="name")
        member_name = self._require_str(args, "membername", "member", name="memberName")

        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        enum_dt = self._find_enum(dtm, enum_name)
        if enum_dt is None:
            raise ValueError(f"Enum not found: {enum_name}")
        if not enum_dt.contains(member_name):
            raise ValueError(f"Enum member not found: {member_name}")

        def _remove_member() -> None:
            enum_dt.remove(member_name)

        self._run_program_transaction(program, "remove-enum-member", _remove_member)
        return create_success_response(
            {
                "action": "remove_member",
                "enum": enum_name,
                "member": member_name,
                "success": True,
            },
        )

    async def _delete(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/enums.py:EnumToolProvider._delete")
        name = self._require_str(args, "name", "enumname", name="name")
        assert self.program_info is not None
        program = self.program_info.program
        dtm = program.getDataTypeManager()

        enum_dt = self._find_enum(dtm, name)
        if enum_dt is None:
            raise ValueError(f"Enum not found: {name}")

        def _delete_enum() -> None:
            dtm.remove(enum_dt, None)

        self._run_program_transaction(program, "delete-enum", _delete_enum)
        return create_success_response({"action": "delete", "name": name, "success": True})
