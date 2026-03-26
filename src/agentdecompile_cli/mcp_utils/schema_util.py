"""Schema utility helpers for MCP JSON schema creation.

SchemaUtil builds MCP tool inputSchema property dicts (string, boolean, integer,
enum, etc.) with optional default/enum/items. Used by providers that construct
schemas programmatically instead of inline dicts. _UNSET is the sentinel for
"no default" so we can distinguish default=None from omitted.
"""

from __future__ import annotations

import logging
logger = logging.getLogger(__name__)

from typing import Any

_UNSET = object()


class SchemaUtil:
    """Utility methods for creating MCP JSON schemas."""

    @staticmethod
    def _property_schema(
        schema_type: str,
        description: str,
        *,
        default: Any = _UNSET,
        enum: list[str] | None = None,
        items: dict[str, Any] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a JSON-schema property with optional common fields."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil._property_schema")
        schema: dict[str, Any] = {
            "type": schema_type,
            "description": description,
        }
        if default is not _UNSET:
            schema["default"] = default
        if enum:
            schema["enum"] = enum
        if items:
            schema["items"] = items
        if properties:
            schema["properties"] = properties
        return schema

    @staticmethod
    def string_property(description: str) -> dict[str, Any]:
        """Create a string property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.string_property")
        return SchemaUtil._property_schema("string", description)

    @staticmethod
    def string_property_with_default(description: str, default_value: str) -> dict[str, Any]:
        """Create a string property schema with a default value."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.string_property_with_default")
        return SchemaUtil._property_schema("string", description, default=default_value)

    @staticmethod
    def optional_string_property(description: str) -> dict[str, Any]:
        """Create an optional string property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.optional_string_property")
        return SchemaUtil.string_property(description)

    @staticmethod
    def boolean_property(description: str) -> dict[str, Any]:
        """Create a boolean property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.boolean_property")
        return SchemaUtil._property_schema("boolean", description)

    @staticmethod
    def boolean_property_with_default(description: str, default_value: bool) -> dict[str, Any]:
        """Create a boolean property schema with a default value."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.boolean_property_with_default")
        return SchemaUtil._property_schema("boolean", description, default=default_value)

    @staticmethod
    def optional_boolean_property(description: str) -> dict[str, Any]:
        """Create an optional boolean property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.optional_boolean_property")
        return SchemaUtil.boolean_property(description)

    @staticmethod
    def integer_property(description: str) -> dict[str, Any]:
        """Create an integer property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.integer_property")
        return SchemaUtil._property_schema("integer", description)

    @staticmethod
    def integer_property_with_default(description: str, default_value: int) -> dict[str, Any]:
        """Create an integer property schema with a default value."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.integer_property_with_default")
        return SchemaUtil._property_schema("integer", description, default=default_value)

    @staticmethod
    def optional_integer_property(description: str) -> dict[str, Any]:
        """Create an optional integer property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.optional_integer_property")
        return SchemaUtil.integer_property(description)

    @staticmethod
    def number_property(description: str) -> dict[str, Any]:
        """Create a number property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.number_property")
        return SchemaUtil._property_schema("number", description)

    @staticmethod
    def array_property(description: str, items: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an array property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.array_property")
        return SchemaUtil._property_schema("array", description, items=items)

    @staticmethod
    def object_property(description: str, properties: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an object property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.object_property")
        return SchemaUtil._property_schema("object", description, properties=properties)

    @staticmethod
    def enum_property(description: str, enum_values: list[str]) -> dict[str, Any]:
        """Create an enum property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.enum_property")
        return SchemaUtil._property_schema("string", description, enum=enum_values)

    @staticmethod
    def create_optional_object_property(description: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create an optional object property schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.create_optional_object_property")
        return SchemaUtil.object_property(description, properties)

    @staticmethod
    def create_schema(
        properties: dict[str, Any],
        required: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a complete JSON schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.create_schema")
        schema = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required
        return schema

    @staticmethod
    def builder() -> SchemaBuilder:
        """Create a schema builder for fluent API."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaUtil.builder")
        return SchemaBuilder()


class SchemaBuilder:
    """Fluent builder for creating JSON schemas."""

    def __init__(self):
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.__init__")
        self._properties: dict[str, Any] = {}
        self._required: list[str] = []

    def _add_property(self, name: str, prop: dict[str, Any]) -> SchemaBuilder:
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder._add_property")
        self._properties[name] = prop
        return self

    def string_property(self, name: str, description: str, default: str | None = None) -> SchemaBuilder:
        """Add a string property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.string_property")
        prop = SchemaUtil.string_property(description)
        if default is not None:
            prop["default"] = default
        return self._add_property(name, prop)

    def boolean_property(self, name: str, description: str, default: bool | None = None) -> SchemaBuilder:
        """Add a boolean property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.boolean_property")
        prop = SchemaUtil.boolean_property(description)
        if default is not None:
            prop["default"] = default
        return self._add_property(name, prop)

    def integer_property(self, name: str, description: str, default: int | None = None) -> SchemaBuilder:
        """Add an integer property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.integer_property")
        prop = SchemaUtil.integer_property(description)
        if default is not None:
            prop["default"] = default
        return self._add_property(name, prop)

    def enum_property(self, name: str, description: str, values: list[str]) -> SchemaBuilder:
        """Add an enum property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.enum_property")
        return self._add_property(name, SchemaUtil.enum_property(description, values))

    def array_property(self, name: str, description: str, items: dict[str, Any] | None = None) -> SchemaBuilder:
        """Add an array property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.array_property")
        return self._add_property(name, SchemaUtil.array_property(description, items))

    def object_property(self, name: str, description: str, properties: dict[str, Any] | None = None) -> SchemaBuilder:
        """Add an object property."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.object_property")
        return self._add_property(name, SchemaUtil.object_property(description, properties))

    def required(self, *names: str) -> SchemaBuilder:
        """Mark properties as required."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.required")
        self._required.extend(names)
        return self

    def build(self) -> dict[str, Any]:
        """Build the final schema."""
        logger.debug("diag.enter %s", "mcp_utils/schema_util.py:SchemaBuilder.build")
        return SchemaUtil.create_schema(self._properties, self._required or None)
