"""Schema utility functions for AgentDecompile Python implementation.

Provides MCP schema creation utilities, .
"""

from __future__ import annotations

from typing import Any


class SchemaUtil:
    """Utility methods for creating MCP JSON schemas."""

    @staticmethod
    def string_property(description: str) -> dict[str, Any]:
        """Create a string property schema."""
        return {
            "type": "string",
            "description": description,
        }

    @staticmethod
    def string_property_with_default(description: str, default_value: str) -> dict[str, Any]:
        """Create a string property schema with a default value."""
        return {
            "type": "string",
            "description": description,
            "default": default_value,
        }

    @staticmethod
    def optional_string_property(description: str) -> dict[str, Any]:
        """Create an optional string property schema."""
        return SchemaUtil.string_property(description)

    @staticmethod
    def boolean_property(description: str) -> dict[str, Any]:
        """Create a boolean property schema."""
        return {
            "type": "boolean",
            "description": description,
        }

    @staticmethod
    def boolean_property_with_default(description: str, default_value: bool) -> dict[str, Any]:
        """Create a boolean property schema with a default value."""
        return {
            "type": "boolean",
            "description": description,
            "default": default_value,
        }

    @staticmethod
    def optional_boolean_property(description: str) -> dict[str, Any]:
        """Create an optional boolean property schema."""
        return SchemaUtil.boolean_property(description)

    @staticmethod
    def integer_property(description: str) -> dict[str, Any]:
        """Create an integer property schema."""
        return {
            "type": "integer",
            "description": description,
        }

    @staticmethod
    def integer_property_with_default(description: str, default_value: int) -> dict[str, Any]:
        """Create an integer property schema with a default value."""
        return {
            "type": "integer",
            "description": description,
            "default": default_value,
        }

    @staticmethod
    def optional_integer_property(description: str) -> dict[str, Any]:
        """Create an optional integer property schema."""
        return SchemaUtil.integer_property(description)

    @staticmethod
    def number_property(description: str) -> dict[str, Any]:
        """Create a number property schema."""
        return {
            "type": "number",
            "description": description,
        }

    @staticmethod
    def array_property(description: str, items: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an array property schema."""
        schema = {
            "type": "array",
            "description": description,
        }
        if items:
            schema["items"] = items
        return schema

    @staticmethod
    def object_property(description: str, properties: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an object property schema."""
        schema = {
            "type": "object",
            "description": description,
        }
        if properties:
            schema["properties"] = properties
        return schema

    @staticmethod
    def enum_property(description: str, enum_values: list[str]) -> dict[str, Any]:
        """Create an enum property schema."""
        return {
            "type": "string",
            "description": description,
            "enum": enum_values,
        }

    @staticmethod
    def create_optional_object_property(description: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create an optional object property schema."""
        return SchemaUtil.object_property(description, properties)

    @staticmethod
    def create_schema(
        properties: dict[str, Any],
        required: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a complete JSON schema."""
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
        return SchemaBuilder()


class SchemaBuilder:
    """Fluent builder for creating JSON schemas."""

    def __init__(self):
        self._properties: dict[str, Any] = {}
        self._required: list[str] = []

    def string_property(self, name: str, description: str, default: str | None = None) -> SchemaBuilder:
        """Add a string property."""
        prop = SchemaUtil.string_property(description)
        if default is not None:
            prop["default"] = default
        self._properties[name] = prop
        return self

    def boolean_property(self, name: str, description: str, default: bool | None = None) -> SchemaBuilder:
        """Add a boolean property."""
        prop = SchemaUtil.boolean_property(description)
        if default is not None:
            prop["default"] = default
        self._properties[name] = prop
        return self

    def integer_property(self, name: str, description: str, default: int | None = None) -> SchemaBuilder:
        """Add an integer property."""
        prop = SchemaUtil.integer_property(description)
        if default is not None:
            prop["default"] = default
        self._properties[name] = prop
        return self

    def enum_property(self, name: str, description: str, values: list[str]) -> SchemaBuilder:
        """Add an enum property."""
        self._properties[name] = SchemaUtil.enum_property(description, values)
        return self

    def array_property(self, name: str, description: str, items: dict[str, Any] | None = None) -> SchemaBuilder:
        """Add an array property."""
        self._properties[name] = SchemaUtil.array_property(description, items)
        return self

    def object_property(self, name: str, description: str, properties: dict[str, Any] | None = None) -> SchemaBuilder:
        """Add an object property."""
        self._properties[name] = SchemaUtil.object_property(description, properties)
        return self

    def required(self, *names: str) -> SchemaBuilder:
        """Mark properties as required."""
        self._required.extend(names)
        return self

    def build(self) -> dict[str, Any]:
        """Build the final schema."""
        return SchemaUtil.create_schema(self._properties, self._required if self._required else None)
