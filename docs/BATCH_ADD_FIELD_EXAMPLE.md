# Batch Add Field Example

This document demonstrates how to use the batch `add_field` action in the `manage-structures` tool to add multiple fields to a structure in a single operation.

## Problem

Previously, adding multiple fields to a structure required separate tool calls for each field:

```json
// Call 1
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "list04_active_ptr",
    "dataType": "void *",
    "offset": 56
  }
}

// Call 2
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "list04_active_count",
    "dataType": "int",
    "offset": 60
  }
}

// ... 4 more calls ...
```

## Solution

With batch mode, you can add all fields in a single call using the `fields` array parameter:

```json
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fields": [
      {
        "fieldName": "list04_active_ptr",
        "dataType": "void *",
        "offset": 56
      },
      {
        "fieldName": "list04_active_count",
        "dataType": "int",
        "offset": 60
      },
      {
        "fieldName": "list04_active_capacity",
        "dataType": "int",
        "offset": 64
      },
      {
        "fieldName": "list05_dynamic_ptr",
        "dataType": "void *",
        "offset": 68
      },
      {
        "fieldName": "list05_dynamic_count",
        "dataType": "int",
        "offset": 72
      },
      {
        "fieldName": "list05_dynamic_capacity",
        "dataType": "int",
        "offset": 76
      }
    ]
  }
}
```

## Benefits

1. **Performance**: All fields are added in a single transaction, reducing overhead
2. **Atomicity**: All fields are added together or none at all
3. **Better Error Handling**: Individual field errors are reported without failing the entire operation
4. **Network Efficiency**: Only one MCP call instead of multiple

## Response Format

The batch operation returns detailed results:

```json
{
  "success": true,
  "structureName": "LightManager",
  "total": 6,
  "succeeded": 6,
  "failed": 0,
  "results": [
    {
      "index": 0,
      "fieldName": "list04_active_ptr",
      "dataType": "void *",
      "offset": 56,
      "fieldOrdinal": 0
    },
    {
      "index": 1,
      "fieldName": "list04_active_count",
      "dataType": "int",
      "offset": 60,
      "fieldOrdinal": 1
    }
    // ... more results ...
  ],
  "message": "Successfully added 6 field(s) to structure: LightManager",
  "name": "LightManager",
  "size": 80,
  "fields": [
    /* complete structure definition */
  ]
}
```

## Field Object Properties

Each field object in the `fields` array must have:
- `fieldName` (required): Name of the field
- `dataType` (required): Data type (e.g., "int", "void *", "char[32]")
- `offset` (optional): Byte offset in the structure. Omit to append at the end.
- `comment` (optional): Comment for the field

## Backwards Compatibility

The single-field syntax still works for adding one field at a time:

```json
{
  "name": "manage-structures",
  "arguments": {
    "action": "add_field",
    "programPath": "/k1_win_gog_swkotor.exe",
    "structureName": "LightManager",
    "fieldName": "myField",
    "dataType": "int",
    "offset": 80,
    "comment": "My field comment"
  }
}
```

## Error Handling

If individual fields fail during batch mode, they are reported in the `errors` array:

```json
{
  "success": true,
  "structureName": "LightManager",
  "total": 6,
  "succeeded": 5,
  "failed": 1,
  "results": [ /* 5 successful fields */ ],
  "errors": [
    {
      "index": 3,
      "fieldName": "invalid_field",
      "error": "Failed to parse data type: UnknownType"
    }
  ],
  "message": "Successfully added 5 field(s) to structure: LightManager"
}
```

The operation continues adding other fields even if one fails.
