# Structure Size Preservation in manage-structures Tool

## Problem

When using the `manage-structures` tool's `add_field` action with batch operations, structures can grow beyond their intended size. This is caused by Ghidra's `insertAtOffset()` method, which shifts existing components to avoid conflicts, potentially expanding the structure.

### Example Scenario

```
1. Create structure with size=743 bytes
2. Add field "Gob" at offset 248 (size 464 bytes)
3. Expected end: 248 + 464 = 712, with 31 bytes padding = 743 bytes
4. Actual result: Structure grows to 1455 bytes due to automatic alignment and shifts
```

## Root Cause

Ghidra's `Structure.insertAtOffset()` behavior:
- Shifts conflicting components down to avoid overlap
- Adds automatic padding/alignment even with `packed=true` in some cases
- Recalculates structure size based on component placements
- Doesn't respect the original `size` parameter from `create` action

## Solutions

### Solution 1: Use `useReplace` Parameter (Recommended for add_field)

When adding fields with explicit offsets to non-packed structures, use `useReplace=true`:

```json
{
  "name": "manage-structures",
  "arguments": {
    "programPath": "/foo.exe",
    "action": "add_field",
    "structureName": "Scene",
    "useReplace": true,
    "fields": [
      {"fieldName": "field1", "dataType": "int", "offset": 0},
      {"fieldName": "Gob", "dataType": "Gob", "offset": 248},
      {"fieldName": "field2", "dataType": "int", "offset": 712}
    ]
  }
}
```

**How it works:**
- Uses `replaceAtOffset()` instead of `insertAtOffset()`
- Replaces undefined bytes at the offset without shifting
- Preserves structure size by consuming existing space
- Best for non-packed structures with explicit field layouts

### Solution 2: Use `preserveSize` Parameter (Validation)

Detect and reject operations that would grow the structure:

```json
{
  "name": "manage-structures",
  "arguments": {
    "programPath": "/foo.exe",
    "action": "add_field",
    "structureName": "Scene",
    "preserveSize": true,
    "fields": [...]
  }
}
```

**How it works:**
- Records original structure size before adding fields
- Validates final size matches original size after all operations
- Rolls back transaction and returns error if size grew
- Provides detailed error message explaining the issue

### Solution 3: Use `parse_header` Action (Best for Complex Structures)

For complex structures with precise byte layouts, use a complete C definition:

```json
{
  "name": "manage-structures",
  "arguments": {
    "programPath": "/foo.exe",
    "action": "parse_header",
    "headerContent": "#pragma pack(push, 1)\nstruct Scene {\n  int field1;\n  char padding1[244];\n  Gob gob;\n  char padding2[31];\n};\n#pragma pack(pop)"
  }
}
```

**Why it works:**
- Parses entire structure definition atomically
- Respects `#pragma pack(push, 1)` for byte alignment
- Calculates size from complete layout at once
- Doesn't iteratively expand like `add_field`

## Response Fields

All `add_field` operations now include size tracking information:

```json
{
  "success": true,
  "originalSize": 743,
  "finalSize": 743,
  "sizeGrew": false,
  "structureName": "Scene",
  "succeeded": 50,
  "message": "Successfully added 50 field(s) to structure: Scene"
}
```

If size grows:

```json
{
  "success": true,
  "originalSize": 743,
  "finalSize": 1455,
  "sizeGrew": true,
  "sizeGrowth": 712,
  "sizeWarning": "Structure grew from 743 to 1455 bytes. Consider using useReplace=true or parse_header action for byte-perfect layouts.",
  "message": "Successfully added 50 field(s) to structure: Scene"
}
```

## Comparison Matrix

| Approach | Pros | Cons | Best For |
|----------|------|------|----------|
| `useReplace=true` (default) | Preserves size, works with batch | Requires explicit offsets | Non-packed structures with known offsets |
| `preserveSize=true` | Detects issues, safe validation | Doesn't fix the problem, just detects it | Testing and validation |
| `parse_header` | Atomic, byte-perfect, respects pragmas | Requires full C definition | Complex structures, embedded types |
| `useReplace=false` | Simple, no extra params | May grow structure unexpectedly | Packed structures, appending fields |

## Technical Details

### Ghidra API Methods

- **`insertAtOffset(offset, dataType, length, name, comment)`**
  - Behavior: Inserts field, shifts conflicting components down
  - Effect: Can grow structure beyond intended size
  - Use when: Inserting into packed structures or when shifting is desired

- **`replaceAtOffset(offset, dataType, length, name, comment)`**
  - Behavior: Replaces existing bytes at offset
  - Effect: Consumes undefined bytes, preserves structure layout
  - Use when: Non-packed structures with explicit byte layout

- **`setLength(length)`**
  - Behavior: Sets structure size (non-packed only)
  - Effect: Trims or grows structure
  - Note: Only affects non-packed structures

### Why `parse_header` Works

The C parser:
1. Parses the entire structure definition in one operation
2. Respects `#pragma pack(push, 1)` directives
3. Calculates component offsets and padding atomically
4. Creates structure with exact layout in single transaction

## Migration Guide

**As of this fix, `useReplace` now defaults to `true`, so the size growth issue is resolved by default.** 

If you have existing code that relied on the old `insertAtOffset` behavior (where fields get shifted to make room), you may need to explicitly set `useReplace=false`:

### Before (Size Growth Issue - Now Fixed by Default)
```json
{
  "action": "add_field",
  "structureName": "Scene",
  "fields": [{"fieldName": "Gob", "dataType": "Gob", "offset": 248}]
}
// Result: Structure stays at intended size (743 bytes)
```

### If You Need the Old Shifting Behavior
```json
{
  "action": "add_field",
  "structureName": "Scene",
  "useReplace": false,  // Explicitly disable to get old behavior
  "fields": [{"fieldName": "Gob", "dataType": "Gob", "offset": 248}]
}
// Result: Structure may grow (1455+ bytes) due to shifting
```

## FAQ

**Q: Why does `packed=true` in `create` not prevent size growth?**
A: The `packed` flag tells Ghidra to minimize alignment padding, but `insertAtOffset()` still shifts components to avoid conflicts, which can grow the structure.

**Q: When should I use `useReplace` vs `parse_header`?**
A: `useReplace=true` is now the default behavior, so you don't need to specify it. Use `parse_header` when you have the complete structure definition upfront or need byte-perfect control.

**Q: Can I use `preserveSize` and `useReplace` together?**
A: Yes! `preserveSize=true` adds validation, while `useReplace=true` (the default) prevents the growth. Using both provides maximum safety.

**Q: What if I need to insert a field in the middle and shift everything?**
A: Set `useReplace=false` to use the old `insertAtOffset` behavior. The shifting is intentional in that case. Just be aware the structure will grow.

**Q: Does `useReplace` work with unions?**
A: No, `add_field` is only supported for structures, not unions.

## Implementation Notes

For developers maintaining this code:

1. **Size tracking**: Original size is recorded at start of transaction
2. **Validation**: `preserveSize` checks size before committing transaction
3. **Method selection**: `useReplace` switches from `insertAtOffset()` to `replaceAtOffset()`
4. **Warning messages**: All operations return size tracking info in response
5. **Rollback**: Failed `preserveSize` validation rolls back entire transaction

See `StructureToolProvider.handleBatchAddFields()` for implementation details.
