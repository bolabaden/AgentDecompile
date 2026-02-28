# AgentDecompile Import/Export Guide

This document explains how to import and export binary files and analysis data using AgentDecompile tools.

## Overview

AgentDecompile provides comprehensive import/export capabilities through two main tools:

- **`import-binary`** - Import binary files and entire directories into the Ghidra project
- **`export`** - Export programs in multiple formats (SARIF, GZF, C/C++, etc.)

## Supported Export Formats

| Format | Description | Use Case | File Extension |
|--------|-------------|----------|-----------------|
| **ASCII** | Plain text format | Text editors, terminal | `.txt` |
| **C/C++** | Decompiled C/C++ source code | Code review, documentation | `.cpp`, `.c` |
| **GZF** | Ghidra Zipped File (packed project) | Archiving, sharing analyzed projects | `.gzf` |
| **HTML** | Human-readable report | Web viewing, documentation | `.html` |
| **SARIF** | SARIF 2.1.0 analysis report | Security analysis, CI/CD integration | `.sarif` |
| **XML** | Structured program metadata | Data interchange, custom processing | `.xml` |

## Tool: `import-binary`

### Purpose
Import binary files or entire directories for analysis in Ghidra.

### Basic Usage

```bash
# Import a single binary
agentdecompile-cli tool import-binary '{
  "path": "/path/to/binary.exe",
  "destinationFolder": "/binaries",
  "analyzeAfterImport": true
}'

# Import a directory recursively
agentdecompile-cli tool import-binary '{
  "path": "/path/to/binaries",
  "recursive": true,
  "maxDepth": 3,
  "mirrorFs": true,
  "analyzeAfterImport": true
}'
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | **required** | File or directory path to import |
| `destinationFolder` | string | `/` | Project folder destination |
| `recursive` | boolean | `false` | Import subdirectories |
| `maxDepth` | integer | unlimited | Recursion depth limit |
| `analyzeAfterImport` | boolean | `true` | Run Ghidra analysis post-import |
| `stripLeadingPath` | boolean | `false` | Strip leading paths from names |
| `stripAllContainerPath` | boolean | `false` | Strip all container paths |
| `mirrorFs` | boolean | `false` | Mirror filesystem structure |
| `enableVersionControl` | boolean | `false` | Enable version tracking |

### Response

```json
{
  "success": true,
  "importedFrom": "/path/to/binaries",
  "filesDiscovered": 5,
  "filesImported": 5,
  "importedPrograms": [
    "/binaries/app.exe",
    "/binaries/lib.dll",
    "/binaries/tools/utility.exe"
  ],
  "groupsCreated": 0,
  "analysisRequested": true
}
```

## Tool: `export`

### Purpose
Export program data in various formats for analysis, documentation, or archival.

### Basic Usage

#### Export SARIF (Security Analysis)

```bash
# Export static analysis results as SARIF 2.1.0
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./analysis.sarif",
  "format": "sarif"
}'
```

**SARIF Feature Highlights:**
- Comprehensive analysis data collection (external references, bookmarks, function analysis)
- SARIF 2.1.0 compliant format
- Integration with security scanning tools (CodeQL, semgrep, etc.)
- Suitable for CI/CD pipelines and compliance reporting

**Example SARIF Structure:**
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "AgentDecompile",
          "version": "1.0.0",
          "rules": [
            {
              "id": "undefined-reference",
              "name": "Undefined Reference",
              "level": "warning"
            },
            {
              "id": "analysis-bookmark",
              "name": "Analysis Bookmark",
              "level": "note"
            },
            {
              "id": "analysis-warning",
              "name": "Analysis Warning",
              "level": "warning"
            }
          ]
        }
      },
      "artifacts": [
        {
          "uri": "app.exe",
          "sourceLanguage": "asm",
          "properties": {
            "imageBase": "0x400000"
          }
        }
      ],
      "results": [
        {
          "ruleId": "undefined-reference",
          "message": {"text": "External reference at 0x401000 to some_api"},
          "level": "warning",
          "locations": [...]
        }
      ],
      "properties": {
        "analysisComplete": true,
        "generatedAt": "2026-02-28T12:00:00Z",
        "resultsCount": 42
      }
    }
  ]
}
```

#### Export GZF (Ghidra Archive)

```bash
# Export as Ghidra Zipped File for archival/sharing
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./app_analyzed.gzf",
  "format": "gzf"
}'
```

**GZF Feature Highlights:**
- Compressed Ghidra project snapshot
- Preserves all analysis data (functions, types, bookmarks, comments)
- Portable between machines/instances
- Can be reopened in Ghidra GUI or loaded via agentdecompile

#### Export C/C++ Source

```bash
# Export decompiled C++ source code with types
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./decompiled.cpp",
  "format": "cpp",
  "createHeader": true,
  "includeTypes": true,
  "includeGlobals": true
}'

# Export minimal C code
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./decompiled.c",
  "format": "c",
  "createHeader": false,
  "includeTypes": false
}'
```

**C/C++ Export Parameters:**
- `createHeader` - Generate header file with declarations (default: `true`)
- `includeTypes` - Emit type definitions (default: `true`)
- `includeGlobals` - Emit global variable declarations (default: `true`)
- `tags` - Optional tag filter string for selective export

#### Export Other Formats

```bash
# XML format
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./metadata.xml",
  "format": "xml"
}'

# HTML format (human-readable)
agentdecompile-cli tool export '{
  "programPath": "/binaries/app.exe",
  "outputPath": "./report.html",
  "format": "html"
}'
```

### Export Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `programPath` | string | required | Path to the program to export |
| `outputPath` | string | required | Output file path |
| `format` | string | `cpp` | Export format: `sarif`, `gzf`, `c`, `cpp`, `cxx`, `xml`, `html`, `ascii` |
| `createHeader` | boolean | `true` | Emit header file (C/C++ only) |
| `includeTypes` | boolean | `true` | Emit type definitions (C/C++ only) |
| `includeGlobals` | boolean | `true` | Emit globals (C/C++ only) |
| `includeComments` | boolean | `false` | Include comments in output |
| `tags` | string | - | Tag filter for selective export |

### Export Response

```json
{
  "action": "export",
  "format": "sarif",
  "outputPath": "/path/to/analysis.sarif",
  "success": true,
  "resultsCollected": 42,
  "apiClass": "SARIF 2.1.0"
}
```

## Workflow Examples

### Example 1: Complete Analysis Workflow

```bash
# 1. Import binary
agentdecompile-cli tool import-binary '{
  "path": "/myapp/binary.exe",
  "analyzeAfterImport": true
}'

# 2. Export SARIF for security scanning
agentdecompile-cli tool export '{
  "programPath": "/myapp/binary.exe",
  "outputPath": "./analysis.sarif",
  "format": "sarif"
}'

# 3. Export C++ for code review
agentdecompile-cli tool export '{
  "programPath": "/myapp/binary.exe",
  "outputPath": "./decompiled.cpp",
  "format": "cpp"
}'

# 4. Export GZF for archival
agentdecompile-cli tool export '{
  "programPath": "/myapp/binary.exe",
  "outputPath": "./analyzed_backup.gzf",
  "format": "gzf"
}'
```

### Example 2: Batch Directory Import with Analysis

```bash
# Import entire directory with folder structure preserved
agentdecompile-cli tool import-binary '{
  "path": "/firmware",
  "recursive": true,
  "maxDepth": 4,
  "mirrorFs": true,
  "analyzeAfterImport": true
}'

# Then export all programs
# (Note: currently requires running CLI separately for each program)
```

### Example 3: CI/CD Integration

```bash
#!/bin/bash
# Script to automatically export SARIF for CI/CD

BINARY_PATH="/artifacts/release.exe"
OUTPUT_SARIF="./results/analysis.sarif"

# Import and analyze
agentdecompile-cli tool import-binary "{
  \"path\": \"$BINARY_PATH\",
  \"analyzeAfterImport\": true
}"

# Extract program path
PROGRAM_PATH=$(agentdecompile-cli list binaries -f json | jq -r '.programs[0]')

# Export SARIF
agentdecompile-cli tool export "{
  \"programPath\": \"$PROGRAM_PATH\",
  \"outputPath\": \"$OUTPUT_SARIF\",
  \"format\": \"sarif\"
}"

# Pass to downstream tools
sarif-fmt "$OUTPUT_SARIF"  # Format output
```

## Resource API

In addition to tools, AgentDecompile provides MCP resources for reading data:

### `ghidra://static-analysis-results`

Read comprehensive static analysis results in SARIF 2.1.0 format:

```bash
agentdecompile-cli resource static-analysis
```

This resource provides real-time analysis data and is equivalent to exporting with `format="sarif"`.

## Format Comparison

| Use Case | Recommended Format | Reason |
|----------|-------------------|--------|
| Security scanning | SARIF | Standard format for security tools |
| Project sharing | GZF | Preserves all analysis; portable |
| Code documentation | C/C++ | Human-readable, source-compatible |
| Archival/backup | GZF | Complete snapshot of analysis |
| Data interchange | XML | Structured, tool-agnostic |
| Web viewing | HTML | Formatted for browsers |
| Quick inspection | ASCII | Terminal-friendly |

## Advanced Topics

### Custom Analysis with SARIF

The SARIF export automatically collects:
- **External references** - APIs and undefined symbols (truncated to 50 results)
- **Bookmarks** - Analysis markers and notes (truncated to 30 results)
- **Function analysis** - Thunk functions, external functions (first 50 functions)

To export custom analysis, you can extend the SARIF generation in `export` tool or use the `ghidra://static-analysis-results` resource.

### Version Control

When importing with `enableVersionControl=true`, AgentDecompile tracks program versions:

```bash
agentdecompile-cli tool import-binary '{
  "path": "/binaries/app.exe",
  "enableVersionControl": true
}'
```

This enables:
- Program version history
- Change tracking
- Collaborative analysis
- Rollback capability

### Large Binary Handling

For large binaries:
1. Import with `analyzeAfterImport=false`
2. Analyze manually or in background
3. Export when ready

```bash
agentdecompile-cli tool import-binary '{
  "path": "/large_binary.bin",
  "analyzeAfterImport": false
}'

# Later: analyze manually
agentdecompile-cli tool analyze-program '{
  "programPath": "/large_binary.bin"
}'
```

## Troubleshooting

### Export Fails with "No Program Loaded"

**Solution:** Use the full programPath from `list binaries`:

```bash
# Get program path
agentdecompile-cli list binaries -f json

# Use full path in export
agentdecompile-cli tool export '{
  "programPath": "/projects/myapp/binary.exe",
  "outputPath": "./output.sarif",
  "format": "sarif"
}'
```

### SARIF Contains No Results

**Cause:** Analysis incomplete. **Solution:** Re-run import with `analyzeAfterImport=true` or call `analyze-program`.

### GZF Export Fails

**Cause:** No active Ghidra project. **Solution:** Ensure binary was imported via `import-binary`, not just opened.

## See Also

- [TOOLS_LIST.md](../TOOLS_LIST.md) - Complete tool reference
- [MCP_AGENTDECOMPILE_USAGE.md](./MCP_AGENTDECOMPILE_USAGE.md) - Full MCP documentation
- [SARIF 2.1.0 Spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/csd02/sarif-v2.1.0-csd02.html)
