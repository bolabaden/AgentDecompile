# Quick Start: SARIF/GZF Import & Export

## 🎯 What's Implemented

AgentDecompile now provides complete import/export capabilities for SARIF security analysis, GZF project archives, and C/C++ source code.

## 📦 Supported Formats

| Format | Purpose | Command |
|--------|---------|---------|
| **SARIF 2.1.0** | Security analysis results | `export format=sarif` |
| **GZF** | Ghidra project archive | `export format=gzf` |
| **C/C++** | Decompiled source | `export format=cpp` |
| **XML** | Metadata export | `export format=xml` |
| **HTML** | Report view | `export format=html` |

## 🚀 Quick Examples

### 1️⃣ Export SARIF Analysis

```bash
agentdecompile-cli tool export '{
  "programPath": "/path/to/binary.exe",
  "outputPath": "./analysis.sarif",
  "format": "sarif"
}'
```

**Output**: SARIF 2.1.0 JSON with:
- Undefined references (external symbols)
- Analysis bookmarks
- Function metadata
- Tool metadata and rules

### 2️⃣ Export GZF Archive

```bash
agentdecompile-cli tool export '{
  "programPath": "/path/to/binary.exe",
  "outputPath": "./analyzed.gzf",
  "format": "gzf"
}'
```

**Output**: Portable Ghidra project archive with all analysis data

### 3️⃣ Import Binary for Analysis

```bash
agentdecompile-cli tool import-binary '{
  "path": "/path/to/binary.exe",
  "analyzeAfterImport": true
}'
```

### 4️⃣ Import Directory Recursively

```bash
agentdecompile-cli tool import-binary '{
  "path": "/firmware_dump",
  "recursive": true,
  "maxDepth": 3,
  "mirrorFs": true,
  "analyzeAfterImport": true
}'
```

### 5️⃣ Read Static Analysis Resource

```bash
# Read SARIF data via MCP resource interface
agentdecompile-cli resource static-analysis
```

## 📋 Key Features

✅ **SARIF 2.1.0 Compliance**
- Standard format for security tools
- CI/CD pipeline ready
- Results include: undefined refs, bookmarks, function analysis

✅ **Comprehensive Analysis Data**
- External references (limit: 50)
- Analysis bookmarks (limit: 30)  
- Function metadata - thunk/external (limit: 50 scans)

✅ **Import Options**
- Single files or recursive directories
- Depth control
- Filesystem mirroring
- Optional automatic analysis
- Version control support

✅ **Multiple Export Formats**
- SARIF, GZF, C/C++, XML, HTML, ASCII
- Customizable output (headers, types, globals, comments)

## 🔍 Understanding SARIF Output

SARIF files contain:

```json
{
  "tool": {
    "driver": {
      "rules": [
        "undefined-reference",    // External API symbols
        "analysis-bookmark",      // Marked regions
        "analysis-warning"        // Function anomalies
      ]
    }
  },
  "results": [
    {
      "ruleId": "undefined-reference",
      "message": "External reference to kernel32.dll",
      "location": "0x401000"
    }
  ]
}
```

## 📚 Documentation

- **[IMPORT_EXPORT_GUIDE.md](./IMPORT_EXPORT_GUIDE.md)** - Full user guide
- **[IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md)** - Technical details
- **[TOOLS_LIST.md](../TOOLS_LIST.md)** - Tool reference

## ⚙️ How It Works Under The Hood

### SARIF Export Pipeline
1. Collect external references from ReferenceManager (50 max)
2. Collect bookmarks from BookmarkManager (30 max)
3. Scan functions for analysis warnings (50 functions scanned)
4. Generate SARIF 2.1.0 JSON with all findings
5. Write to output file

### Static Analysis Resource
The `ghidra://static-analysis-results` MCP resource provides real-time SARIF data without exporting to disk.

### Import Pipeline  
1. Discover binaries in path/directory
2. Create project structure
3. Import each binary
4. Run optional automatic analysis
5. Track versions if enabled

## 🛠️ Troubleshooting

### Export fails: "No Program Loaded"
**Solution**: Use full programPath from `list binaries`, or import first

### SARIF contains no results
**Solution**: Ensure analysis is complete. Re-import with `analyzeAfterImport=true`

### GZF file not created
**Solution**: Verify binary was imported via `import-binary`, not just opened

## ✨ Use Cases

### Security Analysis
```bash
# Export SARIF for security scanning tool
export format=sarif outputPath=findings.sarif

# Import into security dashboard
# Use with: CodeQL, semgrep, IDA Pro, etc.
```

### Project Sharing
```bash
# Archive analyzed project
export format=gzf outputPath=analysis.gzf

# Share with team via email/storage
# Can be reopened in Ghidra GUI or agentdecompile
```

### Code Review
```bash
# Export decompiled source
export format=cpp outputPath=decompiled.cpp

# Review in IDE or version control system
```

### Batch Processing
```bash
# Import firmware dump
import-binary path=/firmware recursive=true mirrorFs=true

# Export all binaries as SARIF
# (Requires loop in calling script)
```

## 🎓 Next Steps

1. **Import a binary**: `import-binary path="/your/binary"`
2. **Export SARIF**: `export format=sarif outputPath="results.sarif"`
3. **View results**: Open `results.sarif` in your IDE
4. **Share archive**: `export format=gzf outputPath="analysis.gzf"`

---

**Status**: ✅ Ready to use  
**Formats Supported**: SARIF, GZF, C/C++, XML, HTML, ASCII  
**Documentation**: Complete
