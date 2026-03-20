# Exhaustive AgentDecompile Tools Reference (Python MCP Implementation)

This document provides an exhaustive, consolidated reference for all canonical tools implemented in the Python MCP (from `src/agentdecompile_cli/registry.py`), including all aliases and synonyms. Each tool is documented once under its canonical name, with aliases/synonyms forwarding to the primary entry (no logic duplication). Parameter normalization handles casing and separators (e.g., `programPath` = `program_path` = `programPath`). Overloads are documented explicitly per canonical tool. Descriptions are detailed, expert-crafted paragraphs explaining the tool's purpose, behavior, and use cases. All parameters are fully documented, including types where specified. Synonyms for parameters are listed exhaustively. Each tool includes an examples section with practical usage scenarios.

**Legacy naming policy**: only the default curated advertised tool names are considered primary. Any other tool name in this document (including non-default canonical names and synonyms) is a legacy compatibility name. Legacy names remain callable, and can be re-advertised by setting `AGENTDECOMPILE_SHOW_LEGACY_TOOLS=1` or `AGENTDECOMPILE_ENABLE_LEGACY_TOOLS=1`.

**GUI vs Headless**: `programPath` (and synonyms) is optional in GUI mode (uses active program) but required in headless for program-scoped tools.

## Server Configuration

### Local project

Control which Ghidra project the server uses via environment variable or CLI argument:

| What | Env var | CLI arg | Notes |
|------|---------|---------|-------|
| Project directory or `.gpr` file | `AGENT_DECOMPILE_PROJECT_PATH` (alias: `AGENTDECOMPILE_PROJECT_PATH`) | `--project-path <path>` | Directory for a new/existing directory-backed project, or path to a `.gpr` file for an existing project. Default: `agentdecompile_projects/` in cwd. |
| Project name | `AGENT_DECOMPILE_PROJECT_NAME` (alias: `AGENTDECOMPILE_PROJECT_NAME`) | `--project-name <name>` | Ignored when pointing to a `.gpr` file. Default: current working directory name. |

```bash
# Directory-backed project (creates if absent)
agentdecompile-server -t streamable-http \
  --project-path /my/projects/analysis \
  --project-name analysis

# Existing Ghidra .gpr file (name inferred from filename)
agentdecompile-server -t streamable-http \
  --project-path /my/projects/analysis.gpr

# Via environment variable (stdio, e.g. Claude Desktop / VS Code MCP)
AGENT_DECOMPILE_PROJECT_PATH=/my/projects/analysis mcp-agentdecompile
```

## Table of Contents

- [Exhaustive AgentDecompile Tools Reference (Python MCP Implementation)](#exhaustive-agentdecompile-tools-reference-python-mcp-implementation)
  - [Server Configuration](#server-configuration)
    - [Local project](#local-project)
  - [Table of Contents](#table-of-contents)
  - [Canonical Tool Docs](#canonical-tool-docs)
    - [`analyze-data-flow`](#analyze-data-flow)
    - [`analyze-program`](#analyze-program)
    - [`analyze-vtables`](#analyze-vtables)
    - [`apply-data-type`](#apply-data-type)
    - [`change-processor`](#change-processor)
    - [`checkin-program`](#checkin-program)
    - [`create-label`](#create-label)
    - [`decompile-function`](#decompile-function)
    - [`sync-project`](#sync-project)
    - [`export`](#export)
    - [`delete-project-binary`](#delete-project-binary)
    - [`gen-callgraph`](#gen-callgraph)
    - [`get-call-graph`](#get-call-graph)
    - [`get-current-address`](#get-current-address)
    - [`get-current-function`](#get-current-function)
    - [`get-current-program`](#get-current-program)
    - [`get-data`](#get-data)
    - [`get-functions`](#get-functions)
    - [`get-references`](#get-references)
    - [`import-binary`](#import-binary)
    - [`inspect-memory`](#inspect-memory)
    - [`list-cross-references`](#list-cross-references)
    - [`list-exports`](#list-exports)
    - [`list-functions`](#list-functions)
    - [`list-imports`](#list-imports)
    - [`list-open-programs`](#list-open-programs)
    - [`list-project-binaries`](#list-project-binaries)
    - [`list-project-binary-metadata`](#list-project-binary-metadata)
    - [`list-project-files`](#list-project-files)
    - [`list-processors`](#list-processors)
    - [`list-prompts`](#list-prompts)
    - [`list-strings`](#list-strings)
    - [`match-function`](#match-function)
    - [`execute-script`](#execute-script)
    - [`open-all-programs-in-code-browser`](#open-all-programs-in-code-browser)
    - [`read-bytes`](#read-bytes)
    - [`resolve-modification-conflict`](#resolve-modification-conflict)
    - [`search-code`](#search-code)
    - [`search-constants`](#search-constants)
    - [`search-everything`](#search-everything)
    - [`search-strings`](#search-strings)
    - [`search-symbols`](#search-symbols)
    - [`search-symbols-by-name`](#search-symbols-by-name)
    - [`suggest`](#suggest)
  - [Usage Tips](#usage-tips)
    - [Start with High-Level Analysis](#start-with-high-level-analysis)
    - [Trace Data Flow](#trace-data-flow)
    - [Find Patterns](#find-patterns)
    - [Organize Findings](#organize-findings)
    - [Analyze C++ Binaries](#analyze-c-binaries)
    - [Manage Functions and Variables](#manage-functions-and-variables)
    - [Transfer Analysis Across Similar Binaries](#transfer-analysis-across-similar-binaries)
- [Reverse Engineering Skills \& Workflows](#reverse-engineering-skills--workflows)
  - [Binary Triage Skill](#binary-triage-skill)
    - [Systematic Triage Workflow](#systematic-triage-workflow)
      - [1. Identify the Program](#1-identify-the-program)
      - [2. Survey Memory Layout](#2-survey-memory-layout)
      - [3. Survey Strings](#3-survey-strings)
      - [4. Survey Symbols and Imports](#4-survey-symbols-and-imports)
      - [5. Survey Functions](#5-survey-functions)
      - [6. Cross-Reference Analysis for Key Findings](#6-cross-reference-analysis-for-key-findings)
      - [7. Selective Initial Decompilation](#7-selective-initial-decompilation)
      - [8. Document Findings](#8-document-findings)
  - [Deep Analysis Skill](#deep-analysis-skill)
    - [The Investigation Loop](#the-investigation-loop)
      - [1. READ - Gather Current Context (1-2 tool calls)](#1-read---gather-current-context-1-2-tool-calls)
      - [2. UNDERSTAND - Analyze What You See](#2-understand---analyze-what-you-see)
      - [3. IMPROVE - Make Small Database Changes (1-3 tool calls)](#3-improve---make-small-database-changes-1-3-tool-calls)
      - [4. VERIFY - Re-read to Confirm Improvement (1 tool call)](#4-verify---re-read-to-confirm-improvement-1-tool-call)
      - [5. FOLLOW THREADS - Pursue Evidence (1-2 tool calls)](#5-follow-threads---pursue-evidence-1-2-tool-calls)
      - [6. TRACK PROGRESS - Document Findings (1 tool call)](#6-track-progress---document-findings-1-tool-call)
      - [7. ON-TASK CHECK - Stay Focused](#7-on-task-check---stay-focused)
    - [Question Type Strategies](#question-type-strategies)
      - ["What does function X do?"](#what-does-function-x-do)
      - ["Does this use cryptography?"](#does-this-use-cryptography)
      - ["Where does data X come from?"](#where-does-data-x-come-from)
  - [CTF Reverse Engineering Skill](#ctf-reverse-engineering-skill)
    - [The Three Questions Framework](#the-three-questions-framework)
    - [Key Pattern Recognition](#key-pattern-recognition)
      - [Simple XOR Patterns](#simple-xor-patterns)
      - [Base64 and Variants](#base64-and-variants)
      - [Block Cipher Patterns (AES, DES)](#block-cipher-patterns-aes-des)
      - [Input Validation Patterns](#input-validation-patterns)
    - [Static vs Dynamic Approach](#static-vs-dynamic-approach)
  - [CTF Cryptography Skill](#ctf-cryptography-skill)
    - [Four-Phase Framework](#four-phase-framework)
      - [Phase 1: Crypto Detection](#phase-1-crypto-detection)
      - [Phase 2: Algorithm Identification](#phase-2-algorithm-identification)
      - [Phase 3: Implementation Analysis](#phase-3-implementation-analysis)
      - [Phase 4: Key Extraction or Breaking](#phase-4-key-extraction-or-breaking)
    - [Cryptographic Pattern Library](#cryptographic-pattern-library)
      - [AES Recognition](#aes-recognition)
      - [DES Recognition](#des-recognition)
      - [RC4 Recognition](#rc4-recognition)
      - [RSA Recognition](#rsa-recognition)
  - [CTF Binary Exploitation (Pwn) Skill](#ctf-binary-exploitation-pwn-skill)
    - [The Exploitation Mindset](#the-exploitation-mindset)
      - [1. Data Flow Layer](#1-data-flow-layer)
      - [2. Memory Safety Layer](#2-memory-safety-layer)
      - [3. Exploitation Layer](#3-exploitation-layer)
    - [Core Question Sequence](#core-question-sequence)
    - [Vulnerability Discovery Patterns](#vulnerability-discovery-patterns)
      - [Unsafe String Operations](#unsafe-string-operations)
      - [Format String Vulnerabilities](#format-string-vulnerabilities)
      - [Buffer Overflow Analysis](#buffer-overflow-analysis)
    - [Exploitation Techniques](#exploitation-techniques)
      - [Return-Oriented Programming (ROP)](#return-oriented-programming-rop)
      - [GOT/PLT Overwrite](#gotplt-overwrite)
      - [Shellcode Injection](#shellcode-injection)
    - [Practical Workflow](#practical-workflow)

## Canonical Tool Docs

### `analyze-data-flow`

**Description**: This tool performs precise data flow analysis using Ghidra's decompiler P-code for backward/forward slicing and variable access tracking within a function. It enables taint analysis, value tracking, and algorithm reverse engineering by tracing data origins (backward), propagations (forward), or all reads/writes (variable_accesses). Outputs JSON paths with P-code operations, variables, and addresses, supporting pagination for large flows. All operations are transaction-safe and read-only unless explicitly modifying annotations. Ideal for understanding variable lifecycles in complex functions, debugging data dependencies, or identifying sources/sinks in security analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `functionAddress` (string, required): Address of the function to analyze.
  - Synonyms: `functionAddress`, `functiona`, `function`, `funcAddr`, `address`, `entryAddress`, `functionIdentifier`.
- `startAddress` (string, optional): Starting address for backward/forward traces.
  - Synonyms: `startAddress`, `starta`.
- `variableName` (string, optional): Variable name for `variable_accesses` mode.
  - Synonyms: `variableName`, `variablen`, `variable_name`.
- `direction` (string, required): Direction of analysis (`backward`, `forward`, or `variable_accesses`).
  - Synonyms: `mode`, `analysisMode`, `traceDirection`, `direction`, `dir`, `flow`, `traversalDirection`, `walkDirection`, `orientation`, `edgeDirection`, `pathDirection`.
**Overloads**:
- `find-variable-accesses(programPath, functionAddress, variableName)` → forwards to `analyze-data-flow`.
- `trace-data-flow-backward(programPath, address)` → forwards to `analyze-data-flow`.
- `trace-data-flow-forward(programPath, address)` → forwards to `analyze-data-flow`.

**Synonyms**: `analyze-data-flow`, `tool_analyze_data_flow`, `analyze_data_flow_tool`, `cmd_analyze_data_flow`, `run_analyze_data_flow`, `do_analyze_data_flow`, `api_analyze_data_flow`, `mcp_analyze_data_flow`, `ghidra_analyze_data_flow`, `agentdecompile_analyze_data_flow`, `analyze_data_flow_command`, `analyze_data_flow_action`, `analyze_data_flow_op`, `analyze_data_flow_task`, `execute_analyze_data_flow`, `find-variable-accesses`, `trace-data-flow-backward`, `trace-data-flow-forward`

**Examples**:
- Trace backward data flow: `analyze-data-flow programPath="/bin.exe" functionAddress="0x401000" direction="backward" startAddress="0x401020"`.
- List variable accesses: `analyze-data-flow programPath="/bin.exe" functionAddress="0x401000" direction="variable_accesses" variableName="local_var"`.

**API References**:
- **`ghidra.app.decompiler.DecompInterface`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html) | [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompInterface.java)
  - `openProgram(Program prog)` → `boolean`
  - `decompileFunction(Function func, int timeoutSecs, TaskMonitor monitor)` → `DecompileResults`
- **`ghidra.program.model.pcode.HighFunction`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html)
  - `getPcodeOps()` → `Iterator<PcodeOpAST>`
  - `getLocalSymbolMap()` → `LocalSymbolMap`
- **`ghidra.program.model.pcode.PcodeOp`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html)
  - `getOpcode()` → `int` | `getOutput()` → `Varnode` | `getInput(int i)` → `Varnode`
- **PyGhidra**: `ifc = DecompInterface(); ifc.openProgram(currentProgram); res = ifc.decompileFunction(func, 60, monitor)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- **Community**: [GitHub Discussion: "High P-code Normalization strategies for Cross-Arch Analysis"](https://github.com/NationalSecurityAgency/ghidra/discussions/8874) | [RE.SE: "Ghidra Python - Get Decompile Line Text by RVA"](https://reverseengineering.stackexchange.com/questions/24685/ghidra-python-get-decompile-line-text-by-rva)
### `analyze-program`

**Description**: Initiates Ghidra's full program analysis pipeline for the active program. This is a heavy operation and should normally be run only once per binary. If Ghidra already marked the program as analyzed, the tool returns an error unless `force=true` is supplied for a deliberate reanalysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `analyzers` (array, optional): Specific analyzer names to target instead of the default analyzer set.
  - Synonyms: `analyzers`.
- `force` (boolean, optional): Force re-analysis even if Ghidra already marked the program as analyzed (default: false). This should be rare.
  - Synonyms: `force`, `forceAnalysis`, `forcea`.
**Overloads**:
- `analyze-program(programPath)` → forwards to `analyze-program`.

**Synonyms**: `analyze-program`, `tool_analyze_program`, `analyze_program_tool`, `cmd_analyze_program`, `run_analyze_program`, `do_analyze_program`, `api_analyze_program`, `mcp_analyze_program`, `ghidra_analyze_program`, `agentdecompile_analyze_program`, `analyze_program_command`, `analyze_program_action`, `analyze_program_op`, `analyze_program_task`, `execute_analyze_program`

**Examples**:
- Analyze a program: `analyze-program programPath="/bin.exe"`.
- Force a deliberate re-analysis: `analyze-program programPath="/bin.exe" force=true`.

**API References**:
- **`ghidra.program.flatapi.FlatProgramAPI`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) | [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/Base/src/main/java/ghidra/program/flatapi/FlatProgramAPI.java)
  - `analyzeAll(Program program)` → `void`
  - `analyzeChanges(Program program)` → `void`
- **`ghidra.app.plugin.core.analysis.AutoAnalysisManager`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/plugin/core/analysis/AutoAnalysisManager.html)
  - `getAnalysisManager(Program p)` → `AutoAnalysisManager` (static)
  - `reAnalyzeAll(AddressSetView set)` → `void`
  - `scheduleOneTimeAnalysis(Analyzer analyzer, AddressSetView set)` → `void`
- **`ghidra.app.services.Analyzer`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/services/Analyzer.html)
  - `getName()` → `String` | `getPriority()` → `AnalysisPriority` | `getAnalysisType()` → `AnalyzerType`
- **PyGhidra**: `with pyghidra.open_program(path, analyze=True) as api: pass` or `pyghidra.analyze(program, monitor)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- **Community**: [GitHub Discussion: "Native MCP Server Extension for Ghidra"](https://github.com/NationalSecurityAgency/ghidra/discussions/8648)
### `analyze-vtables`

**Description**: Analyzes virtual tables (vtables) in C++ binaries, extracting virtual function entries, finding callers of specific virtual methods, or identifying vtables containing a given function. This tool is essential for reverse engineering object-oriented code, understanding class hierarchies, and tracing polymorphic behavior. Modes include full vtable analysis (entries and pointers), caller discovery (with limits for large binaries), and containment checks. Outputs structured JSON with addresses, function pointers, and metadata. Supports pagination and limits to handle complex vtables without overwhelming resources.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, required): Analysis mode (`analyze`, `callers`, `containing`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `vtableAddress` (string, optional): Address of the vtable for `analyze` mode.
  - Synonyms: `vtableAddress`, `vtablea`.
- `functionAddress` (string, optional): Function address or name for `callers` or `containing` modes.
  - Synonyms: `functionAddress`, `functiona`, `function`, `funcAddr`, `address`, `entryAddress`, `functionIdentifier`.
- `maxEntries` (integer, optional): Maximum vtable entries to analyze (default: 200).
  - Synonyms: `maxEntries`, `maxe`.
- `maxResults` (integer, optional): Maximum results for `callers` or `containing` (default: 100).
  - Synonyms: `analysisMode`, `vtable`, `function`, `max_entries`, `max_results`, `maxr`.
**Overloads**:
- `analyze-vtable(programPath, vtableAddress, maxEntries)` → forwards to `analyze-vtables`.
- `find-vtable-callers(programPath, functionAddress, vtableAddress, maxResults)` → forwards to `analyze-vtables`.
- `find-vtables-containing-function(programPath, functionAddress)` → forwards to `analyze-vtables`.

**Synonyms**: `analyze-vtables`, `tool_analyze_vtables`, `analyze_vtables_tool`, `cmd_analyze_vtables`, `run_analyze_vtables`, `do_analyze_vtables`, `api_analyze_vtables`, `mcp_analyze_vtables`, `ghidra_analyze_vtables`, `agentdecompile_analyze_vtables`, `analyze_vtables_command`, `analyze_vtables_action`, `analyze_vtables_op`, `analyze_vtables_task`, `execute_analyze_vtables`, `analyze-vtable`, `find-vtable-callers`, `find-vtables-containing-function`

**Examples**:
- Analyze a vtable: `analyze-vtables programPath="/cppbin.exe" mode="analyze" vtableAddress="0x405000" maxEntries=50`.
- Find callers of virtual function: `analyze-vtables programPath="/cppbin.exe" mode="callers" functionAddress="0x401200"`.

**API References**:
- **`ghidra.program.model.symbol.ReferenceManager`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html) | [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/ReferenceManager.java)
  - `getReferencesTo(Address toAddr)` → `ReferenceIterator`
  - `getReferenceCountTo(Address toAddr)` → `int`
  - `hasFlowReferencesFrom(Address addr)` → `boolean`
- **`ghidra.program.model.data.Structure`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html)
  - `getComponent(int ordinal)` → `DataTypeComponent`
  - `getNumComponents()` → `int`
- **`ghidra.program.model.listing.Listing`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html)
  - `getDataAt(Address addr)` → `Data`
  - `getDataContaining(Address addr)` → `Data`
- **PyGhidra**: `refMgr = currentProgram.getReferenceManager(); refs = list(refMgr.getReferencesTo(addr))` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- **Community**: [SO: "getReferencesTo returning None in Ghidra API (GhidraBridge)"](https://stackoverflow.com/questions/78979364/getreferencesto-returning-none-in-ghidra-api-ghidrabridge) | [GitHub Discussion: "Is there an interface in ghidra that corresponds to ida hexrays' ctree"](https://github.com/NationalSecurityAgency/ghidra/discussions/6771)
### `apply-data-type`

**Description**: Applies a specified data type to a memory location or symbol in the program, enabling better disassembly and decompilation by defining structures, arrays, enums, or primitives at addresses. This tool is crucial for fixing undefined data, creating typed views of buffers (e.g., uint8_t arrays for strings), and propagating types through references. It supports archive-specified types and handles conflicts with existing definitions. Transaction-safe, it improves code readability and analysis accuracy, especially for custom structures or imported data types.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `addressOrSymbol` (string, required): Address or symbol to apply the type to.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `dataTypeString` (string, required): String representation of the data type (e.g., "uint8_t[256]").
  - Synonyms: `dataTypeString`, `datats`.
- `archiveName` (string, optional): Name of the data type archive to use.
  - Synonyms: `address`, `symbol`, `dataType`, `type`, `archive`, `archiveName`, `archiven`.
**Overloads**:
- `apply-data-type(programPath, addressOrSymbol, dataTypeString, archiveName)` → forwards to `apply-data-type`.

**Synonyms**: `apply-data-type`, `tool_apply_data_type`, `apply_data_type_tool`, `cmd_apply_data_type`, `run_apply_data_type`, `do_apply_data_type`, `api_apply_data_type`, `mcp_apply_data_type`, `ghidra_apply_data_type`, `agentdecompile_apply_data_type`, `apply_data_type_command`, `apply_data_type_action`, `apply_data_type_op`, `apply_data_type_task`, `execute_apply_data_type`

**Examples**:
- Apply array type: `apply-data-type programPath="/bin.exe" addressOrSymbol="0x404000" dataTypeString="uint8_t[256]"`.
- From archive: `apply-data-type programPath="/bin.exe" addressOrSymbol="0x405000" dataTypeString="MyStruct" archiveName="custom.gdt"`.

**API References**:
- **`ghidra.program.model.listing.DataUtilities`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/DataUtilities.html)
  - `createData(Program program, Address addr, DataType dataType, int length, boolean stackPointers, ClearDataMode clearMode)` → `Data`
- **`ghidra.program.model.data.DataTypeManager`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html) | [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataTypeManager.java)
  - `resolve(DataType dataType, DataTypeConflictHandler handler)` → `DataType`
  - `getDataType(CategoryPath path, String name)` → `DataType`
  - `findDataTypes(String name, List<DataType> list)` → `void`
- **`ghidra.program.model.address.AddressFactory`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressFactory.html)
  - `getAddress(String addrString)` → `Address`
- **PyGhidra**: `dtm = currentProgram.getDataTypeManager(); dt = dtm.getDataType('/myStruct'); DataUtilities.createData(currentProgram, addr, dt, -1, False, ClearDataMode.CLEAR_ALL_CONFLICT_DATA)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- **Community**: [RE.SE: "ghidra-python: create struct with big endian field"](https://reverseengineering.stackexchange.com/questions/23330/ghidra-python-create-struct-with-big-endian-field)
> Note: `capture-agentdecompile-debug-info` is not an advertised MCP tool name in the Python registry. Use the debug resource URI `ghidra://agentdecompile-debug-info`.

### `change-processor`

**Description**: Changes the processor language and compiler specification for a program, allowing re-analysis with different architecture settings (e.g., switching from x86 to ARM). This tool is vital for handling multi-architecture binaries or correcting initial import assumptions. It triggers re-disassembly and re-analysis, supporting options for endianness, variant, and compiler ID. Use with caution as it may invalidate existing annotations; best paired with `analyze-program` afterward.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `processor` (string, required): Processor name (e.g., "x86", "ARM").
  - Synonyms: `processor`
- `languageId` (string, optional): Full language ID (e.g., "x86:LE:64:default").
  - Synonyms: `languageId`, `languagei`.
- `compilerSpecId` (string, optional): Compiler specification (e.g., "gcc").
  - Synonyms: `compilerSpecId`, `compilersi`.
- `endian` (string, optional): Endianness (`little` or `big`).
  - Synonyms: `arch`, `language`, `compiler`, `byteOrder`, `endian`
**Overloads**:
- `change-processor(programPath, languageId, compilerSpecId)` → forwards to `change-processor`.

**Synonyms**: `change-processor`, `tool_change_processor`, `change_processor_tool`, `cmd_change_processor`, `run_change_processor`, `do_change_processor`, `api_change_processor`, `mcp_change_processor`, `ghidra_change_processor`, `agentdecompile_change_processor`, `change_processor_command`, `change_processor_action`, `change_processor_op`, `change_processor_task`, `execute_change_processor`

**Examples**:
- Change to ARM: `change-processor programPath="/bin.exe" processor="ARM" endian="little"`.

**API References**:
- **`ghidra.program.model.lang.LanguageService`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageService.html)
  - `getLanguage(LanguageID languageID)` → `Language`
  - `getLanguageDescription(LanguageID languageID)` → `LanguageDescription`
- **`ghidra.program.model.lang.Language`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Language.html)
  - `getLanguageID()` → `LanguageID`
  - `getDefaultCompilerSpec()` → `CompilerSpec`
  - `isBigEndian()` → `boolean`
- **`ghidra.program.database.ProgramDB`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/database/ProgramDB.html)
  - `setLanguage(Language language, CompilerSpec compilerSpec, boolean forceRedisassembly, TaskMonitor monitor)` → `void`
- **PyGhidra**: `lang_svc = DefaultLanguageService.getLanguageService(); lang = lang_svc.getLanguage(LanguageID('ARM:LE:32:v8'))` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
### `checkin-program`

**Description**: Checks in a program to the project repository, committing changes like annotations, types, and analysis results for version control. This tool supports comments for the check-in and handles conflicts in shared projects. It is essential for collaborative reverse engineering, ensuring changes are persisted and trackable. Operates in transaction-safe mode and can be used after major improvements to save progress.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `comment` (string, optional): Check-in comment describing changes.
  - Synonyms: `comment`
- `keepCheckedOut` (boolean, optional): Keep the program checked out after commit (default: false).
  - Synonyms: `path`, `message`, `keepOpen`, `keepCheckedOut`, `keepco`.
**Overloads**:
- `checkin-program(programPath, message, keepCheckedOut)` → forwards to `checkin-program`.

**Synonyms**: `checkin-program`, `tool_checkin_program`, `checkin_program_tool`, `cmd_checkin_program`, `run_checkin_program`, `do_checkin_program`, `api_checkin_program`, `mcp_checkin_program`, `ghidra_checkin_program`, `agentdecompile_checkin_program`, `checkin_program_command`, `checkin_program_action`, `checkin_program_op`, `checkin_program_task`, `execute_checkin_program`

**Examples**:
- Check in with comment: `checkin-program programPath="/bin.exe" comment="Added crypto annotations"`.

**API References**:
- **`ghidra.framework.model.DomainFile`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html)
  - `checkin(CheckinHandler checkinHandler, TaskMonitor monitor)` → `void`
  - `checkout(boolean exclusive, TaskMonitor monitor)` → `boolean`
  - `isCheckedOut()` → `boolean`
  - `canCheckin()` → `boolean`
  - `getVersionHistory()` → `Version[]`
- **`ghidra.framework.model.ProjectData`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html)
  - `getFile(String path)` → `DomainFile`
  - `getFolder(String path)` → `DomainFolder`
- **PyGhidra**: `with pyghidra.open(projName) as proj: f = proj.getProjectData().getFile('/myBin'); f.checkin(handler, monitor)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
### `create-label`

**Description**: Legacy compatibility forward. Use `create-label`.

**Parameters**: Same as `manage-symbols`.
  - Synonyms: All from `manage-symbols`.

**Overloads**:
- `create-label(programPath, addressOrSymbol, labelName, setAsPrimary)` → forwards to `create-label`.

**Examples**: `create-label programPath="/bin.exe" addressOrSymbol="0x401000" labelName="main_entry"`.
### `decompile-function`

**Description**: Decompiles a specific function to high-level C-like pseudocode, supporting line limits, offset starting, and inclusion of comments or references. This tool leverages Ghidra's decompiler for readable code views, aiding in understanding logic without assembly. It handles timeouts, simplification options, and batch decompilation for multiple functions. Essential for algorithm reverse engineering, with options to include caller/callee context for broader insight.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `functionIdentifier` (string or array, required): Function name(s) or address(es).
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`, `name`, `name_or_address`, `address`
- `offset` (integer, optional): Starting line offset (1-based, default: 1).
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Number of lines to return (default: all).
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `includeComments` (boolean, optional): Include comments in output (default: false).
  - Synonyms: `includeComments`, `includec`.
- `includeIncomingReferences` (boolean, optional): Include references (default: true).
  - Synonyms: `includeIncomingReferences`, `includeir`.
- `includeReferenceContext` (boolean, optional): Include context snippets (default: true).
  - Synonyms: `function`, `identifier`, `startLine`, `lineCount`, `comments`, `refs`, `context`, `includeReferenceContext`
- `includeDisassembly` (boolean, optional): Include disassembly alongside decompilation (default: false).
  - Synonyms: `includeDisassembly`, `includedisasm`.
- `includeCallers` (boolean, optional): Include caller context (default: false).
  - Synonyms: `includeCallers`.
- `includeCallees` (boolean, optional): Include callee context (default: false).
  - Synonyms: `includeCallees`.
- `signatureOnly` (boolean, optional): Return only the function signature (default: false).
  - Synonyms: `signatureOnly`, `sigOnly`.
- `timeout` (integer, optional): Decompiler timeout in seconds (default: 60).
  - Synonyms: `timeout`, `decompileTimeout`, `timeoutSecs`.
**Overloads**:
- `decompile_function(name)` → forwards to `decompile-function`.
- `decompile_function_by_address(address)` → forwards to `decompile-function`.
- `decompile_function(binary_name, name_or_address)` → forwards to `decompile-function`.
- `get-decompilation(programPath, functionNameOrAddress, offset, limit, includeDisassembly, includeComments, includeIncomingReferences, includeReferenceContext, includeCallers, includeCallees, signatureOnly)` → forwards to `decompile-function`.

**Synonyms**: `get-decompilation`, `decompile-function`, `tool_decompile_function`, `decompile_function_tool`, `cmd_decompile_function`, `run_decompile_function`, `do_decompile_function`, `api_decompile_function`, `mcp_decompile_function`, `ghidra_decompile_function`, `agentdecompile_decompile_function`, `decompile_function_command`, `decompile_function_action`, `decompile_function_op`, `decompile_function_task`, `decompile_function_by_address`, `decompile_function`

**Examples**:
- Decompile function: `decompile-function programPath="/bin.exe" functionIdentifier="0x401000" limit=50 includeComments=true`.

### `sync-project`

**Description**: Transfers and synchronizes content between local and/or shared Ghidra projects. Supports pull, push, and bidirectional modes with source scoping, destination remapping, recursion, max-item limits, overwrite policy, and dry-run planning. Works with shared repository sessions (shared↔local) and local-only projects.

**Parameters**:
- `mode` (string, optional): Transfer mode (`pull`, `push`, `bidirectional`, default: `pull`).
  - Synonyms: `mode`, `direction`, `syncMode`, `operation`, `action`.
- `path` (string, optional): Shared repository source path or folder (default: `/`).
  - Synonyms: `path`, `sourcePath`, `source`, `folder`.
- `newPath` (string, optional): Local project destination path or folder (default: `/`).
  - Synonyms: `newPath`, `destinationPath`, `destinationFolder`, `destination`.
- `recursive` (boolean, optional): Recursively include children under source path (default: true).
  - Synonyms: `recursive`, `recurse`.
- `maxResults` (integer, optional): Maximum number of repository items to process.
  - Synonyms: `maxResults`, `limit`.
- `force` (boolean, optional): Overwrite existing local project files.
  - Synonyms: `force`, `overwrite`.
- `dryRun` (boolean, optional): Preview planned transfers without writing data.
  - Synonyms: `dryRun`, `planOnly`, `preview`.
**Overloads**:
- `sync-project(mode, path, newPath, recursive, maxResults, force, dryRun)` canonical signature.

**Synonyms**: `sync-project`, `sync_project`, `syncproject`, `sync-shared-project`, `sync_shared_project`, `syncsharedproject`, `download-shared-repository`, `download_shared_repository`, `downloadsharedrepository`, `download-shared-project`, `pull-shared-repository`, `push-shared-repository`, `sync-shared-repository`

**Examples**:
- Pull all repository files: `sync-project mode="pull" path="/" newPath="/" recursive=true`.
- Push local scope mapping: `sync-project mode="push" path="/K1" newPath="/K1" recursive=true maxResults=100000`.
- Plan bidirectional sync: `sync-project mode="bidirectional" path="/K1" newPath="/K1" dryRun=true`.

### `export`

**Description**: Exports the current program using Ghidra exporter APIs to generate project/program artifacts such as packed `.gzf`, C/C++ source output, and SARIF reports. For C/C++ source, this uses Ghidra's `CppExporter` pipeline. For packed project snapshots, it uses Ghidra project packed-file export (`.gzf`). SARIF output is emitted in SARIF 2.1.0 JSON format for downstream tooling.

**Parameters**:
- `programPath` (string, optional): Program path (optional in GUI mode if active program is set).
  - Synonyms: `programPath`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `outputPath` (string, required): Output file path.
  - Synonyms: `outputPath`, `output`, `file`, `path`.
- `format` (string, optional): Export format (`gzf`, `c`, `cpp`, `cxx`, `sarif`, `xml`, `html`, `ascii`; default: `cpp`).
  - Synonyms: `format`, `exportType`.
- `createHeader` (boolean, optional): Emit header output for C/C++ export when supported (default: true).
  - Synonyms: `createHeader`.
- `includeTypes` (boolean, optional): Emit type declarations for C/C++ export (default: true).
  - Synonyms: `includeTypes`, `emitTypes`.
- `includeGlobals` (boolean, optional): Emit globals for C/C++ export (default: true).
  - Synonyms: `includeGlobals`, `emitGlobals`.
- `includeComments` (boolean, optional): Include comments in generated output when supported (default: false).
  - Synonyms: `includeComments`.
- `tags` (string, optional): Optional tag filter string for C/C++ export.
  - Synonyms: `tags`.
**Overloads**:
- `export(programPath, outputPath, format, createHeader, includeTypes, includeGlobals, includeComments, tags)` canonical signature.

**Synonyms**: `export`, `tool_export`, `export_tool`, `cmd_export`, `run_export`, `do_export`, `api_export`, `mcp_export`, `ghidra_export`, `agentdecompile_export`, `export_command`, `export_action`

**Examples**:
- Export packed project archive: `export programPath="/bin.exe" outputPath="./out/program.gzf" format="gzf"`.
- Export C++ source: `export programPath="/bin.exe" outputPath="./out/decomp.cpp" format="cpp" includeTypes=true includeGlobals=true`.
- Export SARIF: `export programPath="/bin.exe" outputPath="./out/findings.sarif" format="sarif"`.

**API References**:
- **`ghidra.app.util.exporter.Exporter`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/Exporter)
- **`ghidra.app.util.exporter.GzfExporter`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/GzfExporter)
- **`ghidra.app.util.exporter.CppExporter`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/CppExporter)

### `delete-project-binary`

**Description**: Deletes a binary file from the project, including all associated analysis data and versions. This tool is used for cleaning up projects, removing obsolete imports, or managing storage. It requires confirmation for safety and handles dependencies like open programs. Non-reversible, so use with caution in versioned projects.

**Parameters**:
- `programPath` (string, required): Path to the binary to delete.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `confirm` (boolean, optional): Confirm deletion (default: false).
  - Synonyms: `binaryPath`, `force`, `confirm`
**Overloads**:
- `delete_project_binary(binary_name)` → forwards to `delete-project-binary`.

**Synonyms**: `delete-project-binary`, `tool_delete_project_binary`, `delete_project_binary_tool`, `cmd_delete_project_binary`, `run_delete_project_binary`, `do_delete_project_binary`, `api_delete_project_binary`, `mcp_delete_project_binary`, `ghidra_delete_project_binary`, `agentdecompile_delete_project_binary`, `delete_project_binary_command`, `delete_project_binary_action`, `delete_project_binary_op`, `delete_project_binary_task`, `execute_delete_project_binary`, `delete_project_binary`

**Examples**:
- Delete binary: `delete-project-binary programPath="/oldbin.exe" confirm=true`.
### `gen-callgraph`

**Description**: Legacy compatibility alias (non-advertised by default). Use `get-call-graph`.

**Parameters**: Same as `get-call-graph`.
  - Synonyms: All from `get-call-graph`.

**Overloads**:
- `gen_callgraph(binary_name, function_name, direction, display_type, condense_threshold, top_layers, bottom_layers, max_run_time)` → forwards to `get-call-graph`.

**Examples**: `gen-callgraph programPath="/bin.exe" mode="graph" functionIdentifier="main"`.
### `get-call-graph`

**Description**: Retrieves caller/callee relationships as graphs, trees, sets, decompiled callers, or common callers for functions. Modes support visualization (graph/tree), listing (callers/callees), or advanced queries (common_callers). This tool is indispensable for navigation, dependency analysis, and bottleneck identification in call chains. Outputs JSON structures with addresses and optional decompilation context, with pagination for large results.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `functionIdentifier` (string, required): Function name or address.
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`.
- `mode` (string, optional): Mode (`graph`, `tree`, `callers`, `callees`, `callers_decomp`, `common_callers`, default: graph).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `depth` (integer, optional): Graph depth (default: 1).
  - Synonyms: `depth`
- `direction` (string, optional): Traversal direction for tree/callers/callees.
  - Synonyms: `direction`, `dir`, `flow`, `traversalDirection`, `walkDirection`, `orientation`, `edgeDirection`, `pathDirection`, `scanDirection`.
- `maxDepth` (integer, optional): Tree max depth (default: 3, max: 10).
  - Synonyms: `maxDepth`, `maxd`, `depth`, `level`, `treeDepth`, `maxLevel`, `depthLimit`.
- `startIndex` (integer, optional): Pagination start for callers_decomp.
  - Synonyms: `startIndex`, `starti`.
- `maxCallers` (integer, optional): Max decompiled callers (default: 10).
  - Synonyms: `maxCallers`, `maxc`.
- `includeCallContext` (boolean, optional): Include call-site context (default: true).
  - Synonyms: `includeCallContext`, `includecc`.
- `functionAddresses` (string, optional): Comma-separated addresses for `common_callers`.
  - Synonyms: `function`, `analysisMode`, `level`, `dir`, `max_depth`, `offset`, `limit`, `context`, `functions`, `functionAddresses`
**Overloads**:
- `find-common-callers(programPath, functionAddresses)` → forwards to `get-call-graph`.
- `get-call-graph(programPath, functionAddress, depth)` → forwards to `get-call-graph`.
- `get-call-tree(programPath, functionAddress, direction, maxDepth)` → forwards to `get-call-graph`.
- `get-callers-decompiled(programPath, functionNameOrAddress, maxCallers, startIndex, includeCallContext)` → forwards to `get-call-graph`.

**Synonyms**: `get-call-tree`, `find-common-callers`, `get-call-graph`, `tool_get_call_graph`, `get_call_graph_tool`, `cmd_get_call_graph`, `run_get_call_graph`, `do_get_call_graph`, `api_get_call_graph`, `mcp_get_call_graph`, `ghidra_get_call_graph`, `agentdecompile_get_call_graph`, `get_call_graph_command`, `get_call_graph_action`, `get_call_graph_op`, `get-callers-decompiled`

**Examples**:
- Get caller tree: `get-call-graph programPath="/bin.exe" functionIdentifier="0x401000" mode="tree" direction="callers" maxDepth=5`.

### `get-current-address`

**Description**: GUI-only tool that retrieves the current cursor address in the active CodeBrowser tool. This tool is not advertised in headless/server mode.

**Parameters**:
- `programPath` (string, optional): Path to the program (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get_current_address()` → forwards to `get-current-address`.

**Synonyms**: `get-current-address`, `tool_get_current_address`, `get_current_address_tool`, `cmd_get_current_address`, `run_get_current_address`, `do_get_current_address`, `api_get_current_address`, `mcp_get_current_address`, `ghidra_get_current_address`, `agentdecompile_get_current_address`, `get_current_address_command`, `get_current_address_action`, `get_current_address_op`, `get_current_address_task`, `execute_get_current_address`, `get_current_address`

**Examples**:
- Get current address: `get-current-address`.
### `get-current-function`

**Description**: GUI-only tool that returns the function containing the current cursor address in the CodeBrowser. This tool is not advertised in headless/server mode.

**Parameters**:
- `programPath` (string, optional): Path to the program (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get_current_function()` → forwards to `get-current-function`.

**Synonyms**: `get-current-function`, `tool_get_current_function`, `get_current_function_tool`, `cmd_get_current_function`, `run_get_current_function`, `do_get_current_function`, `api_get_current_function`, `mcp_get_current_function`, `ghidra_get_current_function`, `agentdecompile_get_current_function`, `get_current_function_command`, `get_current_function_action`, `get_current_function_op`, `get_current_function_task`, `execute_get_current_function`, `get_current_function`

**Examples**:
- Get current function: `get-current-function`.
### `get-current-program`

**Description**: Retrieves metadata for the currently active program in the GUI, including name, path, language, and analysis status. This tool is essential for GUI-integrated workflows, ensuring operations target the correct binary without explicit paths.

**Parameters**:
- `programPath` (string, optional): Path to verify (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get-current-program()` → forwards to `get-current-program`.

**Synonyms**: `get-current-program`, `tool_get_current_program`, `get_current_program_tool`, `cmd_get_current_program`, `run_get_current_program`, `do_get_current_program`, `api_get_current_program`, `mcp_get_current_program`, `ghidra_get_current_program`, `agentdecompile_get_current_program`, `get_current_program_command`, `get_current_program_action`, `get_current_program_op`, `get_current_program_task`, `execute_get_current_program`

**Examples**:
- Get current program info: `get-current-program`.
### `get-data`

**Description**: Fetches data at a specific address or symbol, returning bytes, disassembled instructions, or typed values. This tool supports various views (hex, ASCII, structured) and is key for inspecting constants, strings, or structures without full memory reads.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `addressOrSymbol` (string, required): Target address or symbol.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `view` (string, optional): Data view (`hex`, `ascii`, `structured`, default: hex).
  - Synonyms: `address`, `symbol`, `format`, `view`
**Overloads**:
- `get-data(programPath, addressOrSymbol)` → forwards to `get-data`.

**Synonyms**: `get-data`, `tool_get_data`, `get_data_tool`, `cmd_get_data`, `run_get_data`, `do_get_data`, `api_get_data`, `mcp_get_data`, `ghidra_get_data`, `agentdecompile_get_data`, `get_data_command`, `get_data_action`, `get_data_op`, `get_data_task`, `execute_get_data`

**Examples**:
- Get data at address: `get-data programPath="/bin.exe" addressOrSymbol="0x404000" view="hex"`.
### `get-functions`

**Description**: Retrieves decompilation, disassembly, info, or call details for one or more functions, supporting batch processing and pagination. This tool is central for function-level analysis, with options for callers/callees, comments, and references. It resolves identifiers by address or name, handling arrays for multi-function queries, and limits output for large decompilations.

**Parameters**:
- `programPath` (string or array, optional): Source program path(s).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `identifier` (string or array, optional): Function identifier(s) (omit for all).
  - Synonyms: `identifier`, `overrideMaxFunctionsLimit`, `address`.
- `view` (string, optional): View (`decompile`, `disassemble`, `info`, `calls`, default: decompile).
  - Synonyms: `view`
- `offset` (integer, optional): Decompile line start (1-based, default: 1).
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Decompile line count (default: 50).
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `includeCallers` (boolean, optional): Include callers (default: false).
  - Synonyms: `includeCallers`, `includec`.
- `includeCallees` (boolean, optional): Include callees (default: false).
  - Synonyms: `includeCallees`, `includec`.
- `includeComments` (boolean, optional): Include comments (default: false).
  - Synonyms: `includeComments`, `includec`.
- `includeIncomingReferences` (boolean, optional): Include incoming references (default: true).
  - Synonyms: `includeIncomingReferences`, `includeir`.
- `includeReferenceContext` (boolean, optional): Include context (default: true).
  - Synonyms: `identifiers`, `functionIdentifier`, `mode`, `startIndex`, `maxLines`, `callers`, `callees`, `comments`, `refs`, `context`, `includeReferenceContext`
- `filterDefaultNames` (boolean, optional): Filter out default-named functions (default: false).
  - Synonyms: `filterDefaultNames`, `filterdn`.
- `filterByTag` (string, optional): Filter functions by tag.
  - Synonyms: `filterByTag`, `filterbt`.
- `untagged` (boolean, optional): Show only untagged functions (default: false).
  - Synonyms: `untagged`.
- `verbose` (boolean, optional): Include detailed metadata (default: false).
  - Synonyms: `verbose`.
**Overloads**:
- `disassemble_function(address)` → forwards to `get-functions`.
- `get_function_by_address(address)` → forwards to `get-functions`.
- `get-functions(programPath, filterDefaultNames, filterByTag, untagged, verbose, startIndex, maxCount)` → forwards to `get-functions`.

**Synonyms**: `get-function-by-address`, `find-function`, `get-functions`, `tool_get_functions`, `get_functions_tool`, `cmd_get_functions`, `run_get_functions`, `do_get_functions`, `api_get_functions`, `mcp_get_functions`, `ghidra_get_functions`, `agentdecompile_get_functions`, `get_functions_command`, `get_functions_action`, `get_functions_op`, `disassemble_function`, `get_function_by_address`

**Examples**:
- Decompile multiple: `get-functions programPath="/bin.exe" identifier=["0x401000", "main"] view="decompile" limit=30 includeCallers=true`.

### `get-references`

**Description**: Lists references to or from a target address/symbol, including code, data, or external refs, with optional context and pagination. This tool is critical for tracing data flow, finding usages, and understanding dependencies. Modes filter by type/direction, and it supports library-specific queries for imports/exports.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `target` (string, required): Address or symbol.
  - Synonyms: `target`, `address`, `location`, `name`
- `mode` (string, optional): Reference mode (default: all).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `direction` (string, optional): `to` or `from` (default: to).
  - Synonyms: `direction`, `dir`, `flow`, `traversalDirection`, `walkDirection`, `orientation`, `edgeDirection`, `pathDirection`, `scanDirection`.
- `offset` (integer, optional): Result offset.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Max results.
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `libraryName` (string, optional): Library filter.
  - Synonyms: `libraryName`, `libraryn`.
- `startIndex` (integer, optional): Start index.
  - Synonyms: `startIndex`, `starti`.
- `maxReferencers` (integer, optional): Max referencers.
  - Synonyms: `maxReferencers`, `maxr`.
- `includeRefContext` (boolean, optional): Include context (default: true).
  - Synonyms: `includeRefContext`, `includerc`, `includeContext`.
- `includeDataRefs` (boolean, optional): Include data refs (default: true).
  - Synonyms: `addressOrSymbol`, `type`, `dir`, `start`, `count`, `max`, `library`, `index`, `max_refs`, `context`, `dataRefs`, `includeDataRefs`, `includeData`.
- `contextLines` (integer, optional): Number of context lines to include (default: 3).
  - Synonyms: `contextLines`, `contextSize`.
- `importName` (string, optional): Import function name to find references for.
  - Synonyms: `importName`.
- `includeFlow` (boolean, optional): Include flow references (default: true).
  - Synonyms: `includeFlow`.
**Overloads**:
- `get_function_xrefs(name, offset, limit)` → forwards to `get-references`.
- `get_xrefs_from(address, offset, limit)` → forwards to `get-references`.
- `get_xrefs_to(address, offset, limit)` → forwards to `get-references`.
- `find-cross-references(programPath, location, direction, includeFlow, includeData, includeContext, contextLines, offset, limit)` → forwards to `get-references`.
- `find-import-references(programPath, importName, libraryName, maxResults)` → forwards to `get-references`.
- `get-referencers-decompiled(programPath, addressOrSymbol, maxReferencers, startIndex, includeDataRefs, includeRefContext)` → forwards to `get-references`.
- `resolve-thunk(programPath, address)` → forwards to `get-references`.

**Synonyms**: `get-references`, `tool_get_references`, `get_references_tool`, `cmd_get_references`, `run_get_references`, `do_get_references`, `api_get_references`, `mcp_get_references`, `ghidra_get_references`, `agentdecompile_get_references`, `get_references_command`, `get_references_action`, `get_references_op`, `get_references_task`, `execute_get_references`, `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`, `find-cross-references`, `find-import-references`, `get-referencers-decompiled`, `resolve-thunk`

**Examples**:
- Get references to: `get-references programPath="/bin.exe" target="0x401000" direction="to" limit=50 includeRefContext=true`.
### `import-binary`

**Description**: Imports a binary file into the Ghidra project, supporting recursive directory imports, analysis after import, and optional shared-project version-control requests. This tool handles file discovery, folder mirroring, and post-import analysis. If `enableVersionControl=true` is requested for a local-only import, the tool fails explicitly instead of pretending shared versioning is available.

**Parameters**:
- `path` (string, required): File or directory path to import.
  - Synonyms: `path`, `binary_path`
- `destinationFolder` (string, optional): Project folder destination (default: root).
  - Synonyms: `destinationFolder`, `destinationf`.
- `recursive` (boolean, optional): Import subdirectories (default: false).
  - Synonyms: `recursive`
- `maxDepth` (integer, optional): Recursion depth (default: unlimited).
  - Synonyms: `maxDepth`, `maxd`, `depth`, `level`, `treeDepth`, `maxLevel`, `depthLimit`.
- `analyzeAfterImport` (boolean, optional): Run analysis post-import (default: true).
  - Synonyms: `analyzeAfterImport`, `analyzeai`.
- `stripLeadingPath` (boolean, optional): Strip leading paths (default: false).
  - Synonyms: `stripLeadingPath`, `striplp`.
- `stripAllContainerPath` (boolean, optional): Strip all container paths (default: false).
  - Synonyms: `stripAllContainerPath`, `stripacp`.
- `mirrorFs` (boolean, optional): Mirror filesystem structure (default: false).
  - Synonyms: `mirrorFs`, `mirrorf`.
- `enableVersionControl` (boolean, optional): Request import into shared-project version control (default: false). Local-only imports cannot satisfy this request and fail explicitly.
  - Synonyms: `filePath`, `destFolder`, `recurse`, `depth`, `autoAnalyze`, `stripPath`, `stripContainer`, `mirror`, `versioning`, `enableVersionControl`
**Overloads**:
- `import_binary(binary_path)` → forwards to `import-binary`.
- `import-file(path, destinationFolder, recursive, maxDepth, analyzeAfterImport, stripLeadingPath, stripAllContainerPath, mirrorFs, enableVersionControl)` → forwards to `import-binary`.

**Synonyms**: `import-file`, `import-binary`, `tool_import_binary`, `import_binary_tool`, `cmd_import_binary`, `run_import_binary`, `do_import_binary`, `api_import_binary`, `mcp_import_binary`, `ghidra_import_binary`, `agentdecompile_import_binary`, `import_binary_command`, `import_binary_action`, `import_binary_op`, `import_binary_task`, `import_binary`

**Examples**:
- Import file: `import-binary path="/path/to/bin.exe" destinationFolder="/imports" analyzeAfterImport=true`.
- Recursive import: `import-binary path="/dir" recursive=true maxDepth=3 mirrorFs=true`.
- Shared version-control request on a local import fails explicitly: `import-binary path="/path/to/bin.exe" enableVersionControl=true`.

### `inspect-memory`

**Description**: Inspects memory at a given address, returning bytes, disassembly, or data in various modes with length limits. This tool is useful for quick memory dumps, verifying constants, or analyzing segments without full program reads. Modes include hex, ascii, or structured views, with pagination for large regions.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, required): Inspection mode (`bytes`, `disasm`, `data`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`, `format`.
- `address` (string, required): Starting address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`, `addressOrSymbol`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `length` (integer, optional): Bytes to inspect (default: 256).
  - Synonyms: `length`
- `offset` (integer, optional): Result offset.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Max results.
  - Synonyms: `view`, `start`, `size`, `startIndex`, `max`, `limit`, `maxResults`, `maxCount`, `count`, `take`, `cap`.
**Overloads**:
- `list_data_items(offset, limit)` → forwards to `inspect-memory`.
- `list_segments(offset, limit)` → forwards to `inspect-memory`.
- `get-memory-blocks(programPath)` → forwards to `inspect-memory`.
- `read-memory(programPath, addressOrSymbol, length, format)` → forwards to `inspect-memory`.

**Synonyms**: `inspect-memory`, `tool_inspect_memory`, `inspect_memory_tool`, `cmd_inspect_memory`, `run_inspect_memory`, `do_inspect_memory`, `api_inspect_memory`, `mcp_inspect_memory`, `ghidra_inspect_memory`, `agentdecompile_inspect_memory`, `inspect_memory_command`, `inspect_memory_action`, `inspect_memory_op`, `inspect_memory_task`, `execute_inspect_memory`, `list_segments`, `list_data_items`, `get-memory-blocks`, `read-memory`

**Examples**:
- Inspect bytes: `inspect-memory programPath="/bin.exe" mode="bytes" address="0x404000" length=128`.
### `list-cross-references`

**Description**: Legacy compatibility forward.

**Parameters**: Same as `get-references`.
  - Synonyms: All from `get-references`.

**Overloads**:
- `list_cross_references(binary_name, name_or_address)` → forwards to `list-cross-references`.

**Examples**: `list-cross-references programPath="/bin.exe" target="0x401000"`.
### `list-exports`

**Description**: Legacy compatibility forward. Use `list-exports`.

**Parameters**: Same as `manage-symbols`.
  - Synonyms: All from `manage-symbols`.

**Overloads**:
- `list_exports(offset, limit)` → forwards to `list-exports`.
- `list_exports(binary_name, query, offset, limit)` → forwards to `list-exports`.
- `list-exports(programPath, maxResults, startIndex)` → forwards to `list-exports`.

**Examples**: `list-exports programPath="/dll.exe"`.
### `list-functions`

**Description**: Lists all or filtered functions in the program, with options for tagging, reference counts, and verbose metadata. This tool supports querying by name, tag, or reference count, making it ideal for overviewing program structure or finding untagged functions for further analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, optional): Listing mode (default: all).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `query` (string, optional): Search query.
  - Synonyms: `query`, `searchString`, `pattern`, `filter`, `text`, `q`, `needle`, `searchQuery`, `match`.
- `searchString` (string, optional): Alias for query.
  - Synonyms: `searchString`, `searchs`.
- `minReferenceCount` (integer, optional): Min refs (default: 0).
  - Synonyms: `minReferenceCount`, `minrc`.
- `startIndex` (integer, optional): Start index.
  - Synonyms: `startIndex`, `starti`.
- `maxCount` (integer, optional): Max functions (default: 100).
  - Synonyms: `maxCount`, `maxc`, `maxCandidates`.
- `offset` (integer, optional): Alias for startIndex.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Alias for maxCount.
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `filterDefaultNames` (boolean, optional): Filter defaults (default: false).
  - Synonyms: `filterDefaultNames`, `filterdn`.
- `filterByTag` (string, optional): Tag filter.
  - Synonyms: `filterByTag`, `filterbt`.
- `untagged` (boolean, optional): Show untagged (default: false).
  - Synonyms: `untagged`
- `hasTags` (boolean, optional): Show tagged (default: false).
  - Synonyms: `hasTags`, `hast`.
- `verbose` (boolean, optional): Include details (default: false).
  - Synonyms: `verbose`
- `identifiers` (array, optional): Specific IDs.
  - Synonyms: `filter`, `pattern`, `minRefs`, `index`, `max`, `start`, `count`, `defaults`, `tag`, `noTags`, `tagged`, `details`.
**Overloads**:
- `list_functions()` → forwards to `list-functions`.
- `list_methods(offset, limit)` → forwards to `list-functions`.
- `get-function-count(programPath, filterDefaultNames)` → forwards to `list-functions`.
- `get-functions-by-similarity(programPath, searchString, filterDefaultNames, startIndex, maxCount, verbose)` → forwards to `list-functions`.
- `get-undefined-function-candidates(programPath, maxCandidates, startIndex, minReferenceCount)` → forwards to `list-functions`.

**Synonyms**: `list-methods`, `get-all-functions`, `list-functions`, `tool_list_functions`, `list_functions_tool`, `cmd_list_functions`, `run_list_functions`, `do_list_functions`, `api_list_functions`, `mcp_list_functions`, `ghidra_list_functions`, `agentdecompile_list_functions`, `list_functions_command`, `list_functions_action`, `list_functions_op`, `get-function-count`, `get-functions-by-similarity`, `get-undefined-function-candidates`, `list_functions`, `list_methods`

**Examples**:
- List tagged functions: `list-functions programPath="/bin.exe" filterByTag="crypto" verbose=true`.

### `list-imports`

**Description**: Legacy compatibility forward. Use `list-imports`.

**Parameters**: Same as `manage-symbols`.
  - Synonyms: All from `manage-symbols`.

**Overloads**:
- `list_imports(offset, limit)` → forwards to `list-imports`.
- `list_imports(binary_name, query, offset, limit)` → forwards to `list-imports`.
- `list-imports(programPath, libraryFilter, maxResults, startIndex, groupByLibrary)` → forwards to `list-imports`.

**Examples**: `list-imports programPath="/bin.exe"`.
### `list-open-programs`

**Description**: Lists all currently open programs in the Ghidra tool (GUI mode), including paths and status. This tool is useful for managing multiple open binaries during sessions.

**Parameters**:
- None (GUI context implied).
  - Synonyms: N/A.

**Overloads**:
- `list-open-programs()` → forwards to `list-open-programs`.

**Synonyms**: `list-open-programs`, `tool_list_open_programs`, `list_open_programs_tool`, `cmd_list_open_programs`, `run_list_open_programs`, `do_list_open_programs`, `api_list_open_programs`, `mcp_list_open_programs`, `ghidra_list_open_programs`, `agentdecompile_list_open_programs`, `list_open_programs_command`, `list_open_programs_action`, `list_open_programs_op`, `list_open_programs_task`, `execute_list_open_programs`

**Examples**:
- List open: `list-open-programs`.
### `list-project-binaries`

**Description**: Lists all binaries in the project, including metadata like size and import time. This tool provides an overview of project contents for management.

**Parameters**:
- None (project-wide).
  - Synonyms: N/A.

**Overloads**:
- `list_project_binaries()` → forwards to `list-project-binaries`.

**Synonyms**: `list-project-binaries`, `tool_list_project_binaries`, `list_project_binaries_tool`, `cmd_list_project_binaries`, `run_list_project_binaries`, `do_list_project_binaries`, `api_list_project_binaries`, `mcp_list_project_binaries`, `ghidra_list_project_binaries`, `agentdecompile_list_project_binaries`, `list_project_binaries_command`, `list_project_binaries_action`, `list_project_binaries_op`, `list_project_binaries_task`, `execute_list_project_binaries`, `list_project_binaries`

**Examples**:
- List binaries: `list-project-binaries`.
### `list-project-binary-metadata`

**Description**: Retrieves detailed metadata for project binaries, such as language, compiler, and analysis info. This tool aids in auditing project state.

**Parameters**:
- `programPath` (string, required): Binary path.
  - Synonyms: `path`, `programPath`, `programp`, `program`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
**Overloads**:
- `list_project_binary_metadata(binary_name)` → forwards to `list-project-binary-metadata`.

**Synonyms**: `list-project-binary-metadata`, `tool_list_project_binary_metadata`, `list_project_binary_metadata_tool`, `cmd_list_project_binary_metadata`, `run_list_project_binary_metadata`, `do_list_project_binary_metadata`, `api_list_project_binary_metadata`, `mcp_list_project_binary_metadata`, `ghidra_list_project_binary_metadata`, `agentdecompile_list_project_binary_metadata`, `list_project_binary_metadata_command`, `list_project_binary_metadata_action`, `list_project_binary_metadata_op`, `list_project_binary_metadata_task`, `execute_list_project_binary_metadata`, `list_project_binary_metadata`

**Examples**:
- Get metadata: `list-project-binary-metadata programPath="/bin.exe"`.
### `list-project-files`

**Description**: Lists all files in the project, including folders and non-binary files. This tool is for project navigation and cleanup.

**Parameters**:
- None.
**Overloads**:
- `list-project-files(folderPath, recursive)` → forwards to `list-project-files`.

**Synonyms**: `list-project-files`, `tool_list_project_files`, `list_project_files_tool`, `cmd_list_project_files`, `run_list_project_files`, `do_list_project_files`, `api_list_project_files`, `mcp_list_project_files`, `ghidra_list_project_files`, `agentdecompile_list_project_files`, `list_project_files_command`, `list_project_files_action`, `list_project_files_op`, `list_project_files_task`, `execute_list_project_files`

**Examples**:
- List files: `list-project-files`.
### `list-processors`

**Description**: Lists available processor/language identifiers from Ghidra, optionally filtered by text. This tool helps select valid language/compiler targets before import or processor changes.

**Parameters**:
- `filter` (string, optional): Optional case-insensitive filter applied to language IDs and display names.
  - Synonyms: `filter`, `query`, `search`.

**Overloads**:
- `list-processors(filter)` canonical signature.

**Synonyms**: `list-processors`, `tool_list_processors`, `list_processors_tool`, `cmd_list_processors`, `run_list_processors`, `do_list_processors`, `api_list_processors`, `mcp_list_processors`, `ghidra_list_processors`, `agentdecompile_list_processors`, `list_processors_command`, `list_processors_action`, `list_processors_op`, `list_processors_task`, `execute_list_processors`

**Examples**:
- List all processors: `list-processors`.
- Filter to x86 processors: `list-processors filter="x86"`.
### `list-strings`

**Description**: Legacy compatibility forward. Use `manage-strings` with `mode="list"`.

**Parameters**: Same as `manage-strings`.
  - Synonyms: All from `manage-strings`.

**Overloads**:
- `list_strings(offset, limit, filter)` → forwards to `list-strings`.

**Examples**: `list-strings programPath="/bin.exe"`.

### `match-function`

**Description**: Matches functions across different builds or binaries (cross-program matching) by **signature** (parameter count and return type), **name**, and **call-graph** (caller/callee names). Does not use byte-level or instruction-level comparison, so it works when addresses, registers, and stack layout differ (e.g. KOTOR 1 vs KOTOR 2). Supports similarity thresholds and propagation of names, tags, comments, prototype, and bookmarks. When multiple target functions share the same signature, candidates are ranked by name match then by call-graph overlap (shared callees/callers). Single-program modes: similar, callers, callees, signature.

**Parameters**:
- `programPath` (string, optional): Source program.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `functionIdentifier` (string, required): Function.
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`.
- `targetProgramPaths` (array, required): Targets.
  - Synonyms: `targetProgramPaths`, `targetpp`.
- `maxInstructions` (integer, optional): Max instrs.
  - Synonyms: `maxInstructions`, `maxi`.
- `minSimilarity` (number, optional): Min similarity 0–1 or 0–100 (default: 0.7). Name match = 1.0; same signature only = 0.7; call-graph used to disambiguate.
  - Synonyms: `minSimilarity`, `mins`.
- `propagateNames` (boolean, optional): Prop names (default: false).
  - Synonyms: `propagateNames`, `propagaten`.
- `propagateTags` (boolean, optional): Prop tags (default: false).
  - Synonyms: `propagateTags`, `propagatet`.
- `propagateComments` (boolean, optional): Prop comments (default: false).
  - Synonyms: `propagateComments`, `propagatec`.
- `filterDefaultNames` (boolean, optional): Filter defaults (default: false).
  - Synonyms: `filterDefaultNames`, `filterdn`.
- `filterByTag` (string, optional): Tag filter.
  - Synonyms: `filterByTag`, `filterbt`.
- `maxFunctions` (integer, optional): Max functions.
  - Synonyms: `maxFunctions`, `maxf`.
- `batchSize` (integer, optional): Batch size.
  - Synonyms: `sourcePath`, `function`, `targets`, `maxInstr`, `simThreshold`, `propNames`, `propTags`, `propComms`, `defaults`, `tag`, `maxFuncs`, `batch`.
**Overloads**:
- `match-function(programPath, functionIdentifier, targetProgramPaths, maxInstructions, minSimilarity, propagateNames, propagateTags, propagateComments, filterDefaultNames, filterByTag, maxFunctions, batchSize)` canonical signature.


**Synonyms**: `match-function`, `tool_match_function`, `match_function_tool`, `cmd_match_function`, `run_match_function`, `do_match_function`, `api_match_function`, `mcp_match_function`, `ghidra_match_function`, `agentdecompile_match_function`, `match_function_command`, `match_function_action`, `match_function_op`, `match_function_task`, `execute_match_function`

**Examples**:
- Match function: `match-function programPath="/bin1.exe" functionIdentifier="main" targetProgramPaths=["/bin2.exe"] minSimilarity=0.9 propagateNames=true`.
### `execute-script`

**Description**: Auto-generated placeholder section from `agentdecompile_cli/registry.py`.

**Parameters**:
- None.

**Overloads**:
- `execute-script()` canonical signature.

**Synonyms**: `execute-script`

**Examples**:
- `execute-script`

### `open-all-programs-in-code-browser`

**Description**: GUI-only tool that opens all project programs in the CodeBrowser for bulk viewing. This tool is not advertised in headless/server mode.

**Parameters**:
- None.
  - Synonyms: N/A.

**Overloads**:
- `open-all-programs-in-code-browser()` canonical signature.


**Synonyms**: `open-all-programs-in-code-browser`, `tool_open_all_programs_in_code_browser`, `open_all_programs_in_code_browser_tool`, `cmd_open_all_programs_in_code_browser`, `run_open_all_programs_in_code_browser`, `do_open_all_programs_in_code_browser`, `api_open_all_programs_in_code_browser`, `mcp_open_all_programs_in_code_browser`, `ghidra_open_all_programs_in_code_browser`, `agentdecompile_open_all_programs_in_code_browser`, `open_all_programs_in_code_browser_command`, `open_all_programs_in_code_browser_action`, `open_all_programs_in_code_browser_op`, `open_all_programs_in_code_browser_task`, `execute_open_all_programs_in_code_browser`

**Examples**:
- Open all: `open-all-programs-in-code-browser`.
### `read-bytes`

**Description**: Legacy compatibility forward for byte reads. Prefer `inspect-memory` with `mode="read"`.

**Parameters**: Same as `inspect-memory` read-mode semantics.
  - Synonyms: Includes compatibility forms such as `binaryName` and `size`.

**Overloads**:
- `read_bytes(binary_name, address, size)` → forwards to `read-bytes`.

**Examples**: `read-bytes programPath="/bin.exe" address="0x404000" length=256`.

### `resolve-modification-conflict`

**Description**: Resolve a modification conflict reported by another tool. Call only when a tool returned a `conflictId` because the change would overwrite custom data; use `resolution=overwrite` to apply the change or `resolution=skip` to discard.

**Parameters**:
- `conflictId` (string, required): The GUID returned in the conflict response from the modifying tool.
- `resolution` (string, required): `overwrite` = apply the stored modification; `skip` = discard and remove from store.
- `programPath` (string, optional): Optional override for program context when resolving.

**Examples**: After `manage-symbols` (rename) returns a conflict, call `resolve-modification-conflict conflictId="<uuid>" resolution=overwrite` to apply, or `resolution=skip` to discard.

### `list-prompts`

**Description**: List all available MCP prompts (reverse-engineering workflows such as Scout Broad Sweep, Diver Deep Dive, Bottom-Up Analyst, Convergence Orchestrator).

**Parameters**: None.

**Examples**: Call `list-prompts` to discover prompt names (e.g. `re-scout-broad-sweep`, `re-diver-deep-dive`).

### `search-code`

**Description**: Searches code for patterns in disassembly or pcode.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `pattern` (string, required): Code pattern.
  - Synonyms: `pattern`
- `maxResults` (integer, optional): Max (default: 100).
  - Synonyms: `query`, `limit`, `maxResults`, `maxr`.
- `offset` (integer, optional): Result offset for pagination.
  - Synonyms: `offset`, `skip`, `cursor`, `begin`, `position`, `startIndex`.
- `caseSensitive` (boolean, optional): Case-sensitive search (default: false).
  - Synonyms: `caseSensitive`, `cases`.
- `searchMode` (string, optional): Search mode (e.g., exact, regex, fuzzy).
  - Synonyms: `searchMode`, `mode`, `search_mode`.
- `includeFullCode` (boolean, optional): Include full function code in results (default: false).
  - Synonyms: `includeFullCode`, `fullCode`, `include_full_code`.
- `previewLength` (integer, optional): Preview snippet length (default: 200).
  - Synonyms: `previewLength`, `previewLen`, `snippetLength`, `preview_length`.
- `similarityThreshold` (number, optional): Similarity threshold for fuzzy search (0.0-1.0).
  - Synonyms: `similarityThreshold`, `simThreshold`, `threshold`, `similarity_threshold`.
- `overrideMaxFunctionsLimit` (boolean, optional): Override the maximum functions search limit (default: false).
  - Synonyms: `overrideMaxFunctionsLimit`, `noLimit`.
**Overloads**:
- `search_code(binary_name, query, limit, offset, search_mode, include_full_code, preview_length, similarity_threshold)` → forwards to `search-code`.
- `search-decompilation(programPath, pattern, maxResults, caseSensitive, overrideMaxFunctionsLimit)` → forwards to `search-code`.

**Synonyms**: `search-code`, `tool_search_code`, `search_code_tool`, `cmd_search_code`, `run_search_code`, `do_search_code`, `api_search_code`, `mcp_search_code`, `ghidra_search_code`, `agentdecompile_search_code`, `search_code_command`, `search_code_action`, `search_code_op`, `search_code_task`, `execute_search_code`, `search_code`, `search-decompilation`

**Examples**:
- Search code: `search-code programPath="/bin.exe" pattern="XOR"`.
### `search-constants`

**Description**: Searches for specific constants, ranges, or common values in the program.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, required): Mode (`specific`, `range`, `common`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `value` (string, optional): Specific value.
  - Synonyms: `value`
- `minValue` (string, optional): Min.
  - Synonyms: `minValue`, `minv`.
- `maxValue` (string, optional): Max.
  - Synonyms: `maxValue`, `maxv`.
- `maxResults` (integer, optional): Max for specific/range (default: 500).
  - Synonyms: `maxResults`, `maxr`.
- `includeSmallValues` (boolean, optional): Include small in common (default: false).
  - Synonyms: `includeSmallValues`, `includesv`.
- `topN` (integer, optional): Top N in common (default: 50).
  - Synonyms: `action`, `val`, `min`, `max`, `limit`, `smallVals`, `top`, `topN`
**Overloads**:
- `find-constant-uses(programPath, value, maxResults)` → forwards to `search-constants`.
- `find-constants-in-range(programPath, minValue, maxValue, maxResults)` → forwards to `search-constants`.
- `list-common-constants(programPath, topN, minValue, includeSmallValues)` → forwards to `search-constants`.

**Synonyms**: `search-constants`, `tool_search_constants`, `search_constants_tool`, `cmd_search_constants`, `run_search_constants`, `do_search_constants`, `api_search_constants`, `mcp_search_constants`, `ghidra_search_constants`, `agentdecompile_search_constants`, `search_constants_command`, `search_constants_action`, `search_constants_op`, `search_constants_task`, `execute_search_constants`, `find-constant-uses`, `find-constants-in-range`, `list-common-constants`

**Examples**:
- Search constant: `search-constants programPath="/bin.exe" mode="specific" value="0xdeadbeef"`.

### `search-everything`

**Description**: CALL THIS TOOL FIRST FOR DISCOVERY/LOOKUP TASKS. UNIFIED MULTI-DOMAIN SEARCH OVER STRING-BEARING ANALYSIS DATA.

**Parameters**:
- `programPath` (string or array, optional): Program path(s). If omitted, searches all programs in the current project when available.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `programName` (string or array, optional): Alias for programPath.
  - Synonyms: `programName`.
- `binaryName` (string or array, optional): Alias for programPath.
  - Synonyms: `binaryName`.
- `query` (string, optional): Single search term/pattern.
  - Synonyms: `query`, `pattern`, `search`, `searchString`, `text`, `filter`.
- `queries` (array, optional): Multiple terms/patterns.
  - Synonyms: `queries`, `patterns`, `terms`.
- `mode` (string, optional): Match mode (`auto`, `literal`, `regex`, `fuzzy`, default: `auto`).
  - Synonyms: `mode`, `searchMode`.
- `scopes` (array, optional): Search scopes (`functions`, `function_signatures`, `function_parameters`, `function_tags`, `bookmarks`, `comments`, `constants`, `decompilation`, `disassembly`, `symbols`, `imports`, `exports`, `namespaces`, `classes`, `strings`, `data_types`, `data_type_archives`, `structures`, `structure_fields`; default: all listed here).
  - Synonyms: `scopes`, `scope`, `domains`, `sources`, `types`.
- `caseSensitive` (boolean, optional): Case-sensitive matching (default: false).
  - Synonyms: `caseSensitive`.
- `similarityThreshold` (number, optional): Fuzzy threshold (0.0-1.0, default: 0.7).
  - Synonyms: `similarityThreshold`, `threshold`.
- `offset` (integer, optional): Pagination offset.
  - Synonyms: `offset`, `startIndex`.
- `limit` (integer, optional): Maximum returned results.
  - Synonyms: `limit`, `maxResults`, `maxCount`.
- `perScopeLimit` (integer, optional): Pre-pagination cap per scope (default: 300).
  - Synonyms: `perScopeLimit`, `scopeLimit`.
- `maxFunctionsScan` (integer, optional): Function scan cap for expensive scopes (default: 500).
  - Synonyms: `maxFunctionsScan`, `maxFunctions`.
- `maxInstructionsScan` (integer, optional): Instruction scan cap for disassembly scope (default: 200000).
  - Synonyms: `maxInstructionsScan`, `maxInstructions`.
- `decompileTimeout` (integer, optional): Decompiler timeout per function in seconds for decompilation scope (default: 10).
  - Synonyms: `decompileTimeout`, `timeout`.
- `groupByFunction` (boolean, optional): When true, merges function-centric matches into grouped entries with `relatedResults` and guided `nextTools` (default: true).
  - Synonyms: `groupByFunction`.
**Overloads**:
- `global-search(...)` → forwards to `search-everything`.
- `search-anything(...)` → forwards to `search-everything`.
- `unified-search(...)` → forwards to `search-everything`.

**Synonyms**: `search-everything`, `global-search`, `search-anything`, `unified-search`

**Examples**:
- Search all domains with auto mode: `search-everything query="crypto"`.
- Regex only in comments and symbols: `search-everything mode="regex" query="AES_[0-9]+" scopes=["comments","symbols"]`.

### `search-strings`

**Description**: Legacy compatibility forward.

**Parameters**: Same as `manage-strings`.
  - Synonyms: All from `manage-strings`.

**Overloads**:
- `search_strings(binary_name, query, limit)` → forwards to `search-strings`.

**Examples**: `search-strings programPath="/bin.exe" query="https?"`.
### `search-symbols`

**Description**: Legacy compatibility forward.

**Parameters**: Same as `manage-symbols`.
  - Synonyms: All from `manage-symbols`.

**Overloads**:
- `search_functions_by_name(query, offset, limit)` → forwards to `search-symbols`.

**Examples**: `search-symbols programPath="/bin.exe" query="main"`.

### `search-symbols-by-name`

**Description**: Legacy compatibility alias (non-advertised by default). Use `search-symbols`.

**Parameters**: Same as `manage-symbols`.
  - Synonyms: All from `manage-symbols`.

**Overloads**:
- `search_symbols_by_name(binary_name, query, offset, limit)` → forwards to `search-symbols`.

**Examples**: `search-symbols-by-name programPath="/bin.exe" query="entry"`.
### `suggest`

**Description**: Legacy hidden tool (not advertised by default). Enable with `AGENTDECOMPILE_SHOW_LEGACY_TOOLS=1` or `AGENTDECOMPILE_ENABLE_LEGACY_TOOLS=1`.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `suggestionType` (string, required): Type (`name`, `type`, `comment`).
  - Synonyms: `suggestionType`, `suggestiont`.
- `address` (string, optional): Address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`.
- `function` (string, optional): Function.
  - Synonyms: `function`
- `dataType` (string, optional): Type suggestion.
  - Synonyms: `dataType`, `datat`.
- `variableAddress` (string, optional): Var address.
  - Synonyms: `type`, `addr`, `func`, `dt`, `varAddr`, `variableAddress`, `variablea`.
**Overloads**:
- `suggest(programPath, suggestionType, address, function, dataType, variableAddress)` canonical signature.

**Examples**:
- Suggest name: `suggest programPath="/bin.exe" suggestionType="name" address="0x401000"`.

## Usage Tips

### Start with High-Level Analysis

`list-functions` then `get-call-graph` for main.

### Trace Data Flow

`analyze-data-flow` backward from address.

### Find Patterns

`search-constants` for deadbeef.

### Organize Findings

`manage-bookmarks` for encryption function.

### Analyze C++ Binaries

`analyze-vtables` for vtable at address.

### Manage Functions and Variables

`rename-function` and `set-function-prototype` to rename and set prototype.

### Transfer Analysis Across Similar Binaries

`match-function` to propagate from program1 to program2.

---

# Reverse Engineering Skills & Workflows

This section provides comprehensive methodologies, workflows, and pattern recognition guides for various reverse engineering tasks. These skills complement the tools above by providing strategic approaches to common RE challenges.

## Binary Triage Skill

**Purpose**: Performs initial binary survey by examining memory layout, strings, imports/exports, and functions to quickly understand what a binary does and identify suspicious behavior.

**When to use**: First examining a binary, when asked to triage/survey/analyze a program, or getting an overview before deeper reverse engineering.

### Systematic Triage Workflow

Follow this workflow using AgentDecompile MCP tools:

#### 1. Identify the Program
- Use `get-current-program` to see the active program
- Or use `list-project-files` to see available programs in the project
- Note the `programPath` (e.g., "/Hatchery.exe") for use in subsequent tools

#### 2. Survey Memory Layout
- Use `inspect-memory` to understand the binary structure
- Examine key sections:
  - `.text` - executable code
  - `.data` - initialized data
  - `.rodata` - read-only data (strings, constants)
  - `.bss` - uninitialized data
- Flag unusual characteristics:
  - Unusually large sections
  - Packed/encrypted sections
  - Executable data sections
  - Writable code sections

#### 3. Survey Strings
- Use `manage-strings` with `mode='list'` and pagination (100-200 strings at a time)
- Look for indicators of functionality or malicious behavior:
  - **Network**: URLs, IP addresses, domain names, API endpoints
  - **File System**: File paths, registry keys, configuration files
  - **APIs**: Function names, library references
  - **Messages**: Error messages, debug strings, log messages
  - **Suspicious Keywords**: admin, password, credential, token, crypto, encrypt, decrypt, download, execute, inject, shellcode, payload

#### 4. Survey Symbols and Imports
- Use `list-imports` to list external symbols
- Use `list-imports` for library-specific imports
- Focus on external symbols (imports from libraries)
- Flag interesting/suspicious imports by category:
  - **Network APIs**: connect, send, recv, WSAStartup, getaddrinfo, curl_*, socket
  - **File I/O**: CreateFile, WriteFile, ReadFile, fopen, fwrite, fread
  - **Process Manipulation**: CreateProcess, exec, fork, system, WinExec, ShellExecute
  - **Memory Operations**: VirtualAlloc, VirtualProtect, mmap, mprotect
  - **Crypto**: CryptEncrypt, CryptDecrypt, EVP_*, AES_*, bcrypt, RC4
  - **Anti-Analysis**: IsDebuggerPresent, CheckRemoteDebuggerPresent, ptrace
  - **Registry**: RegOpenKey, RegSetValue, RegQueryValue

#### 5. Survey Functions
- Use `list-functions` with `filterDefaultNames=true` to count named functions
- Use `list-functions` with `filterDefaultNames=false` to count all functions
- Calculate ratio of named vs unnamed functions (high unnamed ratio = stripped binary)
- Identify key functions:
  - **Entry points**: `entry`, `start`, `_start`
  - **Main functions**: `main`, `WinMain`, `DllMain`, `_main`
  - **Suspicious names**: If not stripped, look for revealing function names

#### 6. Cross-Reference Analysis for Key Findings
- For interesting strings found in Step 3:
  - Use `get-references` with `direction="to"` to identify which functions reference suspicious strings
- For suspicious imports found in Step 4:
  - Use `get-references` with `direction="to"` to identify which functions call suspicious APIs
- This helps prioritize which functions need detailed examination

#### 7. Selective Initial Decompilation
- Use `get-functions` or `decompile-function` on entry point or main function
  - Set `limit=30` to get ~30 lines initially
  - Set `includeIncomingReferences=true` to see callers
- Use `decompile-function` on 1-2 suspicious functions identified in Step 6
  - Set `limit=20-30` for quick overview
- Look for high-level patterns:
  - Loops (encryption/decryption routines)
  - Network operations
  - File operations
  - Process creation
  - Suspicious control flow (obfuscation indicators)
- **Do not do deep analysis yet** - this is just to understand general behavior

#### 8. Document Findings
- Use `manage-bookmarks` to create actionable task list:
  - `action='create'` for encryption functions, suspicious strings, etc.
  - Categories: "Analysis", "TODO", "Suspicious", "Crypto"
  - Examples:
    - "Investigate string 'http://malicious-c2.com' (referenced at 0x00401234)"
    - "Decompile function sub_401000 (calls VirtualAlloc + memcpy + CreateThread)"
    - "Analyze crypto usage in function encrypt_payload (uses CryptEncrypt)"

---

## Deep Analysis Skill

**Purpose**: Performs focused, depth-first investigation of specific reverse engineering questions through iterative analysis and database improvement. Answers questions like "What does this function do?", "Does this use crypto?", "What's the C2 address?".

**When to use**: After binary-triage for investigating specific suspicious areas or when asked focused questions about binary behavior.

### The Investigation Loop

Follow this iterative process (repeat 3-7 times per question):

#### 1. READ - Gather Current Context (1-2 tool calls)
```
Get decompilation/data at focus point:
- get-functions (limit=20-50 lines, includeIncomingReferences=true, includeReferenceContext=true)
- get-references (direction="to"/"from", includeRefContext=true)
- get-data or inspect-memory for data structures
```

#### 2. UNDERSTAND - Analyze What You See
Ask yourself:
- What is unclear? (variable names, types, logic flow)
- What operations are being performed?
- What APIs/strings/data are referenced?
- What assumptions am I making?

#### 3. IMPROVE - Make Small Database Changes (1-3 tool calls)
Prioritize clarity improvements:
```
rename-variable: var_1 → encryption_key, iVar2 → buffer_size
set-local-variable-type: local_10 from undefined4 to uint32_t
set-function-prototype: void FUN_00401234(uint8_t* data, size_t len)
apply-data-type: Apply uint8_t[256] to S-box constant
manage-comments with mode='set': Document key findings in code
```

#### 4. VERIFY - Re-read to Confirm Improvement (1 tool call)
```
get-functions again → Verify changes improved readability
```

#### 5. FOLLOW THREADS - Pursue Evidence (1-2 tool calls)
```
Follow xrefs to called/calling functions
Trace data flow through variables
Check string/constant usage
Search for similar patterns
```

#### 6. TRACK PROGRESS - Document Findings (1 tool call)
```
manage-bookmarks action='create' type="Analysis" category="[Topic]" → Mark important findings
manage-bookmarks action='create' type="TODO" → Track unanswered questions
manage-bookmarks action='create' type="Note" category="Evidence" → Document key evidence
```

#### 7. ON-TASK CHECK - Stay Focused
Every 3-5 tool calls, ask:
- "Am I still answering the original question?"
- "Is this lead productive or a distraction?"
- "Do I have enough evidence to conclude?"
- "Should I return partial results now?"

### Question Type Strategies

#### "What does function X do?"

**Discovery:**
1. `get-functions` with `includeIncomingReferences=true`
2. `get-references` direction="to" to see who calls it

**Investigation:**
3. Identify key operations (loops, conditionals, API calls)
4. Check strings/constants referenced: `get-data`, `inspect-memory`
5. Use `rename-variable` to rename variables based on usage patterns
6. Use `set-local-variable-type` to fix variable types where evident from operations
7. Use `manage-comments` to document behavior

**Synthesis:**
8. Summarize function behavior with evidence
9. Return threads: "What calls this?", "What does it do with results?"

#### "Does this use cryptography?"

**Discovery:**
1. `search-strings` pattern for crypto keywords (AES, encrypt, decrypt, cipher, key)
2. `search-code` pattern for crypto patterns (S-box, permutation loops)
3. `manage-symbols` with includeExternal=true → Check for crypto API imports

**Investigation:**
4. Use `inspect-memory` at constant arrays → Compare to known S-boxes
5. Check for characteristic loop counts (10, 12, 14, 16 rounds)
6. Look for XOR operations, rotations, substitution patterns
7. `get-references` to crypto functions → Find where keys/data flow

**Synthesis:**
8. Identify algorithm type (AES, DES, RSA, custom)
9. Document key locations, encryption points
10. Return threads: "Where are keys stored?", "What data is encrypted?"

#### "Where does data X come from?"

**Discovery:**
1. `get-references` direction="to" at data address
2. Identify all functions that read/write this data

**Investigation:**
3. `get-functions` for each referencer
4. Trace backwards: where do their inputs come from?
5. Follow call chain upward toward data sources
6. Check for user input, network, file I/O

**Synthesis:**
7. Build data flow map: source → transforms → destination
8. Document assumptions about data origins
9. Return threads: "What happens to this data next?"

---

## CTF Reverse Engineering Skill

**Purpose**: Solve CTF reverse engineering challenges using systematic analysis to find flags, keys, or passwords.

**When to use**: For crackmes, binary bombs, key validators, obfuscated code, algorithm recovery, or any challenge requiring program comprehension to extract hidden information.

### The Three Questions Framework

Every reverse engineering challenge boils down to answering:

**1. What does the program EXPECT?**
- Input format (string, number, binary data?)
- Input structure (length, format, encoding?)
- Validation criteria (checks, comparisons, constraints?)

**2. What does the program DO?**
- Transformation (encrypt, hash, encode, compute?)
- Comparison (against hardcoded value, derived value?)
- Algorithm (standard crypto, custom logic, mathematical?)

**3. How do I REVERSE it?**
- Is the operation reversible? (encryption vs hashing)
- Can I brute force? (keyspace size, performance)
- Can I derive the answer? (solve equations, trace backwards)
- Can I bypass? (patch, debug, manipulate state)

### Key Pattern Recognition

#### Simple XOR Patterns

**Recognition:**
- Very short functions (5-15 lines decompiled)
- XOR operation in loop
- Constant value or small array
- Modulo operation for key index (`i % keylen`)

**Investigation:**
```
search-code pattern for XOR operations
get-functions at suspicious function
inspect-memory at key location to extract XOR key
```

**Solution:** XOR is self-inverse - `decrypt(x) = encrypt(x)`

#### Base64 and Variants

**Recognition:**
- 64-character string constant (lookup table)
- Bit shifting: `>> 6`, `>> 12`, `>> 18`
- Masking: `& 0x3F` (6 bits)
- 3-to-4 or 4-to-3 byte conversion ratio

**Investigation:**
```
search-strings pattern="[A-Za-z0-9+/]{64}" for alphabet
search-code pattern="& 0x3f" for 6-bit masking
get-functions at encoding function to confirm 3→4 byte transformation
```

#### Block Cipher Patterns (AES, DES)

**Recognition:**
- 128-bit (16-byte) or 64-bit (8-byte) blocks
- 10-16 rounds (fixed iteration count)
- Large constant arrays (S-boxes, typically 256 bytes)
- Heavy XOR usage, byte/word array indexing

**Investigation:**
```
search-code pattern for round loops
inspect-memory at constant arrays
Compare first bytes to known S-boxes:
  AES: 63 7c 77 7b f2 6b 6f c5
  DES S1: 0e 04 0d 01 02 0f 0b 08
```

#### Input Validation Patterns

**Recognition:**
- Input reading (scanf, fgets, read)
- Character-by-character checking
- Length validation
- Character set restrictions

**Investigation:**
```
list-functions to find main/entry
get-functions at main with includeCallees=true
get-references to input functions (scanf, read, gets)
Trace validation logic flow
```

### Static vs Dynamic Approach

**Static Analysis** (code reading):
- Use when program is small/focused
- Algorithm identification challenges
- When dynamic analysis is hindered
- **Tools**: `get-functions`, `decompile-function`, `get-call-graph`

**Dynamic Analysis** (runtime inspection):
- Use when complex state/control flow
- Anti-debugging present
- Need to see actual data values
- **Tools**: Debuggers, instrumentation (outside AgentDecompile scope)

**Hybrid Approach** (best for CTF):
- Static to understand structure
- Dynamic to confirm behavior
- Static to verify solution

---

## CTF Cryptography Skill

**Purpose**: Solve CTF cryptography challenges by identifying, analyzing, and exploiting weak crypto implementations in binaries to extract keys or decrypt data.

**When to use**: For custom ciphers, weak crypto, key extraction, or algorithm identification challenges.

### Four-Phase Framework

#### Phase 1: Crypto Detection
**Goal**: Determine if and where cryptography is used

**Investigation approach:**
- Search for crypto-related strings and constants
- Identify mathematical operation patterns (XOR, rotation, substitution)
- Recognize standard algorithm signatures (S-boxes, key schedules, magic constants)
- Find crypto API imports (CryptEncrypt, OpenSSL functions, etc.)

**Tools:**
```
search-strings pattern for crypto keywords (encrypt, decrypt, key, AES, RSA)
manage-symbols includeExternal=true for crypto API imports
search-constants for known crypto magic numbers
```

**Key question**: "Is there crypto, and if so, what kind?"

#### Phase 2: Algorithm Identification
**Goal**: Determine what cryptographic algorithm is being used

**Investigation approach:**
- Compare constants to known crypto constants (initialization vectors, S-boxes)
- Analyze operation patterns (rounds, block sizes, data flow)
- Match code structure to known algorithm patterns
- Check for library usage vs. custom implementation

**Recognition patterns:**

**Block Ciphers (AES, DES)**:
- Fixed block size (64-bit or 128-bit)
- Multiple rounds (8-16+)
- S-box lookups (256-byte constant arrays)
- Heavy XOR usage

**Stream Ciphers (RC4, ChaCha)**:
- State-based generation
- Simple XOR with keystream
- Swap operations
- Modulo arithmetic

**Hash Functions (MD5, SHA)**:
- Compression function
- Magic initialization constants
- Fixed round counts (64, 80)
- Padding logic

**Tools:**
```
inspect-memory at constant arrays to compare S-boxes
get-functions to analyze round structure
search-code for characteristic patterns (rotations, permutations)
```

**Key question**: "What algorithm is this, or is it custom?"

#### Phase 3: Implementation Analysis
**Goal**: Understand how the crypto is implemented and find weaknesses

**Investigation approach:**
- Trace key material sources (hardcoded, derived, user input)
- Analyze key generation/derivation logic
- Identify mode of operation (ECB, CBC, CTR, etc.)
- Look for implementation mistakes (IV reuse, weak RNG, etc.)
- Check for custom modifications to standard algorithms

**Common weaknesses:**
- Hardcoded keys in binary
- Weak random number generators
- ECB mode (allows pattern analysis)
- IV reuse or predictable IVs
- Flawed custom ciphers

**Tools:**
```
get-references to crypto functions to trace key/data flow
inspect-memory at key storage locations
get-functions at key derivation functions
```

**Key question**: "How is it implemented, and where are the weaknesses?"

#### Phase 4: Key Extraction or Breaking
**Goal**: Recover the key or break the implementation to decrypt data

**Investigation approach:**
- Extract hardcoded keys from binary data
- Exploit weak key derivation (predictable RNG, poor entropy)
- Break custom ciphers (frequency analysis, known-plaintext, etc.)
- Leverage implementation flaws (timing, side channels, logic errors)
- Reverse engineer decryption routines to understand transformation

**Extraction techniques:**
- `inspect-memory` at key locations
- `get-data` for embedded keys
- `get-functions` to understand key derivation
- Trace backwards from encryption point

**Key question**: "How do I recover the plaintext or key?"

### Cryptographic Pattern Library

#### AES Recognition
```
S-box starts: 63 7c 77 7b f2 6b 6f c5...
Round counts: 10 (AES-128), 12 (AES-192), 14 (AES-256)
128-bit state (16 bytes, 4x4 matrix)
Rcon array for key expansion
```

#### DES Recognition
```
64-bit blocks (8 bytes)
16 rounds
Permutation tables (IP, FP)
8 S-boxes of 64 entries each
Feistel structure (split, swap, repeat)
```

#### RC4 Recognition
```
256-byte state array
KSA (Key Scheduling Algorithm): array initialization
PRGA (Pseudo-Random Generation Algorithm): swap-based generation
Simple XOR with keystream
```

#### RSA Recognition
```
Very large integers (128-512+ bytes)
Modular exponentiation: result = base^exp mod modulus
Magic constant 0x10001 (65537) common public exponent
Slow execution (big-number arithmetic)
```

---

## CTF Binary Exploitation (Pwn) Skill

**Purpose**: Solve CTF binary exploitation challenges by discovering and exploiting memory corruption vulnerabilities to read flags.

**When to use**: For buffer overflows, format strings, heap exploits, ROP challenges, or any pwn/exploitation task.

### The Exploitation Mindset

**Think in three layers:**

#### 1. Data Flow Layer
**Where does attacker-controlled data go?**
- Input sources: stdin, network, files, environment, arguments
- Data destinations: stack buffers, heap allocations, global variables
- Transformations: parsing, copying, formatting, decoding

#### 2. Memory Safety Layer
**What assumptions does the program make?**
- Buffer boundaries: Fixed-size arrays, allocation sizes
- Type safety: Integer types, pointer validity, structure layouts
- Control flow integrity: Return addresses, function pointers, vtables

#### 3. Exploitation Layer
**How can we violate trust boundaries?**
- Memory writes: Overwrite critical data (return addresses, function pointers)
- Memory reads: Leak information (addresses, canaries, pointer values)
- Control flow hijacking: Redirect execution to attacker-controlled locations
- Logic manipulation: Change program state to skip checks

### Core Question Sequence

For every CTF pwn challenge, ask these questions **in order**:

1. **What data do I control?**
   - Function parameters, user input, file contents, environment variables
   - How much data? What format? Any restrictions?

2. **Where does my data go in memory?**
   - Stack buffers? Heap allocations? Global variables?
   - What's the size of the destination? Is it checked?

3. **What interesting data is nearby in memory?**
   - Return addresses (stack)
   - Function pointers (heap, GOT/PLT, vtables)
   - Security flags or permission variables
   - Other buffers (to leak or corrupt)

4. **What happens if I send more data than expected?**
   - Buffer overflow: Overwrite adjacent memory
   - Identify what gets overwritten
   - Determine offset to critical data

5. **What can I overwrite to change program behavior?**
   - Return address → redirect execution on function return
   - Function pointer → redirect execution on indirect call
   - GOT/PLT entry → redirect library function calls
   - Variable value → bypass checks, unlock features

6. **Where can I redirect execution?**
   - Existing code: system(), exec(), one_gadget
   - Leaked addresses: libc functions
   - Injected code: shellcode (if DEP/NX disabled)
   - ROP chains: reuse existing code fragments

7. **How do I read the flag?**
   - Direct: Call system("/bin/cat flag.txt")
   - Shell: Call system("/bin/sh") and interact
   - Leak: Read flag into buffer, leak contents

### Vulnerability Discovery Patterns

#### Unsafe String Operations

**Dangerous functions:**
- `strcpy`, `strcat`, `sprintf`, `gets` - unbounded copies
- `read()`, `recv()`, `scanf("%s")` - underspecified bounds
- `strncpy` - may not null-terminate

**Investigation strategy:**
```
manage-symbols includeExternal=true to find unsafe API imports
get-references to unsafe functions to locate usage points
get-functions with includeReferenceContext=true to analyze calling context
Trace data flow from input to unsafe operation
```

#### Format String Vulnerabilities

**Vulnerable pattern:**
```c
printf(user_input);          // VULNERABLE
fprintf(fp, user_input);     // VULNERABLE
```

**Safe pattern:**
```c
printf("%s", user_input);    // SAFE
fprintf(fp, "Data: %s\n", user_input); // SAFE
```

**Exploitation primitives:**
- `%x` or `%p` → Leak stack values (addresses, canaries)
- `%s` → Arbitrary read (if pointer on stack)
- `%n` → Arbitrary write (writes byte count to pointer)
- `%N$x` → Direct parameter access

**Investigation strategy:**
```
search-code pattern for printf/fprintf/sprintf
get-functions at each match with includeContext=true
Check if format string argument is constant or variable
Trace format string source to user input
```

#### Buffer Overflow Analysis

**Stack layout understanding:**
```
High addresses
├── Function arguments
├── Return address         ← Critical target
├── Saved frame pointer
├── Local variables
└── Stack buffers          ← Overflow source
Low addresses
```

**Investigation strategy:**
```
get-functions at vulnerable function
Identify buffer size from decompilation
Check input size vs buffer size
Calculate offset to return address
Use manage-bookmarks to mark vulnerability location
```

### Exploitation Techniques

#### Return-Oriented Programming (ROP)

**Concept**: Chain together existing code fragments ("gadgets") ending in `ret` instructions.

**Investigation:**
```
search-code pattern for useful gadgets:
  - pop rdi; ret (set first argument)
  - pop rsi; ret (set second argument)
  - pop rdx; ret (set third argument)
  - system, exec locations
get-functions to find gadget addresses
```

#### GOT/PLT Overwrite

**Concept**: Overwrite Global Offset Table entries to redirect library function calls.

**Investigation:**
```
list-imports to find library functions
get-references to GOT entries
Identify writable GOT location
Calculate offset from overflow point to GOT
```

#### Shellcode Injection

**Concept**: Inject and execute custom machine code.

**Investigation:**
```
Check for executable stack (DEP/NX disabled)
Find controlled buffer location
Calculate jump address to shellcode
```

### Practical Workflow

1. **Identify vulnerability type** using pattern recognition
2. **Analyze memory layout** with `get-functions` and decompilation
3. **Calculate offsets** to critical data
4. **Find exploitation primitives** (gadgets, functions, writable locations)
5. **Construct exploit** based on available primitives
6. **Document with bookmarks** for vulnerability locations and gadgets

---

**Examples**:
- `checkout-status`


