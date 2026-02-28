# Exhaustive AgentDecompile Tools Reference (Python MCP Implementation)

This document provides an exhaustive, consolidated reference for all 49 canonical tools implemented in the Python MCP (from `src/agentdecompile_cli/registry.py`), merged with vendor aliases and synonyms from sources including GhidraMCP, pyghidra-mcp, reverse-engineering-assistant, and the plan in `.github/prompts/plan-exhaustivePythonMcpImplementation.prompt.md`. Each tool is documented once under its canonical name, with aliases/synonyms forwarding to the primary entry (no logic duplication). Parameter normalization handles casing and separators (e.g., `programPath` = `program_path` = `programPath`). Overloads are documented explicitly per canonical tool as vendor signature forwards. Descriptions are detailed, expert-crafted paragraphs explaining the tool's purpose, behavior, and use cases. All parameters are fully documented, including types where specified in sources. Synonyms for parameters are listed exhaustively. Each tool includes an examples section with practical usage scenarios.

**GUI vs Headless**: `programPath` (and synonyms) is optional in GUI mode (uses active program) but required in headless for program-scoped tools.

## Table of Contents

- [Exhaustive AgentDecompile Tools Reference (Python MCP Implementation)](#exhaustive-agentdecompile-tools-reference-python-mcp-implementation)
  - [Table of Contents](#table-of-contents)
  - [Canonical Tools (49)](#canonical-tools-49)
    - [`analyze-data-flow`](#analyze-data-flow)
    - [`analyze-program`](#analyze-program)
    - [`analyze-vtables`](#analyze-vtables)
    - [`apply-data-type`](#apply-data-type)
    - [`capture-agentdecompile-debug-info`](#capture-agentdecompile-debug-info)
    - [`change-processor`](#change-processor)
    - [`checkin-program`](#checkin-program)
    - [`create-label`](#create-label)
    - [`decompile-function`](#decompile-function)
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
    - [`list-strings`](#list-strings)
    - [`manage-bookmarks`](#manage-bookmarks)
    - [`manage-comments`](#manage-comments)
    - [`manage-data-types`](#manage-data-types)
    - [`manage-files`](#manage-files)
    - [`manage-function-tags`](#manage-function-tags)
    - [`manage-function`](#manage-function)
    - [`manage-strings`](#manage-strings)
    - [`manage-structures`](#manage-structures)
    - [`manage-symbols`](#manage-symbols)
    - [`match-function`](#match-function)
    - [`open-all-programs-in-code-browser`](#open-all-programs-in-code-browser)
    - [`open-program-in-code-browser`](#open-program-in-code-browser)
    - [`open`](#open)
    - [`read-bytes`](#read-bytes)
    - [`search-code`](#search-code)
    - [`search-constants`](#search-constants)
    - [`search-strings`](#search-strings)
    - [`search-symbols`](#search-symbols)
    - [`search-symbols-by-name`](#search-symbols-by-name)
    - [`suggest`](#suggest)
  - [Vendor Alias Forwards](#vendor-alias-forwards)
    - [`import-file` (forwards to `import-binary`)](#import-file-forwards-to-import-binary)
    - [`list-classes` (forwards to `manage-symbols`)](#list-classes-forwards-to-manage-symbols)
    - [`list-namespaces` (forwards to `manage-symbols`)](#list-namespaces-forwards-to-manage-symbols)
    - [`rename-data` (forwards to `manage-symbols`)](#rename-data-forwards-to-manage-symbols)
    - [`search-functions-by-name` (forwards to `search-symbols`)](#search-functions-by-name-forwards-to-search-symbols)
    - [`get-function-by-address` (forwards to `get-functions`)](#get-function-by-address-forwards-to-get-functions)
    - [`find-function` (forwards to `get-functions`)](#find-function-forwards-to-get-functions)
    - [`rename-function` (forwards to `manage-function`)](#rename-function-forwards-to-manage-function)
    - [`rename-function-by-address` (forwards to `manage-function`)](#rename-function-by-address-forwards-to-manage-function)
    - [`set-function-prototype` (forwards to `manage-function`)](#set-function-prototype-forwards-to-manage-function)
    - [`set-local-variable-type` (forwards to `manage-function`)](#set-local-variable-type-forwards-to-manage-function)
    - [`rename-variable` (forwards to `manage-function`)](#rename-variable-forwards-to-manage-function)
    - [`list-methods` (forwards to `list-functions`)](#list-methods-forwards-to-list-functions)
    - [`get-all-functions` (forwards to `list-functions`)](#get-all-functions-forwards-to-list-functions)
    - [`get-decompilation` (forwards to `decompile-function`)](#get-decompilation-forwards-to-decompile-function)
    - [`set-comment` (forwards to `manage-comments`)](#set-comment-forwards-to-manage-comments)
    - [`get-comments` (forwards to `manage-comments`)](#get-comments-forwards-to-manage-comments)
    - [`search-comments` (forwards to `manage-comments`)](#search-comments-forwards-to-manage-comments)
    - [`get-call-tree` (forwards to `get-call-graph`)](#get-call-tree-forwards-to-get-call-graph)
    - [`find-common-callers` (forwards to `get-call-graph`)](#find-common-callers-forwards-to-get-call-graph)
    - [`set-bookmark` (forwards to `manage-bookmarks`)](#set-bookmark-forwards-to-manage-bookmarks)
    - [`get-bookmarks` (forwards to `manage-bookmarks`)](#get-bookmarks-forwards-to-manage-bookmarks)
    - [`remove-bookmark` (forwards to `manage-bookmarks`)](#remove-bookmark-forwards-to-manage-bookmarks)
    - [`search-bookmarks` (forwards to `manage-bookmarks`)](#search-bookmarks-forwards-to-manage-bookmarks)
    - [`list-bookmark-categories` (forwards to `manage-bookmarks`)](#list-bookmark-categories-forwards-to-manage-bookmarks)
  - [Parameter Normalization Notes (Applies to All Tools)](#parameter-normalization-notes-applies-to-all-tools)
  - [Tool Consolidation Summary](#tool-consolidation-summary)
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

## Canonical Tools (49)

### `analyze-data-flow`

**Description**: This tool performs precise data flow analysis using Ghidra's decompiler P-code for backward/forward slicing and variable access tracking within a function. It enables taint analysis, value tracking, and algorithm reverse engineering by tracing data origins (backward), propagations (forward), or all reads/writes (variable_accesses). Outputs JSON paths with P-code operations, variables, and addresses, supporting pagination for large flows. All operations are transaction-safe and read-only unless explicitly modifying annotations. Ideal for understanding variable lifecycles in complex functions, debugging data dependencies, or identifying sources/sinks in security analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `find-variable-accesses(programPath, functionAddress, variableName)` from `vendor_reva` → forwards to `analyze-data-flow`.
- `trace-data-flow-backward(programPath, address)` from `vendor_reva` → forwards to `analyze-data-flow`.
- `trace-data-flow-forward(programPath, address)` from `vendor_reva` → forwards to `analyze-data-flow`.

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

**Description**: Initiates or manages Ghidra's full program analysis pipeline, including auto-analysis for functions, data types, references, and decompilation preparation. This tool triggers analyzers for disassembly, function discovery, reference creation, and advanced features like constant propagation or call graph building. It supports forcing re-analysis, verbose logging, and custom analyzer options (e.g., via program_options for symbols or GDTs). Useful for initial binary loading, updating analysis after manual changes, or applying PDB symbols. The process is resource-intensive and may run in threaded mode for performance, with options to wait for completion.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `forceAnalysis` (boolean, optional): Force re-analysis even if already done (default: false).
  - Synonyms: `forceAnalysis`, `forcea`.
- `verbose` (boolean, optional): Enable detailed logging during analysis (default: false).
  - Synonyms: `verbose`
- `noSymbols` (boolean, optional): Disable symbol loading (default: false).
  - Synonyms: `noSymbols`, `nos`.
- `gdts` (array, optional): List of GDT file paths to apply.
  - Synonyms: `gdts`
- `programOptions` (object, optional): Custom analyzer settings (e.g., {"DecompilerParameterAnalyzer.useCPlusPlus": true}).
  - Synonyms: `programOptions`, `programo`.
- `threaded` (boolean, optional): Use multi-threading (default: true).
  - Synonyms: `threaded`
- `maxWorkers` (integer, optional): Number of worker threads (default: CPU count).
  - Synonyms: `maxWorkers`, `maxw`.
- `waitForAnalysis` (boolean, optional): Block until analysis completes (default: false).
  - Synonyms: `binaryPath`, `program`, `force`, `verboseAnalysis`, `no_symbols`, `gdtFiles`, `options`, `useThreading`, `workers`, `wait`, `waitForAnalysis`
**Overloads**:
- `analyze-program(programPath)` from `vendor_reva` → forwards to `analyze-program`.

**Synonyms**: `analyze-program`, `tool_analyze_program`, `analyze_program_tool`, `cmd_analyze_program`, `run_analyze_program`, `do_analyze_program`, `api_analyze_program`, `mcp_analyze_program`, `ghidra_analyze_program`, `agentdecompile_analyze_program`, `analyze_program_command`, `analyze_program_action`, `analyze_program_op`, `analyze_program_task`, `execute_analyze_program`

**Examples**:
- Analyze a program: `analyze-program programPath="/bin.exe" forceAnalysis=true verbose=true`.
- With custom options: `analyze-program programPath="/bin.exe" programOptions={"PDBAnalyzer.useRemote": true}`.

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
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `analyze-vtable(programPath, vtableAddress, maxEntries)` from `vendor_reva` → forwards to `analyze-vtables`.
- `find-vtable-callers(programPath, functionAddress, vtableAddress, maxResults)` from `vendor_reva` → forwards to `analyze-vtables`.
- `find-vtables-containing-function(programPath, functionAddress)` from `vendor_reva` → forwards to `analyze-vtables`.

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
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `addressOrSymbol` (string, required): Address or symbol to apply the type to.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `dataTypeString` (string, required): String representation of the data type (e.g., "uint8_t[256]").
  - Synonyms: `dataTypeString`, `datats`.
- `archiveName` (string, optional): Name of the data type archive to use.
  - Synonyms: `address`, `symbol`, `dataType`, `type`, `archive`, `archiveName`, `archiven`.
**Overloads**:
- `apply-data-type(programPath, addressOrSymbol, dataTypeString, archiveName)` from `vendor_reva` → forwards to `apply-data-type`.

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
### `capture-agentdecompile-debug-info`

**Description**: Captures a comprehensive debug information bundle for AgentDecompile issues, including system configuration, status logs, environment details, and recent analysis artifacts. This tool creates a ZIP archive suitable for submission to developers, optionally including a user-provided issue summary. It is non-destructive and read-only, focusing on diagnostic data without altering the project or programs. Useful for troubleshooting analysis failures, decompiler crashes, or unexpected behaviors in MCP tools.

**Parameters**:
- `message` (string, optional): Optional summary of the issue being debugged.
  - Synonyms: `description`, `issueSummary`, `message`
**Overloads**:
- `capture-reva-debug-info(message)` from `vendor_reva` → forwards to `capture-agentdecompile-debug-info`.

**Synonyms**: `capture-agentdecompile-debug-info`, `tool_capture_agentdecompile_debug_info`, `capture_agentdecompile_debug_info_tool`, `cmd_capture_agentdecompile_debug_info`, `run_capture_agentdecompile_debug_info`, `do_capture_agentdecompile_debug_info`, `api_capture_agentdecompile_debug_info`, `mcp_capture_agentdecompile_debug_info`, `ghidra_capture_agentdecompile_debug_info`, `agentdecompile_capture_agentdecompile_debug_info`, `capture_agentdecompile_debug_info_command`, `capture_agentdecompile_debug_info_action`, `capture_agentdecompile_debug_info_op`, `capture_agentdecompile_debug_info_task`, `execute_capture_agentdecompile_debug_info`, `capture-reva-debug-info`

**Examples**:
- Capture debug info: `capture-agentdecompile-debug-info message="Decompiler crash on function 0x401000"`.

**API References**:
- **`ghidra.framework.Application`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/framework/Application.html)
  - `getApplicationVersion()` → `ApplicationVersion`
  - `getApplicationLayout()` → `ApplicationLayout`
  - `getUserSettingsDirectory()` → `ResourceFile`
- **`ghidra.framework.model.Project`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html)
  - `getName()` → `String`
  - `getProjectLocator()` → `ProjectLocator`
  - `getProjectData()` → `ProjectData`
- **`ghidra.util.Msg`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html)
  - `info(Object originator, Object message)` → `void`
  - `error(Object originator, Object message)` → `void`
- **PyGhidra**: `import pyghidra; pyghidra.started()` → `bool`; `pyghidra.open_project(name, create=False)` → `Project` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
### `change-processor`

**Description**: Changes the processor language and compiler specification for a program, allowing re-analysis with different architecture settings (e.g., switching from x86 to ARM). This tool is vital for handling multi-architecture binaries or correcting initial import assumptions. It triggers re-disassembly and re-analysis, supporting options for endianness, variant, and compiler ID. Use with caution as it may invalidate existing annotations; best paired with `analyze-program` afterward.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `change-processor(programPath, languageId, compilerSpecId)` from `vendor_reva` → forwards to `change-processor`.

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
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `comment` (string, optional): Check-in comment describing changes.
  - Synonyms: `comment`
- `keepCheckedOut` (boolean, optional): Keep the program checked out after commit (default: false).
  - Synonyms: `path`, `message`, `keepOpen`, `keepCheckedOut`, `keepco`.
**Overloads**:
- `checkin-program(programPath, message, keepCheckedOut)` from `vendor_reva` → forwards to `checkin-program`.

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
- **PyGhidra**: `with pyghidra.open_project(projName) as proj: f = proj.getProjectData().getFile('/myBin'); f.checkin(handler, monitor)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
### `create-label`

**Description**: Creates or modifies a label (symbol) at a specific address or symbol location, allowing naming of code, data, or functions for improved readability. This tool supports setting primary labels and handles namespace conflicts. It is fundamental for manual annotation during analysis, enabling better decompilation and reference tracking. Transaction-safe, it integrates with symbol management for batch operations.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `addressOrSymbol` (string, required): Address or existing symbol to label.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `labelName` (string, required): New label name.
  - Synonyms: `labelName`, `labeln`.
- `setAsPrimary` (boolean, optional): Set as primary label (default: true).
  - Synonyms: `address`, `symbol`, `name`, `primary`, `setAsPrimary`, `setap`.
**Overloads**:
- `create-label(programPath, addressOrSymbol, labelName, setAsPrimary)` from `vendor_reva` → forwards to `create-label`.

**Synonyms**: `create-label`, `tool_create_label`, `create_label_tool`, `cmd_create_label`, `run_create_label`, `do_create_label`, `api_create_label`, `mcp_create_label`, `ghidra_create_label`, `agentdecompile_create_label`, `create_label_command`, `create_label_action`, `create_label_op`, `create_label_task`, `execute_create_label`

**Examples**:
- Create label: `create-label programPath="/bin.exe" addressOrSymbol="0x401000" labelName="main_entry"`.

**API References**:
- **`ghidra.program.model.symbol.SymbolTable`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html) | [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/SymbolTable.java)
  - `createLabel(Address addr, String name, SourceType source)` → `Symbol`
  - `createLabel(Address addr, String name, Namespace namespace, SourceType source)` → `Symbol`
  - `getPrimarySymbol(Address addr)` → `Symbol`
- **`ghidra.program.flatapi.FlatProgramAPI`** — [GitHub source (v12)](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/Base/src/main/java/ghidra/program/flatapi/FlatProgramAPI.java)
  - `createLabel(Address addr, String name, boolean makePrimary, SourceType source)` → `Symbol`
  - `removeSymbol(Address addr, String name)` → `boolean`
- **`ghidra.program.model.symbol.SourceType`** — [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SourceType.html)
  - Values: `DEFAULT`, `ANALYSIS`, `IMPORTED`, `USER_DEFINED`
- **PyGhidra**: `sym = currentProgram.getSymbolTable().createLabel(toAddr('0x401000'), 'myLabel', SourceType.USER_DEFINED)` — [README](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- **Community**: [RE.SE: "Ghidra Headless Analyzer - Create Functions"](https://reverseengineering.stackexchange.com/questions/22880/ghidra-headless-analyzer-create-functions)
### `decompile-function`

**Description**: Decompiles a specific function to high-level C-like pseudocode, supporting line limits, offset starting, and inclusion of comments or references. This tool leverages Ghidra's decompiler for readable code views, aiding in understanding logic without assembly. It handles timeouts, simplification options, and batch decompilation for multiple functions. Essential for algorithm reverse engineering, with options to include caller/callee context for broader insight.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `decompile_function(name)` from `vendor_ghidramcp` → forwards to `decompile-function`.
- `decompile_function_by_address(address)` from `vendor_ghidramcp` → forwards to `decompile-function`.
- `decompile_function(binary_name, name_or_address)` from `vendor_pyghidra` → forwards to `decompile-function`.
- `get-decompilation(programPath, functionNameOrAddress, offset, limit, includeDisassembly, includeComments, includeIncomingReferences, includeReferenceContext, includeCallers, includeCallees, signatureOnly)` from `vendor_reva` → forwards to `decompile-function`.

**Synonyms**: `get-decompilation`, `decompile-function`, `tool_decompile_function`, `decompile_function_tool`, `cmd_decompile_function`, `run_decompile_function`, `do_decompile_function`, `api_decompile_function`, `mcp_decompile_function`, `ghidra_decompile_function`, `agentdecompile_decompile_function`, `decompile_function_command`, `decompile_function_action`, `decompile_function_op`, `decompile_function_task`, `decompile_function_by_address`, `decompile_function`

**Examples**:
- Decompile function: `decompile-function programPath="/bin.exe" functionIdentifier="0x401000" limit=50 includeComments=true`.

### `delete-project-binary`

**Description**: Deletes a binary file from the project, including all associated analysis data and versions. This tool is used for cleaning up projects, removing obsolete imports, or managing storage. It requires confirmation for safety and handles dependencies like open programs. Non-reversible, so use with caution in versioned projects.

**Parameters**:
- `programPath` (string, required): Path to the binary to delete.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `confirm` (boolean, optional): Confirm deletion (default: false).
  - Synonyms: `binaryPath`, `force`, `confirm`
**Overloads**:
- `delete_project_binary(binary_name)` from `vendor_pyghidra` → forwards to `delete-project-binary`.

**Synonyms**: `delete-project-binary`, `tool_delete_project_binary`, `delete_project_binary_tool`, `cmd_delete_project_binary`, `run_delete_project_binary`, `do_delete_project_binary`, `api_delete_project_binary`, `mcp_delete_project_binary`, `ghidra_delete_project_binary`, `agentdecompile_delete_project_binary`, `delete_project_binary_command`, `delete_project_binary_action`, `delete_project_binary_op`, `delete_project_binary_task`, `execute_delete_project_binary`, `delete_project_binary`

**Examples**:
- Delete binary: `delete-project-binary programPath="/oldbin.exe" confirm=true`.
### `gen-callgraph`

**Description**: Generates a call graph for the program or specific functions, using Ghidra's graph services to build caller/callee relationships. This tool supports formats like JSON or DOT for visualization, with depth limits and direction options. It is key for understanding program structure, identifying key functions, and tracing execution paths. Integrates with ChromaDB for caching and querying large graphs.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `functionIdentifier` (string, optional): Function to center the graph on.
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`, `function_name`, `function_address`
- `depth` (integer, optional): Graph depth (default: unlimited).
  - Synonyms: `depth`
- `direction` (string, optional): `callers`, `callees`, or `both` (default: both).
  - Synonyms: `direction`, `dir`, `flow`, `traversalDirection`, `walkDirection`, `orientation`, `edgeDirection`, `pathDirection`, `scanDirection`, `cgDirection`.
- `format` (string, optional): Output format (`json`, `dot`, default: json).
  - Synonyms: `function`, `maxDepth`, `mode`, `outputFormat`, `format`
- `displayType` (string, optional): Graph display type (e.g., tree, flat, graph).
  - Synonyms: `displayType`, `cgDisplayType`, `display_type`.
- `condenseThreshold` (integer, optional): Node count threshold for condensing (default: unlimited).
  - Synonyms: `condenseThreshold`, `condense_threshold`.
- `topLayers` (integer, optional): Number of top layers to show.
  - Synonyms: `topLayers`, `top_layers`.
- `bottomLayers` (integer, optional): Number of bottom layers to show.
  - Synonyms: `bottomLayers`, `bottom_layers`.
- `maxRunTime` (integer, optional): Maximum run time in seconds.
  - Synonyms: `maxRunTime`, `max_run_time`.
- `includeRefs` (boolean, optional): Include reference edges (default: true).
  - Synonyms: `includeRefs`.
**Overloads**:
- `gen_callgraph(binary_name, function_name, direction, display_type, condense_threshold, top_layers, bottom_layers, max_run_time)` from `vendor_pyghidra` → forwards to `gen-callgraph`.

**Synonyms**: `gen-callgraph`, `tool_gen_callgraph`, `gen_callgraph_tool`, `cmd_gen_callgraph`, `run_gen_callgraph`, `do_gen_callgraph`, `api_gen_callgraph`, `mcp_gen_callgraph`, `ghidra_gen_callgraph`, `agentdecompile_gen_callgraph`, `gen_callgraph_command`, `gen_callgraph_action`, `gen_callgraph_op`, `gen_callgraph_task`, `execute_gen_callgraph`, `gen_callgraph`

**Examples**:
- Generate full call graph: `gen-callgraph programPath="/bin.exe" format="dot"`.
### `get-call-graph`

**Description**: Retrieves caller/callee relationships as graphs, trees, sets, decompiled callers, or common callers for functions. Modes support visualization (graph/tree), listing (callers/callees), or advanced queries (common_callers). This tool is indispensable for navigation, dependency analysis, and bottleneck identification in call chains. Outputs JSON structures with addresses and optional decompilation context, with pagination for large results.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `find-common-callers(programPath, functionAddresses)` from `vendor_reva` → forwards to `get-call-graph`.
- `get-call-graph(programPath, functionAddress, depth)` from `vendor_reva` → forwards to `get-call-graph`.
- `get-call-tree(programPath, functionAddress, direction, maxDepth)` from `vendor_reva` → forwards to `get-call-graph`.
- `get-callers-decompiled(programPath, functionNameOrAddress, maxCallers, startIndex, includeCallContext)` from `vendor_reva` → forwards to `get-call-graph`.

**Synonyms**: `get-call-tree`, `find-common-callers`, `get-call-graph`, `tool_get_call_graph`, `get_call_graph_tool`, `cmd_get_call_graph`, `run_get_call_graph`, `do_get_call_graph`, `api_get_call_graph`, `mcp_get_call_graph`, `ghidra_get_call_graph`, `agentdecompile_get_call_graph`, `get_call_graph_command`, `get_call_graph_action`, `get_call_graph_op`, `get-callers-decompiled`

**Examples**:
- Get caller tree: `get-call-graph programPath="/bin.exe" functionIdentifier="0x401000" mode="tree" direction="callers" maxDepth=5`.

### `get-current-address`

**Description**: Retrieves the current cursor address in the active CodeBrowser tool (GUI mode only). This tool is useful for scripting interactions with the GUI, capturing user-selected locations, or synchronizing analysis with visual inspection. It returns the address as a string and requires an active program view.

**Parameters**:
- `programPath` (string, optional): Path to the program (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get_current_address()` from `vendor_ghidramcp` → forwards to `get-current-address`.

**Synonyms**: `get-current-address`, `tool_get_current_address`, `get_current_address_tool`, `cmd_get_current_address`, `run_get_current_address`, `do_get_current_address`, `api_get_current_address`, `mcp_get_current_address`, `ghidra_get_current_address`, `agentdecompile_get_current_address`, `get_current_address_command`, `get_current_address_action`, `get_current_address_op`, `get_current_address_task`, `execute_get_current_address`, `get_current_address`

**Examples**:
- Get current address: `get-current-address`.
### `get-current-function`

**Description**: Returns the function containing the current cursor address in the CodeBrowser (GUI mode only). This tool provides function metadata like name, entry point, and boundaries, aiding in context-aware scripting or quick lookups during manual analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get_current_function()` from `vendor_ghidramcp` → forwards to `get-current-function`.

**Synonyms**: `get-current-function`, `tool_get_current_function`, `get_current_function_tool`, `cmd_get_current_function`, `run_get_current_function`, `do_get_current_function`, `api_get_current_function`, `mcp_get_current_function`, `ghidra_get_current_function`, `agentdecompile_get_current_function`, `get_current_function_command`, `get_current_function_action`, `get_current_function_op`, `get_current_function_task`, `execute_get_current_function`, `get_current_function`

**Examples**:
- Get current function: `get-current-function`.
### `get-current-program`

**Description**: Retrieves metadata for the currently active program in the GUI, including name, path, language, and analysis status. This tool is essential for GUI-integrated workflows, ensuring operations target the correct binary without explicit paths.

**Parameters**:
- `programPath` (string, optional): Path to verify (uses current if omitted).
  - Synonyms: `program`, `programPath`, `programp`, `path`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `get-current-program()` from `vendor_reva` → forwards to `get-current-program`.

**Synonyms**: `get-current-program`, `tool_get_current_program`, `get_current_program_tool`, `cmd_get_current_program`, `run_get_current_program`, `do_get_current_program`, `api_get_current_program`, `mcp_get_current_program`, `ghidra_get_current_program`, `agentdecompile_get_current_program`, `get_current_program_command`, `get_current_program_action`, `get_current_program_op`, `get_current_program_task`, `execute_get_current_program`

**Examples**:
- Get current program info: `get-current-program`.
### `get-data`

**Description**: Fetches data at a specific address or symbol, returning bytes, disassembled instructions, or typed values. This tool supports various views (hex, ASCII, structured) and is key for inspecting constants, strings, or structures without full memory reads.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `addressOrSymbol` (string, required): Target address or symbol.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `view` (string, optional): Data view (`hex`, `ascii`, `structured`, default: hex).
  - Synonyms: `address`, `symbol`, `format`, `view`
**Overloads**:
- `get-data(programPath, addressOrSymbol)` from `vendor_reva` → forwards to `get-data`.

**Synonyms**: `get-data`, `tool_get_data`, `get_data_tool`, `cmd_get_data`, `run_get_data`, `do_get_data`, `api_get_data`, `mcp_get_data`, `ghidra_get_data`, `agentdecompile_get_data`, `get_data_command`, `get_data_action`, `get_data_op`, `get_data_task`, `execute_get_data`

**Examples**:
- Get data at address: `get-data programPath="/bin.exe" addressOrSymbol="0x404000" view="hex"`.
### `get-functions`

**Description**: Retrieves decompilation, disassembly, info, or call details for one or more functions, supporting batch processing and pagination. This tool is central for function-level analysis, with options for callers/callees, comments, and references. It resolves identifiers by address or name, handling arrays for multi-function queries, and limits output for large decompilations.

**Parameters**:
- `programPath` (string or array, optional): Source program path(s) (optional in GUI mode).
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
- `disassemble_function(address)` from `vendor_ghidramcp` → forwards to `get-functions`.
- `get_function_by_address(address)` from `vendor_ghidramcp` → forwards to `get-functions`.
- `get-functions(programPath, filterDefaultNames, filterByTag, untagged, verbose, startIndex, maxCount)` from `vendor_reva` → forwards to `get-functions`.

**Synonyms**: `get-function-by-address`, `find-function`, `get-functions`, `tool_get_functions`, `get_functions_tool`, `cmd_get_functions`, `run_get_functions`, `do_get_functions`, `api_get_functions`, `mcp_get_functions`, `ghidra_get_functions`, `agentdecompile_get_functions`, `get_functions_command`, `get_functions_action`, `get_functions_op`, `disassemble_function`, `get_function_by_address`

**Examples**:
- Decompile multiple: `get-functions programPath="/bin.exe" identifier=["0x401000", "main"] view="decompile" limit=30 includeCallers=true`.

### `get-references`

**Description**: Lists references to or from a target address/symbol, including code, data, or external refs, with optional context and pagination. This tool is critical for tracing data flow, finding usages, and understanding dependencies. Modes filter by type/direction, and it supports library-specific queries for imports/exports.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `maxResults` (integer, optional): Alias for limit (default: 100).
  - Synonyms: `maxResults`, `maxr`.
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
- `get_function_xrefs(name, offset, limit)` from `vendor_ghidramcp` → forwards to `get-references`.
- `get_xrefs_from(address, offset, limit)` from `vendor_ghidramcp` → forwards to `get-references`.
- `get_xrefs_to(address, offset, limit)` from `vendor_ghidramcp` → forwards to `get-references`.
- `find-cross-references(programPath, location, direction, includeFlow, includeData, includeContext, contextLines, offset, limit)` from `vendor_reva` → forwards to `get-references`.
- `find-import-references(programPath, importName, libraryName, maxResults)` from `vendor_reva` → forwards to `get-references`.
- `get-referencers-decompiled(programPath, addressOrSymbol, maxReferencers, startIndex, includeDataRefs, includeRefContext)` from `vendor_reva` → forwards to `get-references`.
- `resolve-thunk(programPath, address)` from `vendor_reva` → forwards to `get-references`.

**Synonyms**: `get-references`, `tool_get_references`, `get_references_tool`, `cmd_get_references`, `run_get_references`, `do_get_references`, `api_get_references`, `mcp_get_references`, `ghidra_get_references`, `agentdecompile_get_references`, `get_references_command`, `get_references_action`, `get_references_op`, `get_references_task`, `execute_get_references`, `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`, `find-cross-references`, `find-import-references`, `get-referencers-decompiled`, `resolve-thunk`

**Examples**:
- Get references to: `get-references programPath="/bin.exe" target="0x401000" direction="to" limit=50 includeRefContext=true`.
### `import-binary`

**Description**: Imports a binary file into the Ghidra project, supporting recursive directory imports, analysis after import, and version control options. This tool handles file discovery, folder mirroring, and post-import analysis, making it the entry point for loading new binaries. It supports depth limits, stripping paths, and enabling version tracking for collaborative work.

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
- `enableVersionControl` (boolean, optional): Enable versioning (default: false).
  - Synonyms: `filePath`, `destFolder`, `recurse`, `depth`, `autoAnalyze`, `stripPath`, `stripContainer`, `mirror`, `versioning`, `enableVersionControl`
**Overloads**:
- `import_binary(binary_path)` from `vendor_pyghidra` → forwards to `import-binary`.
- `import-file(path, destinationFolder, recursive, maxDepth, analyzeAfterImport, stripLeadingPath, stripAllContainerPath, mirrorFs, enableVersionControl)` from `vendor_reva` → forwards to `import-binary`.

**Synonyms**: `import-file`, `import-binary`, `tool_import_binary`, `import_binary_tool`, `cmd_import_binary`, `run_import_binary`, `do_import_binary`, `api_import_binary`, `mcp_import_binary`, `ghidra_import_binary`, `agentdecompile_import_binary`, `import_binary_command`, `import_binary_action`, `import_binary_op`, `import_binary_task`, `import_binary`

**Examples**:
- Import file: `import-binary path="/path/to/bin.exe" destinationFolder="/imports" analyzeAfterImport=true`.
- Recursive import: `import-binary path="/dir" recursive=true maxDepth=3 mirrorFs=true`.

### `inspect-memory`

**Description**: Inspects memory at a given address, returning bytes, disassembly, or data in various modes with length limits. This tool is useful for quick memory dumps, verifying constants, or analyzing segments without full program reads. Modes include hex, ascii, or structured views, with pagination for large regions.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `list_data_items(offset, limit)` from `vendor_ghidramcp` → forwards to `inspect-memory`.
- `list_segments(offset, limit)` from `vendor_ghidramcp` → forwards to `inspect-memory`.
- `get-memory-blocks(programPath)` from `vendor_reva` → forwards to `inspect-memory`.
- `read-memory(programPath, addressOrSymbol, length, format)` from `vendor_reva` → forwards to `inspect-memory`.

**Synonyms**: `inspect-memory`, `tool_inspect_memory`, `inspect_memory_tool`, `cmd_inspect_memory`, `run_inspect_memory`, `do_inspect_memory`, `api_inspect_memory`, `mcp_inspect_memory`, `ghidra_inspect_memory`, `agentdecompile_inspect_memory`, `inspect_memory_command`, `inspect_memory_action`, `inspect_memory_op`, `inspect_memory_task`, `execute_inspect_memory`, `list_segments`, `list_data_items`, `get-memory-blocks`, `read-memory`

**Examples**:
- Inspect bytes: `inspect-memory programPath="/bin.exe" mode="bytes" address="0x404000" length=128`.
### `list-cross-references`

**Description**: Lists all cross-references to or from addresses, similar to `get-references` but focused on code xrefs with optional filtering. This tool aids in dependency mapping and usage analysis, outputting addresses and types.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `address` (string, required): Target address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`, `nameOrAddress`, `name_or_address`.
- `direction` (string, optional): `to` or `from` (default: to).
  - Synonyms: `direction`, `dir`, `flow`, `traversalDirection`, `walkDirection`, `orientation`, `edgeDirection`, `pathDirection`, `scanDirection`.
- `maxResults` (integer, optional): Max results (default: 100).
  - Synonyms: `target`, `dir`, `limit`, `maxResults`, `maxr`.
**Overloads**:
- `list_cross_references(binary_name, name_or_address)` from `vendor_pyghidra` → forwards to `list-cross-references`.

**Synonyms**: `list-cross-references`, `tool_list_cross_references`, `list_cross_references_tool`, `cmd_list_cross_references`, `run_list_cross_references`, `do_list_cross_references`, `api_list_cross_references`, `mcp_list_cross_references`, `ghidra_list_cross_references`, `agentdecompile_list_cross_references`, `list_cross_references_command`, `list_cross_references_action`, `list_cross_references_op`, `list_cross_references_task`, `execute_list_cross_references`, `list_cross_references`

**Examples**:
- List xrefs: `list-cross-references programPath="/bin.exe" address="0x401000" direction="to"`.
### `list-exports`

**Description**: Lists exported symbols from the program, including functions and data, with filtering and pagination. This tool is essential for analyzing shared libraries or DLLs, identifying public interfaces, and checking for dynamic linking.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `filter` (string, optional): Export name filter.
  - Synonyms: `filter`, `query`
- `maxResults` (integer, optional): Max results (default: 100).
  - Synonyms: `pattern`, `limit`, `maxResults`, `maxr`.
- `offset` (integer, optional): Result offset for pagination.
  - Synonyms: `offset`, `skip`, `cursor`, `begin`, `position`.
- `startIndex` (integer, optional): Alias for offset.
  - Synonyms: `startIndex`, `starti`.
**Overloads**:
- `list_exports(offset, limit)` from `vendor_ghidramcp` → forwards to `list-exports`.
- `list_exports(binary_name, query, offset, limit)` from `vendor_pyghidra` → forwards to `list-exports`.
- `list-exports(programPath, maxResults, startIndex)` from `vendor_reva` → forwards to `list-exports`.

**Synonyms**: `list-exports`, `tool_list_exports`, `list_exports_tool`, `cmd_list_exports`, `run_list_exports`, `do_list_exports`, `api_list_exports`, `mcp_list_exports`, `ghidra_list_exports`, `agentdecompile_list_exports`, `list_exports_command`, `list_exports_action`, `list_exports_op`, `list_exports_task`, `execute_list_exports`, `list_exports`

**Examples**:
- List exports: `list-exports programPath="/dll.exe" filter="api_*"`.
### `list-functions`

**Description**: Lists all or filtered functions in the program, with options for tagging, reference counts, and verbose metadata. This tool supports querying by name, tag, or reference count, making it ideal for overviewing program structure or finding untagged functions for further analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
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
- `list_functions()` from `vendor_ghidramcp` → forwards to `list-functions`.
- `list_methods(offset, limit)` from `vendor_ghidramcp` → forwards to `list-functions`.
- `get-function-count(programPath, filterDefaultNames)` from `vendor_reva` → forwards to `list-functions`.
- `get-functions-by-similarity(programPath, searchString, filterDefaultNames, startIndex, maxCount, verbose)` from `vendor_reva` → forwards to `list-functions`.
- `get-undefined-function-candidates(programPath, maxCandidates, startIndex, minReferenceCount)` from `vendor_reva` → forwards to `list-functions`.

**Synonyms**: `list-methods`, `get-all-functions`, `list-functions`, `tool_list_functions`, `list_functions_tool`, `cmd_list_functions`, `run_list_functions`, `do_list_functions`, `api_list_functions`, `mcp_list_functions`, `ghidra_list_functions`, `agentdecompile_list_functions`, `list_functions_command`, `list_functions_action`, `list_functions_op`, `get-function-count`, `get-functions-by-similarity`, `get-undefined-function-candidates`, `list_functions`, `list_methods`

**Examples**:
- List tagged functions: `list-functions programPath="/bin.exe" filterByTag="crypto" verbose=true`.

### `list-imports`

**Description**: Lists imported symbols, libraries, and functions, with filtering for external references. This tool helps identify dependencies, potential vulnerabilities in libraries, and dynamic behaviors.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `libraryFilter` (string, optional): Library name filter.
  - Synonyms: `libraryFilter`, `libraryf`.
- `maxResults` (integer, optional): Max results (default: 100).
  - Synonyms: `filter`, `limit`, `maxResults`, `maxr`.
- `offset` (integer, optional): Result offset for pagination.
  - Synonyms: `offset`, `skip`, `cursor`, `begin`, `position`.
- `startIndex` (integer, optional): Alias for offset.
  - Synonyms: `startIndex`, `starti`.
- `query` (string, optional): General search query for filtering imports.
  - Synonyms: `query`, `searchString`, `pattern`, `text`, `q`, `needle`.
- `groupByLibrary` (boolean, optional): Group results by library (default: false).
  - Synonyms: `groupByLibrary`, `groupbl`.
**Overloads**:
- `list_imports(offset, limit)` from `vendor_ghidramcp` → forwards to `list-imports`.
- `list_imports(binary_name, query, offset, limit)` from `vendor_pyghidra` → forwards to `list-imports`.
- `list-imports(programPath, libraryFilter, maxResults, startIndex, groupByLibrary)` from `vendor_reva` → forwards to `list-imports`.

**Synonyms**: `list-imports`, `tool_list_imports`, `list_imports_tool`, `cmd_list_imports`, `run_list_imports`, `do_list_imports`, `api_list_imports`, `mcp_list_imports`, `ghidra_list_imports`, `agentdecompile_list_imports`, `list_imports_command`, `list_imports_action`, `list_imports_op`, `list_imports_task`, `execute_list_imports`, `list_imports`

**Examples**:
- List imports from kernel: `list-imports programPath="/bin.exe" libraryFilter="kernel32"`.
### `list-open-programs`

**Description**: Lists all currently open programs in the Ghidra tool (GUI mode), including paths and status. This tool is useful for managing multiple open binaries during sessions.

**Parameters**:
- None (GUI context implied).
  - Synonyms: N/A.

**Overloads**:
- `list-open-programs()` from `vendor_reva` → forwards to `list-open-programs`.

**Synonyms**: `list-open-programs`, `tool_list_open_programs`, `list_open_programs_tool`, `cmd_list_open_programs`, `run_list_open_programs`, `do_list_open_programs`, `api_list_open_programs`, `mcp_list_open_programs`, `ghidra_list_open_programs`, `agentdecompile_list_open_programs`, `list_open_programs_command`, `list_open_programs_action`, `list_open_programs_op`, `list_open_programs_task`, `execute_list_open_programs`

**Examples**:
- List open: `list-open-programs`.
### `list-project-binaries`

**Description**: Lists all binaries in the project, including metadata like size and import time. This tool provides an overview of project contents for management.

**Parameters**:
- None (project-wide).
  - Synonyms: N/A.

**Overloads**:
- `list_project_binaries()` from `vendor_pyghidra` → forwards to `list-project-binaries`.

**Synonyms**: `list-project-binaries`, `tool_list_project_binaries`, `list_project_binaries_tool`, `cmd_list_project_binaries`, `run_list_project_binaries`, `do_list_project_binaries`, `api_list_project_binaries`, `mcp_list_project_binaries`, `ghidra_list_project_binaries`, `agentdecompile_list_project_binaries`, `list_project_binaries_command`, `list_project_binaries_action`, `list_project_binaries_op`, `list_project_binaries_task`, `execute_list_project_binaries`, `list_project_binaries`

**Examples**:
- List binaries: `list-project-binaries`.
### `list-project-binary-metadata`

**Description**: Retrieves detailed metadata for project binaries, such as language, compiler, and analysis info. This tool aids in auditing project state.

**Parameters**:
- `programPath` (string, required): Binary path.
  - Synonyms: `path`, `programPath`, `programp`, `program`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
**Overloads**:
- `list_project_binary_metadata(binary_name)` from `vendor_pyghidra` → forwards to `list-project-binary-metadata`.

**Synonyms**: `list-project-binary-metadata`, `tool_list_project_binary_metadata`, `list_project_binary_metadata_tool`, `cmd_list_project_binary_metadata`, `run_list_project_binary_metadata`, `do_list_project_binary_metadata`, `api_list_project_binary_metadata`, `mcp_list_project_binary_metadata`, `ghidra_list_project_binary_metadata`, `agentdecompile_list_project_binary_metadata`, `list_project_binary_metadata_command`, `list_project_binary_metadata_action`, `list_project_binary_metadata_op`, `list_project_binary_metadata_task`, `execute_list_project_binary_metadata`, `list_project_binary_metadata`

**Examples**:
- Get metadata: `list-project-binary-metadata programPath="/bin.exe"`.
### `list-project-files`

**Description**: Lists all files in the project, including folders and non-binary files. This tool is for project navigation and cleanup.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.

- `folderPath` (string, optional): Folder path to list (default: root).
  - Synonyms: `folderPath`, `folder`, `directory`, `dir`.
- `recursive` (boolean, optional): List recursively (default: false).
  - Synonyms: `recursive`, `recurse`.
**Overloads**:
- `list-project-files(folderPath, recursive)` from `vendor_reva` → forwards to `list-project-files`.

**Synonyms**: `list-project-files`, `tool_list_project_files`, `list_project_files_tool`, `cmd_list_project_files`, `run_list_project_files`, `do_list_project_files`, `api_list_project_files`, `mcp_list_project_files`, `ghidra_list_project_files`, `agentdecompile_list_project_files`, `list_project_files_command`, `list_project_files_action`, `list_project_files_op`, `list_project_files_task`, `execute_list_project_files`

**Examples**:
- List files: `list-project-files`.
### `list-strings`

**Description**: Lists strings in the program, with filtering and limits. This tool extracts defined strings for quick review.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `filter` (string, optional): String filter.
  - Synonyms: `filter`
- `maxResults` (integer, optional): Max strings (default: 100).
  - Synonyms: `pattern`, `limit`, `maxResults`, `maxr`.
- `offset` (integer, optional): Result offset for pagination.
  - Synonyms: `offset`, `skip`, `cursor`, `begin`, `position`, `startIndex`.
**Overloads**:
- `list_strings(offset, limit, filter)` from `vendor_ghidramcp` → forwards to `list-strings`.

**Synonyms**: `list-strings`, `tool_list_strings`, `list_strings_tool`, `cmd_list_strings`, `run_list_strings`, `do_list_strings`, `api_list_strings`, `mcp_list_strings`, `ghidra_list_strings`, `agentdecompile_list_strings`, `list_strings_command`, `list_strings_action`, `list_strings_op`, `list_strings_task`, `execute_list_strings`, `list_strings`

**Examples**:
- List strings: `list-strings programPath="/bin.exe" filter="http"`.
### `manage-bookmarks`

**Description**: Manages bookmarks for addresses or symbols, supporting creation, listing, removal, and searching by type, category, or text. This tool organizes findings with categories like "Note", "Warning", or "Analysis", enabling collaborative tagging and quick navigation. Batch operations allow multiple bookmarks in one call, with transaction safety for consistency.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `action` (string, required): Action (`create`, `list`, `remove`, `search`, `removeAll`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `addressOrSymbol` (string, optional): Bookmark target.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `type` (string, optional): Type (`Note`, `Warning`, `TODO`, `Bug`, `Analysis`).
  - Synonyms: `type`
- `category` (string, optional): Category.
  - Synonyms: `category`
- `comment` (string, optional): Bookmark text.
  - Synonyms: `comment`
- `bookmarks` (array, optional): Batch bookmark objects.
  - Synonyms: `bookmarks`
- `searchText` (string, optional): Search text.
  - Synonyms: `searchText`, `searcht`.
- `maxResults` (integer, optional): Result cap (default: 100).
  - Synonyms: `maxResults`, `maxr`.
- `removeAll` (boolean, optional): Confirm remove all.
  - Synonyms: `mode`, `address`, `bookmarkType`, `cat`, `text`, `batch`, `query`, `limit`, `clearAll`, `removeAll`
- `addressRange` (string, optional): Address range filter (e.g., "0x400000-0x401000").
  - Synonyms: `addressRange`, `range`, `addrRange`.
- `categories` (array, optional): Array of categories to filter by.
  - Synonyms: `categories`, `cats`.
- `types` (array, optional): Array of bookmark types to filter by.
  - Synonyms: `types`, `bookmarkTypes`.
**Overloads**:
- `get-bookmarks(programPath, addressOrSymbol, addressRange, type, category)` from `vendor_reva` → forwards to `manage-bookmarks`.
- `list-bookmark-categories(programPath, type)` from `vendor_reva` → forwards to `manage-bookmarks`.
- `remove-bookmark(programPath, addressOrSymbol, type, category)` from `vendor_reva` → forwards to `manage-bookmarks`.
- `search-bookmarks(programPath, searchText, types, categories, addressRange, maxResults)` from `vendor_reva` → forwards to `manage-bookmarks`.
- `set-bookmark(programPath, addressOrSymbol, type, category, comment)` from `vendor_reva` → forwards to `manage-bookmarks`.

**Synonyms**: `set-bookmark`, `get-bookmarks`, `remove-bookmark`, `search-bookmarks`, `list-bookmark-categories`, `manage-bookmarks`, `tool_manage_bookmarks`, `manage_bookmarks_tool`, `cmd_manage_bookmarks`, `run_manage_bookmarks`, `do_manage_bookmarks`, `api_manage_bookmarks`, `mcp_manage_bookmarks`, `ghidra_manage_bookmarks`, `agentdecompile_manage_bookmarks`

**Examples**:
- Create bookmark: `manage-bookmarks programPath="/bin.exe" action="create" addressOrSymbol="0x401000" type="Analysis" comment="Crypto function"`.
- Search bookmarks: `manage-bookmarks programPath="/bin.exe" action="search" searchText="crypto" maxResults=20`.

### `manage-comments`

**Description**: Manages code comments at addresses, functions, or lines, supporting creation, listing, removal, and searching by type or text. This tool enhances documentation with pre/post/plate/eol/repeatable types, aiding in code explanation and collaboration. Batch operations and case-sensitive searches make it versatile for large-scale annotation.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `action` (string, required): Action (`set`, `get`, `remove`, `search`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `addressOrSymbol` (string, optional): Comment location.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `function` (string, optional): Function for function-level comments.
  - Synonyms: `function`, `functionNameOrAddress`.
- `lineNumber` (integer, optional): Decompilation line number.
  - Synonyms: `lineNumber`, `linen`.
- `comment` (string, optional): Comment text.
  - Synonyms: `comment`
- `commentType` (string, optional): Type (`pre`, `post`, `plate`, `eol`, `repeatable`).
  - Synonyms: `commentType`, `commentt`.
- `comments` (array, optional): Batch comments.
  - Synonyms: `comments`
- `start` (string, optional): Range start address.
  - Synonyms: `start`
- `end` (string, optional): Range end address.
  - Synonyms: `end`
- `commentTypes` (array, optional): Types to filter.
  - Synonyms: `commentTypes`, `commentt`.
- `searchText` (string, optional): Search text.
  - Synonyms: `searchText`, `searcht`.
- `pattern` (string, optional): Regex pattern.
  - Synonyms: `pattern`
- `caseSensitive` (boolean, optional): Case sensitivity (default: false).
  - Synonyms: `caseSensitive`, `cases`.
- `maxResults` (integer, optional): Max results (default: 100).
  - Synonyms: `maxResults`, `maxr`.
- `overrideMaxFunctionsLimit` (boolean, optional): Override function limits (default: false).
  - Synonyms: `mode`, `address`, `func`, `line`, `text`, `type`, `batch`, `from`, `to`, `types`, `query`, `regex`.
- `addressRange` (string, optional): Address range filter (e.g., "0x400000-0x401000").
  - Synonyms: `addressRange`, `range`, `addrRange`.
**Overloads**:
- `set_decompiler_comment(address, comment)` from `vendor_ghidramcp` → forwards to `manage-comments`.
- `set_disassembly_comment(address, comment)` from `vendor_ghidramcp` → forwards to `manage-comments`.
- `get-comments(programPath, addressOrSymbol, addressRange, commentTypes)` from `vendor_reva` → forwards to `manage-comments`.
- `remove-comment(programPath, addressOrSymbol, commentType)` from `vendor_reva` → forwards to `manage-comments`.
- `search-comments(programPath, searchText, caseSensitive, commentTypes, maxResults)` from `vendor_reva` → forwards to `manage-comments`.
- `set-comment(programPath, addressOrSymbol, commentType, comment)` from `vendor_reva` → forwards to `manage-comments`.
- `set-decompilation-comment(programPath, functionNameOrAddress, lineNumber, commentType, comment)` from `vendor_reva` → forwards to `manage-comments`.

**Synonyms**: `set-comment`, `get-comments`, `search-comments`, `manage-comments`, `tool_manage_comments`, `manage_comments_tool`, `cmd_manage_comments`, `run_manage_comments`, `do_manage_comments`, `api_manage_comments`, `mcp_manage_comments`, `ghidra_manage_comments`, `agentdecompile_manage_comments`, `manage_comments_command`, `manage_comments_action`, `set_decompiler_comment`, `set_disassembly_comment`, `remove-comment`, `set-decompilation-comment`

**Examples**:
- Set comment: `manage-comments programPath="/bin.exe" action="set" addressOrSymbol="0x401000" commentType="pre" comment="Entry point"`.
- Search comments: `manage-comments programPath="/bin.exe" action="search" searchText="crypto" caseSensitive=false`.

### `manage-data-types`

**Description**: Manages data types in the program or archives, including listing, applying, or creating types from categories. This tool handles built-in and custom types, subcategories, and archives for structured data analysis. It is key for type propagation and improving decompilation accuracy.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `action` (string, required): Action (`list`, `apply`, `create`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `archiveName` (string, optional): Archive name.
  - Synonyms: `archiveName`, `archiven`.
- `categoryPath` (string, optional): Category path.
  - Synonyms: `categoryPath`, `categoryp`.
- `includeSubcategories` (boolean, optional): Include subs (default: false).
  - Synonyms: `includeSubcategories`, `includes`.
- `startIndex` (integer, optional): Start index.
  - Synonyms: `startIndex`, `starti`.
- `maxCount` (integer, optional): Max types (default: 100).
  - Synonyms: `maxCount`, `maxc`.
- `dataTypeString` (string, optional): Type string for apply/create.
  - Synonyms: `dataTypeString`, `datats`.
- `addressOrSymbol` (string, optional): Apply location.
  - Synonyms: `mode`, `archive`, `category`, `subs`, `offset`, `limit`, `type`, `address`, `addressOrSymbol`
**Overloads**:
- `get-data-type-archives(programPath)` from `vendor_reva` → forwards to `manage-data-types`.
- `get-data-type-by-string(programPath, dataTypeString, archiveName)` from `vendor_reva` → forwards to `manage-data-types`.
- `get-data-types(programPath, archiveName, categoryPath, includeSubcategories, startIndex, maxCount)` from `vendor_reva` → forwards to `manage-data-types`.

**Synonyms**: `manage-data-types`, `tool_manage_data_types`, `manage_data_types_tool`, `cmd_manage_data_types`, `run_manage_data_types`, `do_manage_data_types`, `api_manage_data_types`, `mcp_manage_data_types`, `ghidra_manage_data_types`, `agentdecompile_manage_data_types`, `manage_data_types_command`, `manage_data_types_action`, `manage_data_types_op`, `manage_data_types_task`, `execute_manage_data_types`, `get-data-type-archives`, `get-data-type-by-string`, `get-data-types`

**Examples**:
- List types: `manage-data-types programPath="/bin.exe" action="list" categoryPath="/structs" includeSubcategories=true`.
### `manage-files`

**Description**: Manages project files, including import, export, deletion, and organization. This tool extends import-binary for broader file handling, supporting versioning and mirroring.

**Parameters**:
- `action` (string, required): Action (`import`, `export`, `delete`, `list`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `filePath` (string, required for import/export): File path.
  - Synonyms: `filePath`, `filep`.
- `destination` (string, optional): Project destination.
  - Synonyms: `destination`
- `recursive` (boolean, optional): Recursive (default: false).
  - Synonyms: `mode`, `path`, `dest`, `recurse`, `recursive`
**Overloads**:
- `manage-files(action, filePath, destination, recursive)` canonical signature.


**Synonyms**: `manage-files`, `tool_manage_files`, `manage_files_tool`, `cmd_manage_files`, `run_manage_files`, `do_manage_files`, `api_manage_files`, `mcp_manage_files`, `ghidra_manage_files`, `agentdecompile_manage_files`, `manage_files_command`, `manage_files_action`, `manage_files_op`, `manage_files_task`, `execute_manage_files`

**Examples**:
- Manage import: `manage-files action="import" filePath="/newfile.exe" destination="/imports"`.
### `manage-function-tags`

**Description**: Manages tags on functions for categorization, such as "crypto" or "network". This tool supports adding, removing, or listing tags, aiding in organization and querying.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `function` (string, required): Function identifier.
  - Synonyms: `function`
- `mode` (string, required): Mode (`add`, `remove`, `list`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `tags` (array or string, optional): Tags to manage.
  - Synonyms: `identifier`, `action`, `labels`, `tags`
**Overloads**:
- `function-tags(programPath, function, mode, tags)` from `vendor_reva` → forwards to `manage-function-tags`.

**Synonyms**: `manage-function-tags`, `tool_manage_function_tags`, `manage_function_tags_tool`, `cmd_manage_function_tags`, `run_manage_function_tags`, `do_manage_function_tags`, `api_manage_function_tags`, `mcp_manage_function_tags`, `ghidra_manage_function_tags`, `agentdecompile_manage_function_tags`, `manage_function_tags_command`, `manage_function_tags_action`, `manage_function_tags_op`, `manage_function_tags_task`, `execute_manage_function_tags`, `function-tags`

**Examples**:
- Add tag: `manage-function-tags programPath="/bin.exe" function="0x401000" mode="add" tags=["crypto"]`.
### `manage-function`

**Description**: Manages function properties, including renaming, setting prototypes, variable types, and propagation across binaries. This tool supports batch operations and creation if missing, essential for cleaning up analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `action` (string, required): Action (`rename`, `setPrototype`, `setVarType`, `create`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `address` (string, optional): Function address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`.
- `functionIdentifier` (string, optional): Identifier.
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`, `function_name`, `function_address`
- `name` (string, optional): New name.
  - Synonyms: `name`
- `functions` (array, optional): Batch functions.
  - Synonyms: `functions`
- `oldName` (string, optional): Old name for rename.
  - Synonyms: `oldName`, `oldn`.
- `newName` (string, optional): New name.
  - Synonyms: `newName`, `newn`, `new_name`.
- `variableMappings` (object, optional): Var renames.
  - Synonyms: `variableMappings`, `variablem`.
- `prototype` (string, optional): Signature.
  - Synonyms: `prototype`
- `variableName` (string, optional): Var name.
  - Synonyms: `variableName`, `variablen`, `variable_name`.
- `newType` (string, optional): New type.
  - Synonyms: `newType`, `newt`, `new_type`.
- `datatypeMappings` (object, optional): Type maps.
  - Synonyms: `datatypeMappings`, `datatypem`.
- `archiveName` (string, optional): Archive.
  - Synonyms: `archiveName`, `archiven`.
- `createIfNotExists` (boolean, optional): Create if missing (default: false).
  - Synonyms: `createIfNotExists`, `createine`.
- `propagate` (boolean, optional): Propagate changes (default: false).
  - Synonyms: `propagate`
- `propagateProgramPaths` (array, optional): Target paths.
  - Synonyms: `propagateProgramPaths`, `propagatepp`.
- `propagateMaxCandidates` (integer, optional): Max candidates.
  - Synonyms: `propagateMaxCandidates`, `propagatemc`.
- `propagateMaxInstructions` (integer, optional): Max instructions.
  - Synonyms: `mode`, `funcAddr`, `identifier`, `new_name`, `batch`, `old_name`, `vars`, `signature`, `varName`, `type`, `types`, `archive`.
**Overloads**:
- `rename_function(old_name, new_name)` from `vendor_ghidramcp` → forwards to `manage-function`.
- `rename_function_by_address(function_address, new_name)` from `vendor_ghidramcp` → forwards to `manage-function`.
- `rename_variable(function_name, old_name, new_name)` from `vendor_ghidramcp` → forwards to `manage-function`.
- `set_function_prototype(function_address, prototype)` from `vendor_ghidramcp` → forwards to `manage-function`.
- `set_local_variable_type(function_address, variable_name, new_type)` from `vendor_ghidramcp` → forwards to `manage-function`.
- `change-variable-datatypes(programPath, functionNameOrAddress, datatypeMappings, archiveName)` from `vendor_reva` → forwards to `manage-function`.
- `create-function(programPath, address, name)` from `vendor_reva` → forwards to `manage-function`.
- `rename-variables(programPath, functionNameOrAddress, variableMappings)` from `vendor_reva` → forwards to `manage-function`.
- `set-function-prototype(programPath, location, signature, createIfNotExists)` from `vendor_reva` → forwards to `manage-function`.

**Synonyms**: `rename-function`, `rename-function-by-address`, `set-function-prototype`, `set-local-variable-type`, `rename-variable`, `manage-function`, `tool_manage_function`, `manage_function_tool`, `cmd_manage_function`, `run_manage_function`, `do_manage_function`, `api_manage_function`, `mcp_manage_function`, `ghidra_manage_function`, `agentdecompile_manage_function`, `change-variable-datatypes`, `create-function`, `rename-variables`, `rename_function`, `rename_function_by_address`, `set_function_prototype`, `set_local_variable_type`, `rename_variable`

**Examples**:
- Rename function: `manage-function programPath="/bin.exe" action="rename" functionIdentifier="0x401000" newName="main"`.

### `manage-strings`

**Description**: Manages string definitions, searching, and filtering, including referencing functions. This tool extracts and annotates strings for analysis.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, required): Mode (`list`, `search`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `pattern` (string, optional): Pattern.
  - Synonyms: `pattern`, `regexPattern`
- `searchString` (string, optional): Search string.
  - Synonyms: `searchString`, `searchs`.
- `filter` (string, optional): Filter.
  - Synonyms: `filter`
- `startIndex` (integer, optional): Start.
  - Synonyms: `startIndex`, `starti`.
- `maxCount` (integer, optional): Max.
  - Synonyms: `maxCount`, `maxc`.
- `offset` (integer, optional): Offset.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Limit.
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `maxResults` (integer, optional): Max results.
  - Synonyms: `maxResults`, `maxr`.
- `includeReferencingFunctions` (boolean, optional): Include refs (default: false).
  - Synonyms: `action`, `query`, `str`, `pat`, `index`, `count`, `start`, `max`, `refs`, `includeReferencingFunctions`
**Overloads**:
- `get-strings(programPath, startIndex, maxCount, includeReferencingFunctions)` from `vendor_reva` → forwards to `manage-strings`.
- `get-strings-by-similarity(programPath, searchString, startIndex, maxCount, includeReferencingFunctions)` from `vendor_reva` → forwards to `manage-strings`.
- `get-strings-count(programPath)` from `vendor_reva` → forwards to `manage-strings`.
- `search-strings-regex(programPath, regexPattern, startIndex, maxCount, includeReferencingFunctions)` from `vendor_reva` → forwards to `manage-strings`.

**Synonyms**: `manage-strings`, `tool_manage_strings`, `manage_strings_tool`, `cmd_manage_strings`, `run_manage_strings`, `do_manage_strings`, `api_manage_strings`, `mcp_manage_strings`, `ghidra_manage_strings`, `agentdecompile_manage_strings`, `manage_strings_command`, `manage_strings_action`, `manage_strings_op`, `manage_strings_task`, `execute_manage_strings`, `get-strings`, `get-strings-by-similarity`, `get-strings-count`, `search-strings-regex`

**Examples**:
- Search strings: `manage-strings programPath="/bin.exe" mode="search" pattern="http" maxResults=50`.
### `manage-structures`

**Description**: Manages data structures, parsing C definitions, creating, editing, or applying them. This tool is vital for defining custom structs.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `action` (string, required): Action (`create`, `apply`, `list`).
  - Synonyms: `action`, `mode`, `operation`, `command`, `op`, `task`, `intent`, `actionType`, `verb`.
- `cDefinition` (string, optional): C struct definition.
  - Synonyms: `cDefinition`, `cd`.
- `headerContent` (string, optional): Header content.
  - Synonyms: `headerContent`, `headerc`.
- `structureName` (string, optional): Name.
  - Synonyms: `structureName`, `structuren`.
- `name` (string, optional): Alias.
  - Synonyms: `name`
- `size` (integer, optional): Size.
  - Synonyms: `size`
- `type` (string, optional): Type.
  - Synonyms: `type`
- `category` (string, optional): Category.
  - Synonyms: `category`
- `packed` (boolean, optional): Packed (default: false).
  - Synonyms: `packed`
- `description` (string, optional): Desc.
  - Synonyms: `description`
- `fields` (array, optional): Fields.
  - Synonyms: `fields`
- `addressOrSymbol` (string, optional): Apply location.
  - Synonyms: `addressOrSymbol`, `addressos`, `address`, `symbol`, `target`, `nameOrAddress`, `addrOrSym`.
- `clearExisting` (boolean, optional): Clear existing (default: false).
  - Synonyms: `clearExisting`, `cleare`.
- `force` (boolean, optional): Force (default: false).
  - Synonyms: `force`
- `nameFilter` (string, optional): Filter.
  - Synonyms: `nameFilter`, `namef`.
- `includeBuiltIn` (boolean, optional): Include built-ins (default: false).
  - Synonyms: `mode`, `cDef`, `header`, `structName`, `sz`, `tp`, `cat`, `pack`, `desc`, `flds`, `addr`, `clear`, `includeBuiltIn`.
- `fieldName` (string, optional): Field name for add/modify field operations.
  - Synonyms: `fieldName`, `field`.
- `dataType` (string, optional): Data type string for field operations.
  - Synonyms: `dataType`, `fieldType`, `dt`.
- `offset` (integer, optional): Byte offset for field placement in structure.
  - Synonyms: `offset`, `fieldOffset`, `byteOffset`.
- `comment` (string, optional): Comment for structure or field.
  - Synonyms: `comment`, `fieldComment`.
- `bitfield` (boolean, optional): Mark field as bitfield (default: false).
  - Synonyms: `bitfield`, `isBitfield`.
- `newDataType` (string, optional): New data type for modify-field.
  - Synonyms: `newDataType`, `newType`.
- `newFieldName` (string, optional): New name for modify-field.
  - Synonyms: `newFieldName`, `renameTo`.
- `newComment` (string, optional): New comment for modify-field.
  - Synonyms: `newComment`, `updatedComment`.
- `newLength` (integer, optional): New length for modify-field.
  - Synonyms: `newLength`, `newSize`.
**Overloads**:
- `add-structure-field(programPath, structureName, fieldName, dataType, offset, comment, bitfield)` from `vendor_reva` → forwards to `manage-structures`.
- `apply-structure(programPath, structureName, addressOrSymbol, clearExisting)` from `vendor_reva` → forwards to `manage-structures`.
- `create-structure(programPath, name, size, type, category, packed, description)` from `vendor_reva` → forwards to `manage-structures`.
- `delete-structure(programPath, structureName, force)` from `vendor_reva` → forwards to `manage-structures`.
- `get-structure-info(programPath, structureName)` from `vendor_reva` → forwards to `manage-structures`.
- `list-structures(programPath, category, nameFilter, includeBuiltIn)` from `vendor_reva` → forwards to `manage-structures`.
- `modify-structure-field(programPath, structureName, fieldName, offset, newDataType, newFieldName, newComment, newLength)` from `vendor_reva` → forwards to `manage-structures`.
- `modify-structure-from-c(programPath, cDefinition)` from `vendor_reva` → forwards to `manage-structures`.
- `parse-c-header(programPath, headerContent, category)` from `vendor_reva` → forwards to `manage-structures`.
- `parse-c-structure(programPath, cDefinition, category)` from `vendor_reva` → forwards to `manage-structures`.
- `validate-c-structure(cDefinition)` from `vendor_reva` → forwards to `manage-structures`.

**Synonyms**: `manage-structures`, `tool_manage_structures`, `manage_structures_tool`, `cmd_manage_structures`, `run_manage_structures`, `do_manage_structures`, `api_manage_structures`, `mcp_manage_structures`, `ghidra_manage_structures`, `agentdecompile_manage_structures`, `manage_structures_command`, `manage_structures_action`, `manage_structures_op`, `manage_structures_task`, `execute_manage_structures`, `add-structure-field`, `apply-structure`, `create-structure`, `delete-structure`, `get-structure-info`, `list-structures`, `modify-structure-field`, `modify-structure-from-c`, `parse-c-header`, `parse-c-structure`, `validate-c-structure`

**Examples**:
- Create struct: `manage-structures programPath="/bin.exe" action="create" cDefinition="struct MyStruct { int x; char y; };"`.
### `manage-symbols`

**Description**: Manages symbols, including listing classes/namespaces/imports/exports, renaming, creating labels, and demangling. This tool groups by library, filters defaults, and supports pagination for large symbol tables.

**Parameters**:
- `programPath` (string, optional): Path to the program in the project (optional in GUI mode).
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `mode` (string, required): Mode (`list`, `rename`, `create`, `demangle`).
  - Synonyms: `mode`, `analysisMode`, `action`, `view`, `operation`, `type`, `kind`, `strategy`, `behaviorMode`.
- `address` (string, optional): Address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`.
- `labelName` (string, optional): Label.
  - Synonyms: `labelName`, `labeln`.
- `newName` (string, optional): New name.
  - Synonyms: `newName`, `newn`, `new_name`.
- `libraryFilter` (string, optional): Library filter.
  - Synonyms: `libraryFilter`, `libraryf`.
- `maxResults` (integer, optional): Max.
  - Synonyms: `maxResults`, `maxr`.
- `startIndex` (integer, optional): Start.
  - Synonyms: `startIndex`, `starti`.
- `offset` (integer, optional): Offset.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Limit.
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `groupByLibrary` (boolean, optional): Group by library (default: false).
  - Synonyms: `groupByLibrary`, `groupbl`.
- `includeExternal` (boolean, optional): Include externals (default: false).
  - Synonyms: `includeExternal`, `includee`.
- `maxCount` (integer, optional): Max count.
  - Synonyms: `maxCount`, `maxc`.
- `filterDefaultNames` (boolean, optional): Filter defaults (default: false).
  - Synonyms: `filterDefaultNames`, `filterdn`.
- `demangleAll` (boolean, optional): Demangle all (default: false).
  - Synonyms: `action`, `addr`, `name`, `renameTo`, `library`, `max`, `index`, `start`, `count`, `group`, `extern`, `defaults`.
**Overloads**:
- `list_classes(offset, limit)` from `vendor_ghidramcp` → forwards to `manage-symbols`.
- `list_namespaces(offset, limit)` from `vendor_ghidramcp` → forwards to `manage-symbols`.
- `rename_data(address, new_name)` from `vendor_ghidramcp` → forwards to `manage-symbols`.
- `get-symbols(programPath, includeExternal, startIndex, maxCount, filterDefaultNames)` from `vendor_reva` → forwards to `manage-symbols`.
- `get-symbols-count(programPath, includeExternal, filterDefaultNames)` from `vendor_reva` → forwards to `manage-symbols`.

**Synonyms**: `list-classes`, `list-namespaces`, `rename-data`, `manage-symbols`, `tool_manage_symbols`, `manage_symbols_tool`, `cmd_manage_symbols`, `run_manage_symbols`, `do_manage_symbols`, `api_manage_symbols`, `mcp_manage_symbols`, `ghidra_manage_symbols`, `agentdecompile_manage_symbols`, `manage_symbols_command`, `manage_symbols_action`, `get-symbols`, `get-symbols-count`, `list_classes`, `list_namespaces`, `rename_data`

**Examples**:
- List imports: `manage-symbols programPath="/bin.exe" mode="list" libraryFilter="kernel32"`.

### `match-function`

**Description**: Matches functions across binaries using fingerprints, with similarity thresholds and propagation of names/tags/comments. This tool uses ChromaDB for efficient matching and batch processing.

**Parameters**:
- `programPath` (string, optional): Source program.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `functionIdentifier` (string, required): Function.
  - Synonyms: `functionIdentifier`, `functioni`, `function`, `functionId`, `identifier`, `functionAddress`, `functionNameOrAddress`.
- `targetProgramPaths` (array, required): Targets.
  - Synonyms: `targetProgramPaths`, `targetpp`.
- `maxInstructions` (integer, optional): Max instrs.
  - Synonyms: `maxInstructions`, `maxi`.
- `minSimilarity` (number, optional): Min similarity (default: 0.8).
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
### `open-all-programs-in-code-browser`

**Description**: Opens all project programs in the CodeBrowser tool (GUI mode), for bulk viewing.

**Parameters**:
- None.
  - Synonyms: N/A.

**Overloads**:
- `open-all-programs-in-code-browser()` canonical signature.


**Synonyms**: `open-all-programs-in-code-browser`, `tool_open_all_programs_in_code_browser`, `open_all_programs_in_code_browser_tool`, `cmd_open_all_programs_in_code_browser`, `run_open_all_programs_in_code_browser`, `do_open_all_programs_in_code_browser`, `api_open_all_programs_in_code_browser`, `mcp_open_all_programs_in_code_browser`, `ghidra_open_all_programs_in_code_browser`, `agentdecompile_open_all_programs_in_code_browser`, `open_all_programs_in_code_browser_command`, `open_all_programs_in_code_browser_action`, `open_all_programs_in_code_browser_op`, `open_all_programs_in_code_browser_task`, `execute_open_all_programs_in_code_browser`

**Examples**:
- Open all: `open-all-programs-in-code-browser`.
### `open-program-in-code-browser`

**Description**: Opens a specific program in the CodeBrowser (GUI mode).

**Parameters**:
- `programPath` (string, required): Path.
  - Synonyms: `path`, `programPath`, `programp`, `program`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `open-program-in-code-browser(programPath)` canonical signature.


**Synonyms**: `open-program-in-code-browser`, `tool_open_program_in_code_browser`, `open_program_in_code_browser_tool`, `cmd_open_program_in_code_browser`, `run_open_program_in_code_browser`, `do_open_program_in_code_browser`, `api_open_program_in_code_browser`, `mcp_open_program_in_code_browser`, `ghidra_open_program_in_code_browser`, `agentdecompile_open_program_in_code_browser`, `open_program_in_code_browser_command`, `open_program_in_code_browser_action`, `open_program_in_code_browser_op`, `open_program_in_code_browser_task`, `execute_open_program_in_code_browser`

**Examples**:
- Open program: `open-program-in-code-browser programPath="/bin.exe"`.
### `open`

**Description**: Opens a program from the project for analysis, supporting GUI integration.

**Parameters**:
- `programPath` (string, required): Path.
  - Synonyms: `path`, `programPath`, `programp`, `program`, `binaryPath`, `filePath`, `targetProgram`.
**Overloads**:
- `open(programPath)` canonical signature.


**Synonyms**: `open`, `tool_open`, `open_tool`, `cmd_open`, `run_open`, `do_open`, `api_open`, `mcp_open`, `ghidra_open`, `agentdecompile_open`, `open_command`, `open_action`, `open_op`, `open_task`, `execute_open`, `open_alias_18`

**Examples**:
- Open: `open programPath="/bin.exe"`.
### `read-bytes`

**Description**: Reads raw bytes from memory, similar to inspect-memory but byte-focused.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `address` (string, required): Address.
  - Synonyms: `address`, `addr`, `startAddress`, `targetAddress`, `location`, `offsetAddress`, `addressValue`, `memAddress`, `va`.
- `length` (integer, required): Length.
  - Synonyms: `start`, `size`, `length`
**Overloads**:
- `read_bytes(binary_name, address, size)` from `vendor_pyghidra` → forwards to `read-bytes`.

**Synonyms**: `read-bytes`, `tool_read_bytes`, `read_bytes_tool`, `cmd_read_bytes`, `run_read_bytes`, `do_read_bytes`, `api_read_bytes`, `mcp_read_bytes`, `ghidra_read_bytes`, `agentdecompile_read_bytes`, `read_bytes_command`, `read_bytes_action`, `read_bytes_op`, `read_bytes_task`, `execute_read_bytes`, `read_bytes`

**Examples**:
- Read bytes: `read-bytes programPath="/bin.exe" address="0x404000" length=256`.
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
- `search_code(binary_name, query, limit, offset, search_mode, include_full_code, preview_length, similarity_threshold)` from `vendor_pyghidra` → forwards to `search-code`.
- `search-decompilation(programPath, pattern, maxResults, caseSensitive, overrideMaxFunctionsLimit)` from `vendor_reva` → forwards to `search-code`.

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
- `find-constant-uses(programPath, value, maxResults)` from `vendor_reva` → forwards to `search-constants`.
- `find-constants-in-range(programPath, minValue, maxValue, maxResults)` from `vendor_reva` → forwards to `search-constants`.
- `list-common-constants(programPath, topN, minValue, includeSmallValues)` from `vendor_reva` → forwards to `search-constants`.

**Synonyms**: `search-constants`, `tool_search_constants`, `search_constants_tool`, `cmd_search_constants`, `run_search_constants`, `do_search_constants`, `api_search_constants`, `mcp_search_constants`, `ghidra_search_constants`, `agentdecompile_search_constants`, `search_constants_command`, `search_constants_action`, `search_constants_op`, `search_constants_task`, `execute_search_constants`, `find-constant-uses`, `find-constants-in-range`, `list-common-constants`

**Examples**:
- Search constant: `search-constants programPath="/bin.exe" mode="specific" value="0xdeadbeef"`.
### `search-strings`

**Description**: Searches strings with regex or similarity, similar to manage-strings search.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `pattern` (string, optional): Regex.
  - Synonyms: `pattern`
- `searchString` (string, optional): String.
  - Synonyms: `searchString`, `searchs`.
- `maxResults` (integer, optional): Max (default: 100).
  - Synonyms: `regex`, `query`, `limit`, `maxResults`, `maxr`.
**Overloads**:
- `search_strings(binary_name, query, limit)` from `vendor_pyghidra` → forwards to `search-strings`.

**Synonyms**: `search-strings`, `tool_search_strings`, `search_strings_tool`, `cmd_search_strings`, `run_search_strings`, `do_search_strings`, `api_search_strings`, `mcp_search_strings`, `ghidra_search_strings`, `agentdecompile_search_strings`, `search_strings_command`, `search_strings_action`, `search_strings_op`, `search_strings_task`, `execute_search_strings`, `search_strings`

**Examples**:
- Search strings: `search-strings programPath="/bin.exe" pattern="https?"`.
### `search-symbols`

**Description**: Searches symbols by name or pattern, including externals.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`.
- `query` (string, required): Search query.
  - Synonyms: `query`, `searchString`, `pattern`, `filter`, `text`, `q`, `needle`, `searchQuery`, `match`.
- `offset` (integer, optional): Offset.
  - Synonyms: `offset`, `startIndex`, `start`, `index`, `from`, `skip`, `cursor`, `begin`, `position`.
- `limit` (integer, optional): Limit.
  - Synonyms: `limit`, `maxResults`, `maxCount`, `count`, `size`, `max`, `take`, `cap`, `pageSize`.
- `includeExternal` (boolean, optional): Include externals (default: false).
  - Synonyms: `includeExternal`, `includee`.
- `filterDefaultNames` (boolean, optional): Filter defaults (default: false).
  - Synonyms: `q`, `start`, `max`, `extern`, `defaults`, `filterDefaultNames`, `filterdn`.
**Overloads**:
- `search_functions_by_name(query, offset, limit)` from `vendor_ghidramcp` → forwards to `search-symbols`.

**Synonyms**: `search-functions-by-name`, `search-symbols`, `tool_search_symbols`, `search_symbols_tool`, `cmd_search_symbols`, `run_search_symbols`, `do_search_symbols`, `api_search_symbols`, `mcp_search_symbols`, `ghidra_search_symbols`, `agentdecompile_search_symbols`, `search_symbols_command`, `search_symbols_action`, `search_symbols_op`, `search_symbols_task`, `search_functions_by_name`

**Examples**:
- Search symbols: `search-symbols programPath="/bin.exe" query="main"`.

### `search-symbols-by-name`

**Description**: Searches symbols by exact name, subset of search-symbols.

**Parameters**:
- `programPath` (string, optional): Path.
  - Synonyms: `programPath`, `programp`, `program`, `path`, `binaryPath`, `filePath`, `targetProgram`, `binary_name`
- `query` (string, required): Name.
  - Synonyms: `query`, `searchString`, `pattern`, `filter`, `text`, `q`, `needle`, `searchQuery`, `match`.
- `maxResults` (integer, optional): Max (default: 100).
  - Synonyms: `name`, `limit`, `maxResults`, `maxr`.
- `offset` (integer, optional): Result offset for pagination.
  - Synonyms: `offset`, `skip`, `cursor`, `begin`, `position`, `startIndex`.
**Overloads**:
- `search_symbols_by_name(binary_name, query, offset, limit)` from `vendor_pyghidra` → forwards to `search-symbols-by-name`.

**Synonyms**: `search-symbols-by-name`, `tool_search_symbols_by_name`, `search_symbols_by_name_tool`, `cmd_search_symbols_by_name`, `run_search_symbols_by_name`, `do_search_symbols_by_name`, `api_search_symbols_by_name`, `mcp_search_symbols_by_name`, `ghidra_search_symbols_by_name`, `agentdecompile_search_symbols_by_name`, `search_symbols_by_name_command`, `search_symbols_by_name_action`, `search_symbols_by_name_op`, `search_symbols_by_name_task`, `execute_search_symbols_by_name`, `search_symbols_by_name`

**Examples**:
- Search by name: `search-symbols-by-name programPath="/bin.exe" query="entry"`.
### `suggest`

**Description**: Suggests improvements like names, types, or comments based on context.

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


**Synonyms**: `suggest`, `tool_suggest`, `suggest_tool`, `cmd_suggest`, `run_suggest`, `do_suggest`, `api_suggest`, `mcp_suggest`, `ghidra_suggest`, `agentdecompile_suggest`, `suggest_command`, `suggest_action`, `suggest_op`, `suggest_task`, `execute_suggest`, `suggest_alias_18`

**Examples**:
- Suggest name: `suggest programPath="/bin.exe" suggestionType="name" address="0x401000"`.
## Vendor Alias Forwards

### `import-file` (forwards to `import-binary`)

**Description**: Forwards to `import-binary` for file import logic.

**Parameters**: Same as `import-binary`.
  - Synonyms: All from `import-binary`.

**Overloads**:
- `import-file(...)` vendor/alias entry → forwards to `import-binary` with the same supported parameters.


**Examples**: Same as `import-binary`.

### `list-classes` (forwards to `manage-symbols`)

**Description**: Forwards to `manage-symbols` with mode for classes.

**Parameters**: Same as `manage-symbols`, with `mode` preset to classes.
  - Synonyms: All from `manage-symbols`, plus `classes` for mode.

**Overloads**:
- `list-classes(...)` vendor/alias entry → forwards to `manage-symbols` with the same supported parameters.


**Examples**: `list-classes programPath="/bin.exe" maxResults=50`.

### `list-namespaces` (forwards to `manage-symbols`)

**Description**: Forwards to `manage-symbols` with mode for namespaces.

**Parameters**: Same as `manage-symbols`, with `mode` preset to namespaces.
  - Synonyms: All from `manage-symbols`, plus `namespaces` for mode.

**Overloads**:
- `list-namespaces(...)` vendor/alias entry → forwards to `manage-symbols` with the same supported parameters.


**Examples**: `list-namespaces programPath="/bin.exe"`.

### `rename-data` (forwards to `manage-symbols`)

**Description**: Forwards to `manage-symbols` for data renaming.

**Parameters**: Same as `manage-symbols`, with `mode` preset to rename_data.
  - Synonyms: All from `manage-symbols`, plus `rename_data` for mode.

**Overloads**:
- `rename-data(...)` vendor/alias entry → forwards to `manage-symbols` with the same supported parameters.


**Examples**: `rename-data programPath="/bin.exe" address="0x404000" newName="sbox"`.

### `search-functions-by-name` (forwards to `search-symbols`)

**Description**: Forwards to `search-symbols` for function subset.

**Parameters**: Same as `search-symbols`.
  - Synonyms: All from `search-symbols`.

**Overloads**:
- `search-functions-by-name(...)` vendor/alias entry → forwards to `search-symbols` with the same supported parameters.


**Examples**: Same as `search-symbols`.

### `get-function-by-address` (forwards to `get-functions`)

**Description**: Forwards to `get-functions` for single function by address.

**Parameters**: Same as `get-functions`.
  - Synonyms: All from `get-functions`.

**Overloads**:
- `get-function-by-address(...)` vendor/alias entry → forwards to `get-functions` with the same supported parameters.


**Examples**: Same as `get-functions`.

### `find-function` (forwards to `get-functions`)

**Description**: Forwards to `get-functions`.

**Parameters**: Same as `get-functions`.
  - Synonyms: All from `get-functions`.

**Overloads**:
- `find-function(...)` vendor/alias entry → forwards to `get-functions` with the same supported parameters.


**Examples**: Same as `get-functions`.

### `rename-function` (forwards to `manage-function`)

**Description**: Forwards to `manage-function` for rename.

**Parameters**: Same as `manage-function`, with `action` preset to rename.
  - Synonyms: All from `manage-function`.

**Overloads**:
- `rename-function(...)` vendor/alias entry → forwards to `manage-function` with the same supported parameters.


**Examples**: Same as `manage-function`.

### `rename-function-by-address` (forwards to `manage-function`)

**Description**: Forwards to `manage-function` for rename by address.

**Parameters**: Same as `manage-function`.
  - Synonyms: All from `manage-function`.

**Overloads**:
- `rename-function-by-address(...)` vendor/alias entry → forwards to `manage-function` with the same supported parameters.


**Examples**: Same as `manage-function`.

### `set-function-prototype` (forwards to `manage-function`)

**Description**: Forwards to `manage-function` for prototype setting.

**Parameters**: Same as `manage-function`, with `action` preset to setPrototype.
  - Synonyms: All from `manage-function`.

**Overloads**:
- `set-function-prototype(...)` vendor/alias entry → forwards to `manage-function` with the same supported parameters.


**Examples**: Same as `manage-function`.

### `set-local-variable-type` (forwards to `manage-function`)

**Description**: Forwards to `manage-function` for local var type.

**Parameters**: Same as `manage-function`.
  - Synonyms: All from `manage-function`.

**Overloads**:
- `set-local-variable-type(...)` vendor/alias entry → forwards to `manage-function` with the same supported parameters.


**Examples**: Same as `manage-function`.

### `rename-variable` (forwards to `manage-function`)

**Description**: Forwards to `manage-function` for var rename.

**Parameters**: Same as `manage-function`.
  - Synonyms: All from `manage-function`.

**Overloads**:
- `rename-variable(...)` vendor/alias entry → forwards to `manage-function` with the same supported parameters.


**Examples**: Same as `manage-function`.

### `list-methods` (forwards to `list-functions`)

**Description**: Forwards to `list-functions` for methods.

**Parameters**: Same as `list-functions`.
  - Synonyms: All from `list-functions`.

**Overloads**:
- `list-methods(...)` vendor/alias entry → forwards to `list-functions` with the same supported parameters.


**Examples**: Same as `list-functions`.

### `get-all-functions` (forwards to `list-functions`)

**Description**: Forwards to `list-functions` for all.

**Parameters**: Same as `list-functions`.
  - Synonyms: All from `list-functions`.

**Overloads**:
- `get-all-functions(...)` vendor/alias entry → forwards to `list-functions` with the same supported parameters.


**Examples**: Same as `list-functions`.

### `get-decompilation` (forwards to `decompile-function`)

**Description**: Forwards to `decompile-function`.

**Parameters**: Same as `decompile-function`.
  - Synonyms: All from `decompile-function`.

**Overloads**:
- `get-decompilation(...)` vendor/alias entry → forwards to `decompile-function` with the same supported parameters.


**Examples**: Same as `decompile-function`.

### `set-comment` (forwards to `manage-comments`)

**Description**: Forwards to `manage-comments` for set.

**Parameters**: Same as `manage-comments`, with `action` preset to set.
  - Synonyms: All from `manage-comments`.

**Overloads**:
- `set-comment(...)` vendor/alias entry → forwards to `manage-comments` with the same supported parameters.


**Examples**: Same as `manage-comments`.

### `get-comments` (forwards to `manage-comments`)

**Description**: Forwards to `manage-comments` for get.

**Parameters**: Same as `manage-comments`, with `action` preset to get.
  - Synonyms: All from `manage-comments`.

**Overloads**:
- `get-comments(...)` vendor/alias entry → forwards to `manage-comments` with the same supported parameters.


**Examples**: Same as `manage-comments`.

### `search-comments` (forwards to `manage-comments`)

**Description**: Forwards to `manage-comments` for search.

**Parameters**: Same as `manage-comments`, with `action` preset to search.
  - Synonyms: All from `manage-comments`.

**Overloads**:
- `search-comments(...)` vendor/alias entry → forwards to `manage-comments` with the same supported parameters.


**Examples**: Same as `manage-comments`.

### `get-call-tree` (forwards to `get-call-graph`)

**Description**: Forwards to `get-call-graph` for tree mode.

**Parameters**: Same as `get-call-graph`, with `mode` preset to tree.
  - Synonyms: All from `get-call-graph`.

**Overloads**:
- `get-call-tree(...)` vendor/alias entry → forwards to `get-call-graph` with the same supported parameters.


**Examples**: Same as `get-call-graph`.

### `find-common-callers` (forwards to `get-call-graph`)

**Description**: Forwards to `get-call-graph` for common_callers.

**Parameters**: Same as `get-call-graph`, with `mode` preset to common_callers.
  - Synonyms: All from `get-call-graph`.

**Overloads**:
- `find-common-callers(...)` vendor/alias entry → forwards to `get-call-graph` with the same supported parameters.


**Examples**: Same as `get-call-graph`.

### `set-bookmark` (forwards to `manage-bookmarks`)

**Description**: Forwards to `manage-bookmarks` for create.

**Parameters**: Same as `manage-bookmarks`, with `action` preset to create.
  - Synonyms: All from `manage-bookmarks`.

**Overloads**:
- `set-bookmark(...)` vendor/alias entry → forwards to `manage-bookmarks` with the same supported parameters.


**Examples**: Same as `manage-bookmarks`.

### `get-bookmarks` (forwards to `manage-bookmarks`)

**Description**: Forwards to `manage-bookmarks` for list.

**Parameters**: Same as `manage-bookmarks`, with `action` preset to list.
  - Synonyms: All from `manage-bookmarks`.

**Overloads**:
- `get-bookmarks(...)` vendor/alias entry → forwards to `manage-bookmarks` with the same supported parameters.


**Examples**: Same as `manage-bookmarks`.

### `remove-bookmark` (forwards to `manage-bookmarks`)

**Description**: Forwards to `manage-bookmarks` for remove.

**Parameters**: Same as `manage-bookmarks`, with `action` preset to remove.
  - Synonyms: All from `manage-bookmarks`.

**Overloads**:
- `remove-bookmark(...)` vendor/alias entry → forwards to `manage-bookmarks` with the same supported parameters.


**Examples**: Same as `manage-bookmarks`.

### `search-bookmarks` (forwards to `manage-bookmarks`)

**Description**: Forwards to `manage-bookmarks` for search.

**Parameters**: Same as `manage-bookmarks`, with `action` preset to search.
  - Synonyms: All from `manage-bookmarks`.

**Overloads**:
- `search-bookmarks(...)` vendor/alias entry → forwards to `manage-bookmarks` with the same supported parameters.


**Examples**: Same as `manage-bookmarks`.

### `list-bookmark-categories` (forwards to `manage-bookmarks`)

**Description**: Forwards to `manage-bookmarks` for category listing.

**Parameters**: Same as `manage-bookmarks`.
  - Synonyms: All from `manage-bookmarks`.

**Overloads**:
- `list-bookmark-categories(...)` vendor/alias entry → forwards to `manage-bookmarks` with the same supported parameters.


**Examples**: `list-bookmark-categories programPath="/bin.exe" type="Analysis"`.

## Parameter Normalization Notes (Applies to All Tools)

Parameters are normalized via `normalize_identifier()`: casing-insensitive, separators ignored (e.g., `programPath` = `program_path` = `program-path`). Common synonyms include `programPath/binaryName/binary/program`, `mode/action/type`, `address/addressOrSymbol/symbol/target`, `limit/maxResults/maxCount/count`, `offset/startIndex/start`, `query/searchString/pattern/filter/q`.

## Tool Consolidation Summary

Consolidated groups: Symbols (`manage-symbols`), Strings (`manage-strings`), Functions (`list-functions`, `manage-function`, etc.), Memory (`inspect-memory`), Project/GUI (`open`, `list-project-files`, etc.), References (`get-references`), Types (`manage-data-types`, `manage-structures`), Annotations (`manage-comments`, `manage-bookmarks`), Flow/Graph (`analyze-data-flow`, `get-call-graph`, etc.).

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

`manage-function` to rename and set prototype.

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
- Use `manage-symbols` with `mode='imports'` to list external symbols
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
manage-function with mode='rename_variable': var_1 → encryption_key, iVar2 → buffer_size
manage-function with mode='set_variable_type': local_10 from undefined4 to uint32_t
manage-function with mode='set_prototype': void FUN_00401234(uint8_t* data, size_t len)
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
5. Use `manage-function` to rename variables based on usage patterns
6. Use `manage-function` to fix variable types where evident from operations
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

*These skills leverage the AgentDecompile MCP tools to provide systematic, evidence-based approaches to various reverse engineering challenges. Refer to the canonical tool entries above for detailed parameter documentation.*