# AgentDecompile API Documentation Reference

This document provides **direct URLs** to all API documentation used by AgentDecompile. Use these links when adding Javadoc comments or understanding external dependencies.

**Inline documentation**: Java classes in `src/main/java/agentdecompile/` include Javadoc with `@see` tags and HTML links to relevant API docs. Documented files:
- **util**: AddressUtil, ProgramLookupUtil, MemoryUtil, DataTypeParserUtil, SchemaUtil, SymbolUtil, SmartSuggestionsUtil, ProjectUtil, DecompilationContextUtil, DebugLogger, DecompilationDiffUtil, FunctionFingerprintUtil, AgentDecompileInternalServiceRegistry, AgentDecompileToolLogger, EnvConfigUtil, IntelligentBookmarkUtil, DecompilationReadTracker, SimilarityComparator, ToolLogCollector
- **tools**: ToolProvider, AbstractToolProvider, ProgramValidationException, DecompilerToolProvider, FunctionToolProvider, SymbolToolProvider, BookmarkToolProvider, CallGraphToolProvider, CommentToolProvider, ConstantSearchToolProvider, DataToolProvider, DataFlowToolProvider, DataTypeToolProvider, GetFunctionToolProvider, ImportExportToolProvider, MemoryToolProvider, ProjectToolProvider, StringToolProvider, StructureToolProvider, SuggestionToolProvider, VtableToolProvider, CrossReferencesToolProvider
- **plugin**: AgentDecompilePlugin, AgentDecompileApplicationPlugin, AgentDecompileProgramManager, ConfigManager, ConfigChangeListener
- **plugin/config**: ConfigurationBackend, ConfigurationBackendListener, FileBackend, InMemoryBackend, ToolOptionsBackend
- **server**: McpServerManager, ApiKeyAuthFilter, KeepAliveFilter, RequestLoggingFilter, CachingRequestWrapper, CachingResponseWrapper
- **resources**: ResourceProvider, AbstractResourceProvider
- **resources/impl**: ProgramListResource, StaticAnalysisResultsResource, AgentDecompileDebugInfoResource
- **services**: AgentDecompileMcpService
- **headless**: AgentDecompileHeadlessLauncher
- **ui**: AgentDecompileProvider, CaptureDebugAction
- **debug**: DebugCaptureService, DebugInfoCollector
- **root**: agentdecompileFileSystem, agentdecompileExporter, agentdecompileAnalyzer

---

## Quick Reference – Main Documentation URLs

| API | Base URL | Description |
|-----|----------|-------------|
| **Ghidra API** | https://ghidra.re/ghidra_docs/api/ | Official Ghidra Javadoc (reverse engineering framework) |
| **MCP Java SDK** | https://github.com/modelcontextprotocol/java-sdk | Model Context Protocol Java server/client SDK |
| **MCP Java Server Docs** | https://modelcontextprotocol.info/docs/sdk/java/mcp-server/ | MCP Server implementation guide |
| **MCP Protocol Spec** | https://modelcontextprotocol.io/ | Model Context Protocol specification |
| **Ghidra Main Site** | https://ghidra.re/ | Ghidra project home |

---

## Ghidra API – Package & Class URLs

AgentDecompile uses the Ghidra Java API extensively. The URL pattern is:
`https://ghidra.re/ghidra_docs/api/{package-path}/{ClassName}.html`  
(dots become slashes)

### Core Program Model

| Class | Full URL |
|-------|----------|
| Program | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html |
| Listing | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html |
| Function | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html |
| FunctionManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html |
| FunctionIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionIterator.html |
| FunctionTag | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionTag.html |
| FunctionTagManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionTagManager.html |
| Instruction | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html |
| CodeUnit | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html |
| CodeUnitIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnitIterator.html |
| Data | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html |
| DataIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/DataIterator.html |
| Parameter | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Parameter.html |
| Variable | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Variable.html |
| CommentType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CommentType.html |
| Bookmark | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Bookmark.html |
| BookmarkManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/BookmarkManager.html |

### Address Model

| Class | Full URL |
|-------|----------|
| Address | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html |
| AddressSpace | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html |
| AddressSet | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSet.html |
| AddressSetView | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSetView.html |
| AddressIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressIterator.html |
| AddressOutOfBoundsException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressOutOfBoundsException.html |

### Symbol Model

| Class | Full URL |
|-------|----------|
| Symbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html |
| SymbolTable | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html |
| SymbolIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolIterator.html |
| SymbolType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolType.html |
| Namespace | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Namespace.html |
| Reference | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Reference.html |
| ReferenceManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html |
| ReferenceIterator | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceIterator.html |
| ExternalLocation | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ExternalLocation.html |
| SourceType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SourceType.html |

### Data Type Model

| Class | Full URL |
|-------|----------|
| DataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html |
| DataTypeManager | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html |
| DataTypeComponent | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeComponent.html |
| Structure | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Structure.html |
| StructureDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/StructureDataType.html |
| Union | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Union.html |
| UnionDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/UnionDataType.html |
| Composite | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Composite.html |
| Category | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Category.html |
| CategoryPath | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/CategoryPath.html |
| BitFieldDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/BitFieldDataType.html |
| FunctionDefinitionDataType | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html |
| ParameterDefinition | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/ParameterDefinition.html |
| ParameterDefinitionImpl | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/ParameterDefinitionImpl.html |
| DataTypeConflictHandler | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeConflictHandler.html |
| InvalidDataTypeException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/InvalidDataTypeException.html |
| DataTypeDependencyException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeDependencyException.html |

### Memory Model

| Class | Full URL |
|-------|----------|
| Memory | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html |
| MemoryBlock | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html |
| MemoryAccessException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryAccessException.html |

### Decompiler

| Class | Full URL |
|-------|----------|
| DecompInterface | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html |
| DecompileResults | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html |
| DecompiledFunction | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompiledFunction.html |
| ClangToken | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangToken.html |
| ClangTokenGroup | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangTokenGroup.html |
| ClangLine | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/ClangLine.html |
| DecompilerUtils | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/DecompilerUtils.html |

### PCode (High-Level IR)

| Class | Full URL |
|-------|----------|
| HighFunction | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html |
| HighSymbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html |
| HighFunctionDBUtil | https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunctionDBUtil.html |

### Framework & Plugin

| Class | Full URL |
|-------|----------|
| AppInfo | https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html |
| Project | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html |
| ProjectLocator | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html |
| DomainFile | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html |
| DomainFolder | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html |
| DomainObject | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html |
| ToolManager | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html |
| PluginTool | https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html |
| ProgramManager | https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html |
| CodeViewerService | https://ghidra.re/ghidra_docs/api/ghidra/app/services/CodeViewerService.html |
| ProgramLocation | https://ghidra.re/ghidra_docs/api/ghidra/program/util/ProgramLocation.html |
| AutoAnalysisManager | https://ghidra.re/ghidra_docs/api/ghidra/app/plugin/core/analysis/AutoAnalysisManager.html |

### Language / Compiler Spec

| Class | Full URL |
|-------|----------|
| Language | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Language.html |
| LanguageID | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageID.html |
| LanguageService | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageService.html |
| DefaultLanguageService | https://ghidra.re/ghidra_docs/api/ghidra/program/util/DefaultLanguageService.html |
| CompilerSpec | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpec.html |
| CompilerSpecID | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecID.html |
| LanguageCompilerSpecPair | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageCompilerSpecPair.html |
| LanguageNotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageNotFoundException.html |
| CompilerSpecNotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecNotFoundException.html |

### Utilities & Parsing

| Class | Full URL |
|-------|----------|
| Msg | https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html |
| TaskMonitor | https://ghidra.re/ghidra_docs/api/ghidra/util/task/TaskMonitor.html |
| TimeoutTaskMonitor | https://ghidra.re/ghidra_docs/api/ghidra/util/task/TimeoutTaskMonitor.html |
| DataTypeParser | https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html |
| CParser | https://ghidra.re/ghidra_docs/api/ghidra/app/util/cparser/C/CParser.html |
| FunctionSignatureParser | https://ghidra.re/ghidra_docs/api/ghidra/app/util/parser/FunctionSignatureParser.html |
| Demangler | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/Demangler.html |
| DemanglerUtil | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/DemanglerUtil.html |
| DemangledObject | https://ghidra.re/ghidra_docs/api/ghidra/app/util/demangler/DemangledObject.html |

### Importer / Loader / Exporter

| Class | Full URL |
|-------|----------|
| Loader | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/Loader.html |
| LoadSpec | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/LoadSpec.html |
| LoadResults | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/LoadResults.html |
| Loaded | https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/Loaded.html |
| ByteProvider | https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/ByteProvider.html |
| MessageLog | https://ghidra.re/ghidra_docs/api/ghidra/app/util/importer/MessageLog.html |
| ExporterException | https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/ExporterException.html |
| BatchGroup | https://ghidra.re/ghidra_docs/api/ghidra/plugins/importer/batch/BatchGroup.html |
| BatchInfo | https://ghidra.re/ghidra_docs/api/ghidra/plugins/importer/batch/BatchInfo.html |

### Commands

| Class | Full URL |
|-------|----------|
| CreateFunctionCmd | https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/CreateFunctionCmd.html |

### Exceptions

| Class | Full URL |
|-------|----------|
| CancelledException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/CancelledException.html |
| DuplicateNameException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/DuplicateNameException.html |
| InvalidInputException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/InvalidInputException.html |
| InvalidNameException | https://ghidra.re/ghidra_docs/api/ghidra/util/InvalidNameException.html |
| CodeUnitInsertionException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/util/CodeUnitInsertionException.html |
| VersionException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/VersionException.html |
| IncompatibleLanguageException | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/IncompatibleLanguageException.html |
| OverlappingFunctionException | https://ghidra.re/ghidra_docs/api/ghidra/program/database/function/OverlappingFunctionException.html |

### Other Ghidra Classes

| Class | Full URL |
|-------|----------|
| UndefinedFunction | https://ghidra.re/ghidra_docs/api/ghidra/util/UndefinedFunction.html |
| GhidraProject | https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html |
| DefaultCheckinHandler | https://ghidra.re/ghidra_docs/api/ghidra/framework/data/DefaultCheckinHandler.html |
| FileSystemService | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FileSystemService.html |
| FSRL | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FSRL.html |
| FSUtilities | https://ghidra.re/ghidra_docs/api/ghidra/formats/gfilesystem/FSUtilities.html |
| LocalFileSystem | https://ghidra.re/ghidra_docs/api/ghidra/framework/store/local/LocalFileSystem.html |
| ClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientAuthenticator.html |
| ClientUtil | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html |
| PasswordClientAuthenticator | https://ghidra.re/ghidra_docs/api/ghidra/framework/client/PasswordClientAuthenticator.html |
| LockException | https://ghidra.re/ghidra_docs/api/ghidra/framework/store/LockException.html |
| NotOwnerException | https://ghidra.re/ghidra_docs/api/ghidra/util/NotOwnerException.html |
| NotFoundException | https://ghidra.re/ghidra_docs/api/ghidra/util/exception/NotFoundException.html |

---

## MCP (Model Context Protocol) Java SDK

AgentDecompile uses `io.modelcontextprotocol.sdk:mcp` (BOM 0.17.0). The SDK provides server and client implementations.

### Documentation URLs

| Resource | URL |
|----------|-----|
| **MCP Java SDK GitHub** | https://github.com/modelcontextprotocol/java-sdk |
| **MCP Java Server Docs** | https://modelcontextprotocol.info/docs/sdk/java/mcp-server/ |
| **MCP Protocol Spec** | https://modelcontextprotocol.io/ |
| **MCP SDK Package** | io.modelcontextprotocol.sdk (Maven Central) |

### Key MCP Classes Used by AgentDecompile

- `io.modelcontextprotocol.server.McpSyncServer` – Synchronous MCP server
- `io.modelcontextprotocol.server.McpServer` – Base MCP server interface
- `io.modelcontextprotocol.spec.McpSchema` – MCP schema types (Tool, CallToolRequest, CallToolResult, Content, TextContent, JsonSchema, Resource, ReadResourceResult, etc.)
- `io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification` – Tool registration
- `io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification` – Resource registration
- `io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider` – HTTP transport
- `io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper` – JSON mapping

---

## How to Add API Documentation Links in Code

When documenting a method or class that uses Ghidra or MCP APIs:

1. Add a `@see` or inline link in the Javadoc:
   ```java
   /**
    * Parses an address string using the program's address factory.
    * @see ghidra.program.model.address.Address
    * @see <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html">Address API</a>
    */
   ```

2. Or use a concise reference block at the top of the class:
   ```java
   /**
    * Utility for address formatting and parsing.
    * <p>Ghidra APIs used: {@link ghidra.program.model.address.Address}, {@link ghidra.program.model.listing.Program}</p>
    * <p>API docs: <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API</a></p>
    */
   ```

---

## Package Summary Pages (Ghidra)

| Package | URL |
|---------|-----|
| ghidra.program.model.address | https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/package-summary.html |
| ghidra.program.model.listing | https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/package-summary.html |
| ghidra.program.model.symbol | https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/package-summary.html |
| ghidra.program.model.data | https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html |
| ghidra.program.model.mem | https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/package-summary.html |
| ghidra.app.decompiler | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html |
| ghidra.app.decompiler.component | https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/component/package-summary.html |
| ghidra.framework.model | https://ghidra.re/ghidra_docs/api/ghidra/framework/model/package-summary.html |
| ghidra.framework.plugintool | https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/package-summary.html |
| ghidra.util.task | https://ghidra.re/ghidra_docs/api/ghidra/util/task/package-summary.html |
