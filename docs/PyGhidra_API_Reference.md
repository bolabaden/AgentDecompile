# PyGhidra API Reference

This document is an **exhaustive reference** for:
1. **The pyghidra Python package** (`.venv/lib/site-packages/pyghidra`) — public API with import path, name, arguments, return values, and **at least one paragraph per symbol** explaining what it does and how to use it.
2. **The Ghidra Java API** exposed via PyGhidra (JVM) — grouped by primary object, then getters / setters / other. Every function and method is documented with signatures and **paragraph-level documentation** (behavior, typical use, and caveats).

Built from: installed package inspection, Context7, Ghidra API docs (ghidra.re), and repo research (src/agentdecompile_cli, ghidrecomp, mcp_server/providers).

### Quick reference (by symbol)

| Symbol / concept | Section |
|------------------|---------|
| **Part A (pyghidra)** | A.1–A.6 |
| `open_project`, `program_context`, `consume_program`, `analyze`, `transaction`, `program_loader`, `walk_project`, `walk_programs` | A.1 |
| Launchers (`HeadlessPyGhidraLauncher`, etc.) | A.2 |
| Script / PyGhidraScript | A.3 |
| ApplicationInfo, ExtensionDetails | A.4 |
| ProgramLoader.Builder | A.5 |
| **Part B (Ghidra Java API)** | B.1–B.10 |
| Program, DomainObject, release() | B.1 |
| Memory, MemoryBlock | B.1.1 |
| BookmarkManager, Bookmark | B.1.2 |
| Function, FunctionTag, Namespace | B.2 |
| Address, AddressFactory, AddressSpace, AddressSetView, AddressRange, AddressSet | B.3, B.3.1 |
| Listing, CommentType, CodeUnit, Data, Instruction | B.4 |
| FunctionManager | B.5 |
| DecompInterface, DecompileOptions, DecompileResults, DecompiledFunction, HighFunction | B.6 |
| FlatProgramAPI | B.7 |
| SymbolTable, Symbol, SourceType, SymbolType | B.8 |
| ReferenceManager, Reference, RefType | B.9 |
| DomainFile, DomainFolder, Project, ProjectData, GhidraProject | B.10.1–B.10.2 |
| GhidraProgramUtilities, ProgramUtilities, DefinedDataIterator, DefinedStringIterator, TaskMonitor | B.10.3 |
| DataTypeParser, CppExporter, DemanglerUtil, ApplyFunctionDataTypesCmd | B.10.4–B.10.7 |
| CheckinHandler, ClientUtil, BSim, GenSignatures | B.10.8–B.10.12 |
| Remaining imports (AutoAnalysisManager, AppInfo, GhidraURL, DataType/Component/Variable, ghidra_builtins) | B.10.13 |

---

# Part A: pyghidra Python package

Source: `.venv/lib/site-packages/pyghidra/` (version 3.0.2). Only public, user-facing API is listed.

## A.1 Module `pyghidra` (root)

| Import path | Name | Arguments | Returns |
|-------------|------|------------|--------|
| `pyghidra` | `__version__` | — | `str` (e.g. `"3.0.2"`) |
| `pyghidra` | `debug_callback` | `suspend=False`, `**kwargs` (forwarded to `pydevd.settrace`) | decorator; returns decorated function |
| `pyghidra` | `start` | `verbose=False`, `*, install_dir: Optional[Path] = None` | `PyGhidraLauncher` (the launcher used to start) |
| `pyghidra` | `started` | — | `bool` (whether PyGhidra has already started) |
| `pyghidra` | `open_program` | `binary_path`, `project_location=None`, `project_name=None`, `analyze=True`, `language=None`, `compiler=None`, `loader=None`, `program_name=None`, `nested_project_location=True` | context manager → `Generator[FlatProgramAPI]` (deprecated: use `open_project` + `program_context` or `program_loader`) |
| `pyghidra` | `run_script` | `binary_path`, `script_path`, `project_location=None`, `project_name=None`, `script_args=None`, `verbose=False`, `analyze=True`, `lang=None`, `compiler=None`, `loader=None`, `program_name=None`, `nested_project_location=True`, `*, install_dir=None` | `None` (deprecated: use `open_project` + `ghidra_script`) |
| `pyghidra` | `open_project` | `path: Union[str, Path]`, `name: str`, `create: bool = False` | `Project` (raises `FileNotFoundError` if not found and not create) |
| `pyghidra` | `open_filesystem` | `path: Union[str, Path]` | `GFileSystem` (raises `ValueError` if unsupported) |
| `pyghidra` | `consume_program` | `project: Project`, `path: Union[str, Path]`, `consumer: Optional[Any] = None` | `Tuple[Program, Object]` (caller must `program.release(consumer)` when done; raises `FileNotFoundError` or `ProgramTypeError`) |
| `pyghidra` | `program_context` | `project: Project`, `path: Union[str, Path]` | context manager → `Generator[Program]` |
| `pyghidra` | `analyze` | `program: Program`, `monitor: Optional[TaskMonitor] = None` | `str` (analysis log) |
| `pyghidra` | `ghidra_script` | `path: Union[str, Path]`, `project: Project`, `program: Optional[Program] = None`, `script_args: List[str] = []`, `echo_stdout=True`, `echo_stderr=True` | `Tuple[str, str]` (stdout, stderr) |
| `pyghidra` | `transaction` | `program: Program`, `description: str = "Unnamed Transaction"` | context manager → `Generator[int]` (transaction ID) |
| `pyghidra` | `analysis_properties` | `program: Program` | `Options` (Program.ANALYSIS_PROPERTIES) |
| `pyghidra` | `program_info` | `program: Program` | `Options` (Program.PROGRAM_INFO) |
| `pyghidra` | `program_loader` | — | `ProgramLoader.Builder` (see A.5) |
| `pyghidra` | `task_monitor` | `timeout: Optional[int] = None` | `TaskMonitor` (DUMMY if timeout is None) |
| `pyghidra` | `walk_project` | `project: Project`, `callback: Callable[[DomainFile], None]`, `start: Union[str, Path] = "/"`, `file_filter: Callable[[DomainFile], bool] = lambda _: True` | `None` (raises `FileNotFoundError` if start folder missing) |
| `pyghidra` | `walk_programs` | `project: Project`, `callback: Callable[[DomainFile, Program], None]`, `start: Union[str, Path] = "/"`, `program_filter: Callable[[DomainFile, Program], bool] = lambda _f, _p: True` | `None` |
| `pyghidra` | `ProgramTypeError` | (extends `TypeError`) | exception when path is not a Program |
| `pyghidra` | `get_current_interpreter` | — | `GhidraScript` or `None` (active PyGhidra console script) |
| `pyghidra` | `DeferredPyGhidraLauncher` | class | see A.2 |
| `pyghidra` | `GuiPyGhidraLauncher` | class | see A.2 |
| `pyghidra` | `HeadlessPyGhidraLauncher` | class | see A.2 |
| `pyghidra` | `ApplicationInfo` | dataclass from `version` | see A.4 |
| `pyghidra` | `ExtensionDetails` | dataclass from `version` | see A.4 |

**Documentation (A.1).** — **`__version__`**: String version of the installed pyghidra package (e.g. `"3.0.2"`); use for logging or compatibility checks. — **`debug_callback`**: Decorator that invokes `pydevd.settrace` with optional `suspend` and keyword args; use for attaching a debugger to PyGhidra script execution. — **`start`**: Starts the JVM and initializes Ghidra; returns the launcher used. Call once before any ghidra/pyghidra API use. Pass `install_dir` if Ghidra is not on the default path. — **`started`**: Returns whether PyGhidra has already been started; useful to avoid double-start. — **`open_program`** (deprecated): Legacy context manager that opens a binary in a temporary project and yields a `FlatProgramAPI`; prefer **`open_project`** plus **`program_context`** or **`program_loader`** for explicit project and program lifecycle. — **`run_script`** (deprecated): Runs a Ghidra script on a binary; prefer **`open_project`** + **`ghidra_script`** for project-scoped script runs. — **`open_project`**: Opens (or creates) a Ghidra project at `path` with `name`. Returns a `Project` (Java); use with **`consume_program`** or **`program_loader`** to load programs. Raises `FileNotFoundError` if the project does not exist and `create` is False. — **`open_filesystem`**: Opens a **GFileSystem** (Ghidra virtual filesystem) for non-Ghidra filesystem paths (e.g. to browse or read files without importing as a program); raises `ValueError` if the path type is unsupported. Use when you need filesystem access through Ghidra’s **GFileSystem** API rather than Python’s **pathlib** or **os**.

**Documentation (GFileSystem).** **GFileSystem** (Ghidra virtual filesystem) is returned by **`pyghidra.open_filesystem(path)`** for supported path types (e.g. certain archive or filesystem URLs). It provides a Ghidra-native view over files and directories so you can list, open, or read content without importing the path as a Program. Use it when your script must operate on non-program files through Ghidra’s file APIs; for program loading use **open_project** and **consume_program** or **program_context** instead. — **`consume_program`**: Loads a program from the project at the given path; returns `(Program, consumer)`. The caller **must** call `program.release(consumer)` when done to release the program lock. Raises `FileNotFoundError` or `ProgramTypeError` if the path is missing or not a program. — **`program_context`**: Context manager that yields a `Program` for the given project and path; handles release on exit. Prefer this when you do not need the consumer object. — **`analyze`**: Runs Ghidra analysis on the program and returns the analysis log string; pass an optional `TaskMonitor` for cancellation/progress. — **`ghidra_script`**: Executes a Ghidra script file with the given project and optional program; returns `(stdout, stderr)`. Use for automation that relies on existing Ghidra scripts. — **`transaction`**: Context manager that starts a program transaction and yields the transaction ID; commit happens on exit. Use for any sequence of modifications (renames, comments, etc.); required before changing program state. — **`analysis_properties`** / **`program_info`**: Return `Options` for program analysis and program metadata respectively; use to read or adjust analysis and info settings. — **`program_loader`**: Returns a **ProgramLoader.Builder** (see A.5) for loading binaries into a project with optional language/compiler/analyze. — **`task_monitor`**: Returns a `TaskMonitor`; if `timeout` is None, returns `TaskMonitor.DUMMY` (no-op). Use for long-running operations that support cancellation. — **`walk_project`**: Recursively invokes a callback for each `DomainFile` under `start`, optionally filtered by `file_filter`; use to enumerate project contents. — **`walk_programs`**: Like `walk_project` but invokes the callback with `(DomainFile, Program)` and only for program files; use a `program_filter` to skip certain programs. Release each program when done if you obtained it via a path that implies consumption. — **`ProgramTypeError`**: Subclass of `TypeError` raised when a path in the project does not refer to a Program. — **`get_current_interpreter`**: Returns the active GhidraScript (PyGhidra console) or None; used in script contexts to access the current script state.

## A.2 Launchers (`pyghidra.launcher`)

**Base:** `PyGhidraLauncher` (not in `__all__` but base for the three below).

| Import path | Name | Arguments | Returns |
|-------------|------|------------|--------|
| `pyghidra` | `HeadlessPyGhidraLauncher` | `verbose=False`, `*, install_dir: Path = None` | launcher instance |
| `pyghidra` | `GuiPyGhidraLauncher` | `verbose=False`, `*, install_dir: Path = None` | launcher instance |
| `pyghidra` | `DeferredPyGhidraLauncher` | `verbose=False`, `*, install_dir: Path = None` | launcher instance |

**PyGhidraLauncher** (and subclasses) — methods:

| Method | Arguments | Returns |
|--------|------------|--------|
| `__init__` | `verbose=False`, `*, install_dir: Path = None` | — (raises `ValueError` if install_dir invalid) |
| `start` | `**jpype_kwargs` | `None` (starts JVM if not started) |
| `get_install_path` | `plugin_name: str` | `Path` |
| `uninstall_plugin` | `plugin_name: str` | `None` |
| `install_plugin` | `source_path: Path`, `details: ExtensionDetails` | `None` (queued until start) |
| `has_launched` | (static) | `bool` (JVM started and Ghidra initialized) |

**DeferredPyGhidraLauncher only:**

| Method | Arguments | Returns |
|--------|------------|--------|
| `initialize_ghidra` | `headless: bool = True` | `None` |

**Documentation (A.2).** — **HeadlessPyGhidraLauncher** / **GuiPyGhidraLauncher** / **DeferredPyGhidraLauncher**: Concrete launchers for headless, GUI, or deferred JVM startup. Use **HeadlessPyGhidraLauncher** for scripts and servers; use **GuiPyGhidraLauncher** when the Ghidra UI is needed; use **DeferredPyGhidraLauncher** when you want to start the JVM first and initialize Ghidra later. — **`__init__`**: Constructs the launcher; `install_dir` overrides the Ghidra install path (required if Ghidra is not in the default location). Raises `ValueError` if the path is invalid. — **`start`**: Starts the JVM if not already started; pass `**jpype_kwargs` for JVM options. — **`get_install_path`**: Returns the filesystem path for a Ghidra plugin by name. — **`uninstall_plugin`** / **`install_plugin`**: Remove or queue installation of a plugin; `install_plugin` is applied when the launcher is started. — **`has_launched`** (static): Returns True if the JVM has been started and Ghidra initialized. — **`initialize_ghidra`** (DeferredPyGhidraLauncher only): Completes Ghidra initialization after JVM start; use `headless=True` for non-GUI use.

## A.3 Script (`pyghidra.script`)

| Import path | Name | Arguments | Returns |
|-------------|------|------------|--------|
| `pyghidra` | `get_current_interpreter` | — | `GhidraScript` or `None` |

**PyGhidraScript** (dict-like wrapper; used internally by `run_script` / `_flat_api`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `__init__` | `jobj=None` | — |
| `set` | `state: GhidraState`, `monitor: TaskMonitor`, `writer: Writer`, `error_writer: Writer` | `None` (injects script state, monitor, and output streams per GhidraScript contract) |
| `run` | `script_path: str = None`, `script_args: List[str] = None` | `None` |
| `get_static` | `key` | value or sentinel |
| `get_static_view` | — | `_StaticMap` (for rlcompleter) |

**Documentation (A.3).** — **`get_current_interpreter`**: Returns the currently active GhidraScript when running inside a PyGhidra script/console, or None; use to access script globals (e.g. `currentProgram`) from helper code. — **PyGhidraScript**: Dict-like wrapper around the Java GhidraScript used by `run_script` and internal flat API. **`set`**: Injects GhidraState, TaskMonitor, and writer/error_writer so the script has access to program, monitor, and output. **`run`**: Executes the script at `script_path` with optional `script_args`. **`get_static`** / **`get_static_view`**: Read script static variables or a static view for completion; used by the PyGhidra REPL.

## A.4 Version / app info (`pyghidra.version`)

| Import path | Name | Arguments | Returns |
|-------------|------|------------|--------|
| `pyghidra` | `ApplicationInfo` | dataclass: `name`, `version`, `release_name`, `revision_ghidra`, `build_date`, `build_date_short`, `layout_version`, `gradle_min`, `java_min`, `java_max`, `java_compiler`, `gradle_max` | — |
| `ApplicationInfo.from_file` | `file: Path` | `ApplicationInfo` |
| `pyghidra` | `ExtensionDetails` | dataclass: `name`, `description`, `author`, `createdOn`, `version`, `plugin_version` | — |
| `ExtensionDetails.from_file` | `ext_path: Path` | `ExtensionDetails` |
| `pyghidra.version` | `MINIMUM_GHIDRA_VERSION` | — | `str` (e.g. `"12.0"`) |

**Documentation (A.4).** — **ApplicationInfo**: Dataclass holding Ghidra application metadata (name, version, release name, revision, build date, Java/Gradle constraints). **`from_file`**: Builds ApplicationInfo from a Ghidra installation file (e.g. `support/launch.properties`). — **ExtensionDetails**: Dataclass for a Ghidra extension (name, description, author, version, etc.). **`from_file`**: Builds from an extension manifest. — **MINIMUM_GHIDRA_VERSION**: Minimum supported Ghidra version string; use for compatibility checks.

## A.5 ProgramLoader (pyghidra)

**Import:** `pyghidra.program_loader()` returns `ProgramLoader.Builder`.

**ProgramLoader.Builder** (builder pattern for loading programs):

| Method | Arguments | Returns |
|--------|------------|--------|
| `load` | `binary_path: Union[str, Path]`, `project: Project`, `analyze: bool = True`, `language: Optional[str] = None`, `compiler: Optional[str] = None`, `loader: Optional[str] = None`, `program_name: Optional[str] = None` | `Program` or `None` (if load fails) |

**Documentation (A.5).** — **ProgramLoader.Builder**: Builder for loading a binary into an existing project. **`load`**: Loads the file at `binary_path` into `project`, optionally running analysis (`analyze=True`). You can pass `language`, `compiler`, `loader`, and `program_name` to override defaults. Returns the loaded `Program` or None if loading fails. Use when you want a single-step load without manually creating a domain file; for project paths that already contain an imported program, use **`consume_program`** or **`program_context`** instead.

Usage: `loader = pyghidra.program_loader(); program = loader.load(binary_path, project, analyze=True)`. Alternative to `consume_program()` for program loading.

## A.6 Other modules (no extra public API)

- **`pyghidra.converters`**: JPype conversions `Path` → `java.lang.String`, `Path` → `java.io.File` (no user-facing names in `__all__`).
- **`pyghidra.__main__`**: CLI entry point; `main()`, `PyGhidraArgs`, `PathAction`, parser (invoked as `python -m pyghidra`).
- **`pyghidra.internal`**: internal implementation (e.g. `plugin`, `__init__.py`); not part of public API.

**Documentation (A.6).** These modules are not part of the documented user API: **converters** provide JPype type conversions for Path; **__main__** is the CLI entry point for `python -m pyghidra`; **internal** holds plugin and bootstrap code. Do not rely on their public names for stable scripts.

---

# Part B: Ghidra Java API (exposed via PyGhidra)

The Ghidra Java API is accessed from Python via JPype after PyGhidra has started. Objects (Program, Function, Address, Listing, etc.) are Java objects; call their methods from Python with the same signatures. Grouping below is **by primary object** (the object you call methods on), then **getters** → **setters** → other. Each section includes tables of method signatures plus **Documentation** paragraphs that explain what each method does and how to use it, including iteration patterns (e.g. **hasNext()**/ **next()** for Java iterators) and when to use transactions, **release()**, or null checks.

---

## B.1 Program (ghidra.program.model.listing)

**Import:** `ghidra.program.model.listing.Program`  
**Primary object:** the `Program` instance (no “first argument” for interface methods; they are called on the program).

### 2.1 Getters (Program)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddressFactory` | — | `AddressFactory` |
| `getAddressMap` | — | `AddressMap` (deprecated) |
| `getAddressSetPropertyMap` | `name: String` | `AddressSetPropertyMap` |
| `getBookmarkManager` | — | `BookmarkManager` |
| `getChanges` | — | `ProgramChangeSet` |
| `getCompiler` | — | `String` |
| `getCompilerSpec` | — | `CompilerSpec` |
| `getCreationDate` | — | `Date` |
| `getDataTypeManager` | — | `ProgramBasedDataTypeManager` |
| `getDefaultPointerSize` | — | `int` |
| `getDomainFile` | — | `DomainFile` (can be null in some contexts; use for pathname, checkout, checkin) |
| `getEquateTable` | — | `EquateTable` |
| `getExecutableFormat` | — | `String` |
| `getExecutableMD5` | — | `String` |
| `getExecutablePath` | — | `String` |
| `getExecutableSHA256` | — | `String` |
| `getExternalManager` | — | `ExternalManager` |
| `getFunctionManager` | — | `FunctionManager` |
| `getGlobalNamespace` | — | `Namespace` |
| `getImageBase` | — | `Address` |
| `getIntRangeMap` | `name: String` | `IntRangeMap` |
| `getLanguage` | — | `Language` |
| `getLanguageID` | — | `LanguageID` |
| `getListing` | — | `Listing` |
| `getMaxAddress` | — | `Address` |
| `getMemory` | — | `Memory` |
| `getMinAddress` | — | `Address` |
| `getPreferredRootNamespaceCategoryPath` | — | `CategoryPath` |
| `getProgramContext` | — | `ProgramContext` |
| `getProgramUserData` | — | `ProgramUserData` |
| `getReferenceManager` | — | `ReferenceManager` |
| `getRegister` | `addr: Address` | `Register` |
| `getRegister` | `addr: Address, size: int` | `Register` |
| `getRegister` | `varnode: Varnode` | `Register` |
| `getRegister` | `name: String` | `Register` |
| `getRegisters` | `addr: Address` | `Register[]` |
| `getRelocationTable` | — | `RelocationTable` |
| `getSourceFileManager` | — | `SourceFileManager` (default) |
| `getSymbolTable` | — | `SymbolTable` |
| `getUniqueProgramID` | — | `long` |
| `getUsrPropertyManager` | — | `PropertyMapManager` |

**Documentation (Program getters).** **Program** is the central Ghidra object representing a single binary (executable or library). — **`getAddressFactory`**: Returns the factory for creating and parsing addresses in this program’s language; use for `getAddress(offset)` or `getAddress(addrStr)`. — **`getBookmarkManager`**: Access to bookmarks (type, category, comment per address); see B.1.2. — **`getCompiler`** / **`getCompilerSpec`**: **getCompiler()** returns the compiler ID string (e.g. **"gcc"**). **getCompilerSpec()** returns the **CompilerSpec** (ghidra.program.model.lang), which defines calling conventions, stack behavior, and register usage; use **getCallingConventionNames()**, **getDefaultCallingConvention()**, or **getPrototypeEvaluationModel()** when setting or comparing function prototypes. — **`getDataTypeManager`**: Program’s **ProgramBasedDataTypeManager**; see **Documentation (DataTypeManager)** below. — **`getDomainFile`**: The project’s DomainFile for this program; use for pathname, versioned checkout/checkin, and save. Can be null for in-memory programs. — **`getFunctionManager`**: Access to functions by address; see B.5. — **`getLanguage`** / **`getLanguageID`**: Processor language and ID. — **`getListing`**: Disassembly/listing (instructions, data, comments); see B.4. — **`getMemory`**: Memory map (blocks, bytes); see B.1.1. — **`getMinAddress`** / **`getMaxAddress`**: Bounds of the program’s loaded address space. — **`getReferenceManager`**: References from/to addresses; see B.9. — **`getSymbolTable`**: Symbols (labels, functions, namespaces); see B.8. — **`getRegister(addr)`** / **`getRegister(addr, size)`** / **`getRegister(varnode)`** / **`getRegister(name)`**: Returns a **Register** (ghidra.program.model.lang) for the program’s language — the processor register at that address, of that size, for that varnode, or with that name. Use **`getRegisters(addr)`** for all registers at an address. **Register** has **`getName()`**, **`getAddress()`**, **`getBitLength()`**, **`getMinimumByteSize()`**; use it to interpret operands or build pcode. — **`getGlobalNamespace`**: Root namespace for symbols. — **`getImageBase`**: Base address for relocation. — **`getExecutablePath`** / **`getExecutableMD5`** / **`getExecutableSHA256`** / **`getExecutableFormat`**: Metadata about the source binary. — **`getAddressSetPropertyMap`** / **`getIntRangeMap`**: Named property and range maps. — **`getChanges`**: Change set for undo/versioning. — **`getCreationDate()`**: Returns the program’s creation **Date** (java.util.Date). — **`getDefaultPointerSize()`**: Pointer size in bytes for the program’s language (e.g. 4 or 8). — **`getPreferredRootNamespaceCategoryPath()`**: **CategoryPath** for where root namespace symbols are categorized in the symbol tree. — **`getEquateTable()`**: **EquateTable** — maps scalar values to named equates (e.g. 0x1 → "TRUE"); use to add or resolve equates. — **`getExternalManager()`**: **ExternalManager** — external library/location definitions. — **`getProgramContext()`** / **`getProgramUserData()`**: Register and context state; user key-value storage. — **`getRelocationTable()`**: **RelocationTable** for relocations. — **`getSourceFileManager()`**: Source file references. — **`getUniqueProgramID()`**: Unique long ID for the program. — **`getUsrPropertyManager()`**: **PropertyMapManager** for address-based user properties. See Ghidra Javadoc for detailed APIs.

**Documentation (AddressMap).** **AddressMap** (ghidra.program.model.address) is returned by **`program.getAddressMap()`** and is **deprecated**. It provided a legacy mapping between address spaces or internal address representations. Prefer **AddressFactory**, **AddressSpace**, and **program.getAddressFactory().getAddress(addrStr)** or **parseAddress(addrStr)** for creating and resolving addresses in current code.

**Documentation (DataTypeManager).** **DataTypeManager** (ghidra.program.model.data; **ProgramBasedDataTypeManager** for a program) holds and resolves data types. Obtain from **`program.getDataTypeManager()`** or **`listing.getDataTypeManager()`**. — **`getDataType(categoryPath, name)`**: Resolve a type by category path and name. — **`getRootCategory()`**: Root **Category** of the type tree; walk with **getCategories()`** / **getCategory(name)** to find types. — **`resolve(dataType, null)`** / **resolve** overloads: Resolve a type into this manager’s context. Use with **DataTypeParser** to parse type strings, then pass the resulting **DataType** to **createData(addr, dataType)**, **setReturnType(dt, source)**, or **ApplyFunctionDataTypesCmd**. See Ghidra Javadoc for **addDataType**, **getDataTypes()**, and category APIs.

**Documentation (Category).** **Category** (ghidra.program.model.data) is a node in the data type category tree. Obtain from **`dataTypeManager.getRootCategory()`** or **`parentCategory.getCategory(name)`**. — **`getCategories()`**: Child categories (iterate to walk the tree). — **`getCategory(name)`**: Child category by name. — **`getDataTypes()`**: **DataType**s in this category. — **`getCategoryPath()`**: **CategoryPath** for this node. Use to enumerate or resolve types by path (e.g. **"/MyCategory/Structs"**); **DataTypeManager.getDataType(categoryPath, name)** takes a **CategoryPath** and type name.

**Documentation (DataType).** **DataType** (ghidra.program.model.data) is the base type for all data types (primitives, pointers, structures, unions, arrays, etc.). Obtain from **`DataTypeManager.getDataType(categoryPath, name)`**, **`DataTypeParser.parse(str)`**, **`function.getReturnType()`**, **`parameter.getDataType()`**, or **`data.getDataType()`**. **`getLength() → int`** returns the size in bytes (or **DataType.DEFAULT** for variable-length). Use DataType when creating data (**createData(addr, dataType)**), setting return types (**setReturnType(dt, source)**), or inspecting parameters and variables; resolve through the program’s **DataTypeManager** so types are in the correct category and namespace.

**Documentation (Options).** **Options** (ghidra.framework.config) holds program and tool options. Obtain from **`program.getOptions()`** (DomainObject). — **`getString(category, key, default)`** / **`setString(category, key, value)`**: String options. — **`getInt(category, key, default)`** / **`setInt(...)`**, **`getLong`** / **`setLong`**, **`getBoolean`** / **`setBoolean`**: Other primitives. Categories include **Program.PROGRAM_INFO**, **Program.ANALYSIS_PROPERTIES**. Use for analysis toggles, display settings, or custom metadata; **analysis_properties(program)** and **program_info(program)** in pyghidra return Options for common categories.

**Documentation (Register).** **Register** (ghidra.program.model.lang) represents a processor register. Obtain from **`program.getRegister(addr)`**, **`getRegister(name)`**, **`getRegister(addr, size)`**, **`getRegister(varnode)`**, or **`getRegisters(addr)`**. — **`getName()`**: Register name (e.g. **"EAX"**, **"RSP"**). — **`getAddress()`**: Address in register space. — **`getBitLength()`** / **`getMinimumByteSize()`**: Size. Use when interpreting operands, building pcode, or mapping storage to register names. **Varnode** (ghidra.program.model.pcode): Represents a storage location (register, stack, or unique) in pcode; **getRegister(varnode)** returns the **Register** when the varnode is register storage.

**Documentation (CompilerSpec).** **CompilerSpec** (ghidra.program.model.lang) defines calling conventions and ABI for the program’s language. Obtain from **`program.getCompilerSpec()`**. — **`getCallingConventionNames()`**: Collection of convention names (e.g. **"stdcall"**, **"cdecl"**). — **`getDefaultCallingConvention()`**: Default **PrototypeModel**. — **`getPrototypeEvaluationModel()`**: Model for parameter evaluation. Use when setting **function.setCallingConvention(name)** or comparing conventions; names must be one of **getCallingConventionNames()**.

**Documentation (EquateTable, ExternalManager, ProgramContext, ProgramUserData, RelocationTable, SourceFileManager, PropertyMapManager).** These types are returned by Program getters and provide specialized state or metadata. — **EquateTable** (ghidra.program.model.equate): Maps scalar values to named equates (e.g. **0x1** → **"TRUE"**); use **getEquate(addr, value)** or **createEquate(name, value)** to resolve or define equates at addresses. — **ExternalManager** (ghidra.program.model.symbol): Manages external program/location definitions; use to list or resolve external libraries and entry points. — **ProgramContext** (ghidra.program.model.lang): Holds register and processor context state (e.g. values after execution); use when analyzing or modifying context. — **ProgramUserData** (ghidra.program.model.listing): Key-value user data attached to the program; use for script or tool-specific state. — **RelocationTable** (ghidra.program.model.reloc): Relocation entries for the binary; use to inspect or apply relocations. — **SourceFileManager** (ghidra.app.util.importer): Source file references for the program; default implementation. — **PropertyMapManager** (from **getUsrPropertyManager()**): Creates and manages address-based property maps (e.g. **getPropertyMap(name)**); use for custom address-keyed metadata.

### 2.2 Setters (Program)

| Method | Arguments | Returns |
|--------|------------|--------|
| `setCompiler` | `compiler: String` | `void` |
| `setExecutableFormat` | `format: String` | `void` |
| `setExecutableMD5` | `md5: String` | `void` |
| `setExecutablePath` | `path: String` | `void` |
| `setExecutableSHA256` | `sha256: String` | `void` |
| `setImageBase` | `base: Address, commit: boolean` | `void` |
| `setLanguage` | `language: Language, compilerSpecID: CompilerSpecID, forceRedisassembly: boolean, monitor: TaskMonitor` | `void` |
| `setPreferredRootNamespaceCategoryPath` | `categoryPath: String` | `void` |

**Documentation (Program setters).** Use these inside a transaction. — **`setCompiler`**: Set compiler ID. — **`setExecutableFormat`** / **`setExecutableMD5`** / **`setExecutablePath`** / **`setExecutableSHA256`**: Set executable metadata. — **`setImageBase`**: Set base address for relocation; `commit` controls whether to apply. — **`setLanguage`**: Change program language/compiler spec; use with care (may require re-analysis). — **`setPreferredRootNamespaceCategoryPath`**: Set default category for root namespace symbols.

### 2.3 Other (Program)

| Method | Arguments | Returns |
|--------|------------|--------|
| `createAddressSetPropertyMap` | `name: String` | `AddressSetPropertyMap` |
| `createIntRangeMap` | `name: String` | `IntRangeMap` |
| `createOverlaySpace` | `overlaySpaceName: String, baseSpace: AddressSpace` | `ProgramOverlayAddressSpace` |
| `deleteAddressSetPropertyMap` | `name: String` | `void` |
| `deleteIntRangeMap` | `name: String` | `void` |
| `parseAddress` | `addrStr: String` | `Address[]` |
| `parseAddress` | `addrStr: String, caseSensitive: boolean` | `Address[]` |
| `removeOverlaySpace` | `overlaySpaceName: String` | `boolean` |
| `renameOverlaySpace` | `overlaySpaceName: String, newName: String` | `void` |
| `restoreImageBase` | — | `void` |

**Documentation (Program other).** — **`createAddressSetPropertyMap`** / **`createIntRangeMap`**: Create named property or integer-range maps for storing address-keyed state. — **`deleteAddressSetPropertyMap`** / **`deleteIntRangeMap`**: Remove those maps by name. — **`createOverlaySpace`**: Create an overlay address space (e.g. for loaded overlays); returns **ProgramOverlayAddressSpace**. **`removeOverlaySpace`** / **`renameOverlaySpace`** manage it. **ProgramOverlayAddressSpace** is an **AddressSpace** that overlays another space; use **getAddress(offset)** and the usual AddressSpace API. — **`parseAddress`**: Parse a string into one or more Addresses; use for user input or scripts. — **`restoreImageBase`**: Restore the image base to the default for the language.

**Documentation (AddressSetPropertyMap, IntRangeMap, ProgramChangeSet, CategoryPath, Language).** — **AddressSetPropertyMap** (from **createAddressSetPropertyMap** or **getAddressSetPropertyMap**): Stores address-set values keyed by name; use **add(addrSet)** / **remove(addrSet)** / **getAddressSet()** (or similar) to record which addresses have a given property. — **IntRangeMap**: Maps address ranges to integer values; use for range-based metadata. — **ProgramChangeSet** (from **getChanges()**): Tracks what changed in the program for undo/versioning; see Ghidra Javadoc for iteration and merge. — **CategoryPath** (ghidra.program.model.data): Path in the data type category tree (e.g. **"/Category/SubCategory"**); use with **DataTypeManager.getDataType(categoryPath, name)** or **getRootCategory()** to resolve types. — **Language** (ghidra.program.model.lang): Processor language; from **program.getLanguage()**. **LanguageID**: Language identifier; use **program.getLanguageID()** when you need a stable ID for the processor.

**Documentation (DomainObject).** **DomainObject** (ghidra.framework.model) is the base class for persistent, modifiable objects in Ghidra such as **Program** and **DomainFile**. It provides **`getName()`** / **`setName(String)`** for the display name, **`getOptions() → Options`** for program or tool options, **`save()`** to persist changes, and the transaction lifecycle: **`startTransaction(description) → int`** to begin a transaction and **`endTransaction(transactionId, commit)`** to end it (use **commit=True** to keep changes). All modifications to a Program must occur between startTransaction and endTransaction. DomainFile extends DomainObject for file-level operations (checkout, checkin, pathname). Use DomainObject when you need to reason about the common interface of programs and domain files (e.g. naming, saving, or transaction boundaries).

**Documentation (DomainObject methods on Program).** **Program** inherits from **DomainObject**, which provides lifecycle and transaction management. — **`getDomainFile() → DomainFile`**: Returns the project file handle for this program; use for pathname, checkout, checkin, and save operations. Can be null for in-memory programs. — **`getName() → String`** / **`setName(String)`**: Get or set the program's display name. — **`getOptions() → Options`**: Returns the program's **Options** object; see **Documentation (Options)**. — **`save()`**: Saves the program to disk. **Important**: End any active transaction before calling **`save()`** or **`domainFile.checkout()`**/ **`checkin()`** to avoid "Unable to lock due to active transaction" errors. — **`startTransaction(description) → int`**: Begins a transaction and returns a transaction ID. All modifications must occur within a transaction. — **`endTransaction(transactionId, commit)`**: Ends a transaction; set **`commit=True`** to save changes, **`False`** to discard. Always end transactions in a try/finally block to ensure cleanup.

**Documentation (Program.release).** When a **Program** is obtained via **`consume_program()`**, you **must** call **`program.release(consumer)`** when done. The **`consumer`** is the object returned by **`consume_program()`** (the second element of the tuple); pass **`None`** if no consumer was provided. This releases the program lock and allows other processes to access the program. Failure to release can cause resource leaks and lock contention. Use **`program_context`** context manager to automatically handle release, or ensure manual release in finally blocks.

### B.1.1 Memory and MemoryBlock (ghidra.program.model.mem)

**Import:** `ghidra.program.model.mem.Memory`, `ghidra.program.model.mem.MemoryBlock`  
**Primary object:** `program.getMemory()` returns **Memory**; **MemoryBlock** is per block.

**Memory** (from `program.getMemory()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getBlock` | `address: Address` | `MemoryBlock` or `null` (block containing address) |
| `getBlocks` | — | `Iterator<MemoryBlock>` (all blocks; Java iterator: use `hasNext()`/`next()` from Python) |
| `getMinAddress` | — | `Address` (lowest loaded address; may be null) |
| `contains` | `address: Address` | `boolean` (whether address is in a loaded block) |
| `getBytes` | `addr: Address, buf: byte[]` | `int` (bytes read; use Java byte array, then convert to Python bytes) |
| `getAddressSet` | — | `AddressSetView` (when available; all loaded addresses) |
| `getAllInitializedAddressSet` | — | `AddressSetView` (when available; initialized ranges) |
| `getLoadedAndInitializedAddressSet` | — | `AddressSetView` (when available; alternative to getAddressSet) |

**MemoryBlock** (element from `getBlocks()` or `getBlock(addr)`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getStart` | — | `Address` |
| `getEnd` | — | `Address` |
| `getSize` | — | `long` |
| `getName` | — | `String` |
| `contains` | `address: Address` | `boolean` |

**Documentation (Memory).** **Memory** represents the program’s loaded memory map. — **`getBlock(addr)`**: Returns the MemoryBlock containing the address, or null. — **`getBlocks()`**: Java iterator over all blocks; use `hasNext()`/`next()` from Python. — **`getMinAddress()`**: Lowest loaded address (may be null if empty). — **`contains(addr)`**: True if the address lies in any loaded block. — **`getBytes(addr, buf)`**: Reads bytes into a Java byte array; convert to Python bytes if needed. — **`getAddressSet`** / **`getAllInitializedAddressSet`** / **`getLoadedAndInitializedAddressSet`**: AddressSetView of loaded (and optionally initialized) ranges.

**Documentation (MemoryBlock).** Each block has **`getStart`** / **`getEnd`** / **`getSize`** (bounds and size), **`getName`** (e.g. `.text`, `.data`), and **`contains(addr)`** to test membership.

### B.1.2 BookmarkManager and Bookmark (ghidra.program.model.listing)

**Import:** `ghidra.program.model.listing.BookmarkManager` (via `program.getBookmarkManager()`); **Bookmark** is per bookmark.

**BookmarkManager** (from `program.getBookmarkManager()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getBookmarks` | `address: Address` | `Bookmark[]` (bookmarks at address) |
| `getBookmarks` | `category: String` | `Bookmark[]` (e.g. `"Analysis"`) |
| `getBookmarksIterator` | — | `BookmarkIterator` (all bookmarks) |
| `getBookmarksIterator` | `addr: Address, forward: boolean` | `BookmarkIterator` (over address range) |
| `setBookmark` | `address: Address, type: String, category: String, comment: String` | `Bookmark` |
| `removeBookmark` | `bookmark: Bookmark` | `void` |
| `removeAllBookmarks` | — | `void` |

**Bookmark** (from iterator or `getBookmarks()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | — | `Address` |
| `getTypeString` | — | `String` |
| `getCategory` | — | `String` |
| `getComment` | — | `String` |

**Documentation (BookmarkManager).** Use **`getBookmarkManager()`** on the program to obtain the manager. — **`getBookmarks(addr)`**: All bookmarks at an address. **`getBookmarks(category)`**: All bookmarks in a category (e.g. `"Analysis"`). — **`getBookmarksIterator()`** / **`getBookmarksIterator(addr, forward)`**: Iterate over all bookmarks or over an address range. — **`setBookmark(addr, type, category, comment)`**: Create or update a bookmark at an address; returns the Bookmark. — **`removeBookmark(bookmark)`** / **`removeAllBookmarks()`**: Remove one or all bookmarks.

**Documentation (Bookmark).** Each bookmark has **`getAddress`**, **`getTypeString`**, **`getCategory`**, and **`getComment`**; use these to display or filter bookmarks.

---

## B.2 Function (ghidra.program.model.listing)

**Import:** `ghidra.program.model.listing.Function`  
**Primary object:** a `Function` (entry point / body).

### 3.1 Getters (Function)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAllVariables` | — | `Variable[]` |
| `getAutoParameterCount` | — | `int` |
| `getBody` | — | `AddressSetView` (function code range) |
| `getCalledFunctions` | `monitor: TaskMonitor` | `Set<Function>` |
| `getCallFixup` | — | `String` |
| `getCallingConvention` | — | `PrototypeModel` |
| `getCallingConventionName` | — | `String` |
| `getCallingFunctions` | `monitor: TaskMonitor` | `Set<Function>` |
| `getComment` | — | `String` |
| `getCommentAsArray` | — | `String[]` |
| `getEntryPoint` | — | `Address` |
| `getExternalLocation` | — | `ExternalLocation` |
| `getFunctionThunkAddresses` | `recursive: boolean` | `Address[]` |
| `getLocalVariables` | — | `Variable[]` |
| `getLocalVariables` | `filter: VariableFilter` | `Variable[]` |
| `getName` | — | `String` |
| `getParameter` | `ordinal: int` | `Parameter` |
| `getParameterCount` | — | `int` |
| `getParameters` | — | `Parameter[]` |
| `getParameters` | `filter: VariableFilter` | `Parameter[]` |
| `getProgram` | — | `Program` |
| `getPrototypeString` | `formalSignature: boolean, includeCallingConvention: boolean` | `String` |
| `getSymbol` | — | `Symbol` (symbol for this function's entry point) |
| `getRepeatableComment` | — | `String` |
| `getRepeatableCommentAsArray` | — | `String[]` |
| `getReturn` | — | `Parameter` |
| `getReturnType` | — | `DataType` |
| `getSignature` | — | `FunctionSignature` |
| `getSignature` | `formalSignature: boolean` | `FunctionSignature` |
| `getSignatureSource` | — | `SourceType` |
| `getStackFrame` | — | `StackFrame` |
| `getStackPurgeSize` | — | `int` |
| `getTags` | — | `Set<FunctionTag>` (iterate for tag names; see **FunctionTag** below) |
| `getThunkedFunction` | `recursive: boolean` | `Function` |
| `getType` | — | `Namespace.Type` (default) |
| `getVariables` | `filter: VariableFilter` | `Variable[]` |
| (property) | `entryPoint` | In JPype may be exposed as `func.entryPoint` in addition to `getEntryPoint()`; same value. |
| `hasCustomVariableStorage` | — | `boolean` |
| `hasNoReturn` | — | `boolean` |
| `hasUnknownCallingConventionName` | — | `boolean` (default) |
| `hasVarArgs` | — | `boolean` |
| `isDeleted` | — | `boolean` |
| `isExternal` | — | `boolean` |
| `isInline` | — | `boolean` |
| `isStackPurgeSizeValid` | — | `boolean` |
| `isThunk` | — | `boolean` |

**Documentation (Function getters).** **Function** represents a single function (entry point and body). — **`getEntryPoint`**: Address of the first instruction. — **`getName`** / **`getSymbol`**: Name and symbol at the entry point. — **`getBody()`**: AddressSetView of the function’s code range; use with Listing/iterators. — **`getParameters()`** / **`getParameter(ordinal)`** / **`getParameterCount()`**: Parameters; **`getReturn()`** / **`getReturnType()`**: Return value. — **`getPrototypeString`** / **`getSignature()`**: Full prototype/signature string. — **`getCallingConventionName()`** / **`getCallingConvention()`**: Calling convention. — **`getComment()`** / **`getRepeatableComment()`**: Function-level comments (repeatable is shown at all references). — **`getCalledFunctions(monitor)`** / **`getCallingFunctions(monitor)`**: Callees and callers (require TaskMonitor). — **`getTags()`**: Set of FunctionTag; iterate for tag names. — **`getThunkedFunction(recursive)`**: For thunks, the target function. — **`getProgram()`**: Owning program. — **`getLocalVariables()`** / **`getAllVariables()`** / **`getVariables(filter)`**: Local and all variables. — **`hasNoReturn`** / **`isExternal`** / **`isThunk`** / **`isInline`**: Boolean flags. — **`getStackFrame()`**: Returns **StackFrame** (local variable layout, parameter offsets); use to inspect or modify stack layout. — **`getStackPurgeSize()`**: Bytes of stack cleaned by callee; **`isStackPurgeSizeValid()`** indicates if set. — **`getSignatureSource()`**: **SourceType** of the function signature (USER_DEFINED, ANALYSIS, etc.). — **`getCallFixup()`**: Name of call fixup for special calling handling, or empty. — **`getExternalLocation()`**: For external functions, the **ExternalLocation**; null otherwise. — **`getFunctionThunkAddresses(recursive)`**: For thunks, addresses of thunked function(s). — **`getAutoParameterCount()`**: Number of parameters inferred by analysis. — **`getCommentAsArray()`** / **`getRepeatableCommentAsArray()`**: Comment split into lines (String[]). — **`getPrototypeString(formalSignature, includeCallingConvention)`**: Full prototype string with optional convention. — **`getType()`**: **Namespace.Type** (e.g. function’s namespace type). — **`hasCustomVariableStorage()`** / **`hasUnknownCallingConventionName()`** / **`hasVarArgs()`** / **`isDeleted()`** / **`isStackPurgeSizeValid()`**: Additional boolean flags; see Javadoc when needed.

### 3.2 Setters (Function)

| Method | Arguments | Returns |
|--------|------------|--------|
| `setBody` | `newBody: AddressSetView` | `void` |
| `setCallFixup` | `name: String` | `void` |
| `setCallingConvention` | `name: String` | `void` |
| `setComment` | `comment: String` | `void` |
| `setCustomVariableStorage` | `hasCustomVariableStorage: boolean` | `void` |
| `setInline` | `isInline: boolean` | `void` |
| `setName` | `name: String, source: SourceType` | `void` |
| `setNoReturn` | `hasNoReturn: boolean` | `void` |
| `setRepeatableComment` | `comment: String` | `void` |
| `setReturnType` | `dt: DataType, source: SourceType` | `void` |
| `setSignatureSource` | `source: SourceType` | `void` |
| `setStackPurgeSize` | `purgeSize: int` | `void` |

**Documentation (Function setters).** All setters require an active transaction (use **`program.startTransaction(...)`**). — **`setName(name, source)`**: Renames the function; use **`SourceType.USER_DEFINED`** for user renames (this marks the name as user-defined rather than analysis-derived). — **`setComment(comment)`** / **`setRepeatableComment(comment)`**: Set function-level comments; repeatable comments are shown at all references to the function. — **`setReturnType(dt, source)`**: Sets the return type; **`dt`** is a **DataType**, **`source`** is **SourceType** (use **USER_DEFINED** for manual changes). — **`setCallingConvention(name)`**: Sets the calling convention by name (e.g. "stdcall", "cdecl"); use **`functionManager.getCallingConventionNames()`** to see available conventions. — **`setBody(newBody)`**: Redefines the function body to a new **AddressSetView**; use with caution as this can invalidate existing analysis. — **`setCallFixup(name)`**: Sets a call fixup name for special calling convention handling. — **`setCustomVariableStorage(hasCustom)`**: Marks whether the function uses custom variable storage (non-standard parameter locations). — **`setInline(isInline)`**: Marks the function as inline (should be inlined at call sites). — **`setNoReturn(hasNoReturn)`**: Marks the function as not returning (e.g. exit functions). — **`setSignatureSource(source)`**: Sets the source of the function signature (USER_DEFINED, ANALYSIS, etc.). — **`setStackPurgeSize(purgeSize)`**: Sets the stack purge size (bytes cleaned up by the callee); use when the calling convention doesn't specify this correctly.

### 3.3 Other (Function)

| Method | Arguments | Returns |
|--------|------------|--------|
| `addLocalVariable` | `var: Variable, source: SourceType` | `Variable` |
| `addParameter` | `var: Variable, source: SourceType` | `Parameter` (deprecated) |
| `addTag` | `name: String` | `boolean` |
| `insertParameter` | `ordinal: int, var: Variable, source: SourceType` | `Parameter` (deprecated) |
| `moveParameter` | `fromOrdinal: int, toOrdinal: int` | `Parameter` (deprecated) |
| `promoteLocalUserLabelsToGlobal` | — | `void` |
| `removeParameter` | `ordinal: int` | `void` (deprecated) |
| `removeTag` | `name: String` | `void` |
| `removeVariable` | `var: Variable` | `void` |
| `replaceParameters` | `updateType: FunctionUpdateType, force: boolean, source: SourceType, ... params` | `void` |
| `replaceParameters` | `params: List<Variable>, updateType: FunctionUpdateType, force: boolean, source: SourceType` | `void` |

**Documentation (Function other).** — **`addTag(name)`** / **`removeTag(name)`**: Add or remove a function tag by name; **`addTag`** returns true if added. — **`addLocalVariable(var, source)`**: Add a local variable; **var** is a **Variable** (name, type, storage). — **`replaceParameters(updateType, force, source, ...params)`** / **`replaceParameters(params, updateType, force, source)`**: Replace the entire parameter list; **updateType** is **FunctionUpdateType** (e.g. **CUSTOM** to keep custom storage, **DYNAMIC** to re-analyze); **force** allows replacing even when types differ; use **SourceType.USER_DEFINED** for user changes. Prefer this over deprecated **addParameter** / **insertParameter** / **moveParameter** / **removeParameter**. — **`removeVariable(var)`**: Remove a local variable. — **`promoteLocalUserLabelsToGlobal()`**: Promote user-defined local labels to global scope (e.g. after extracting a function). — **FunctionTag**: From **`getTags()`**; **`getName()`** returns the tag string. **Namespace** (e.g. from **`Symbol.getParentNamespace()`**): **`getParentNamespace()`** walks up the namespace tree. **Parameter**: **`getName()`**, **`getDataType()`**, **`getLength()`**; **FunctionSignature** is used for full prototype string.

**Documentation (FunctionUpdateType).** **FunctionUpdateType** (ghidra.program.model.listing) is an enum that controls how parameters are updated when calling **`function.replaceParameters(updateType, force, source, ...)`**. **CUSTOM** preserves existing custom variable storage (parameter locations) and only updates types/names as specified. **DYNAMIC** allows the analyzer to re-infer parameter storage and types, which can overwrite custom layout. Use **CUSTOM** when you have manually placed parameters and want to keep their storage; use **DYNAMIC** when you want analysis to recompute the prototype. Other values (e.g. **DEFAULT**) exist in the Ghidra API; see Javadoc for the full set. Always pass a valid **SourceType** (e.g. **USER_DEFINED**) for the source of the change.

**Documentation (FunctionTag).** **FunctionTag** represents a tag attached to a function (e.g. "vulnerable", "crypto", "network"). Obtain from **`function.getTags()`** which returns a **Set<FunctionTag>**; iterate to get individual tags. **`getName() → String`** returns the tag name. Use tags to categorize or mark functions for analysis workflows. Add tags with **`function.addTag(name)`** and remove with **`function.removeTag(name)`**.

**Documentation (Namespace).** **Namespace** represents a symbol namespace (e.g. a class, struct, or nested scope). Functions and symbols belong to a namespace; the root is the global namespace. Obtain from **`Symbol.getParentNamespace()`** or **`function.getType()`** (which returns **Namespace.Type**). **`getParentNamespace() → Namespace`** walks up the namespace tree (can be null at the root). Use namespaces to organize symbols hierarchically and to qualify symbol names (e.g. **`Namespace::symbolName`**).

**Documentation (Parameter).** **Parameter** represents a function parameter or return value. Obtain from **`function.getParameter(ordinal)`**, **`function.getParameters()`**, or **`function.getReturn()`**. **`getName() → String`** returns the parameter name (may be auto-generated like "param_1"). **`getDataType() → DataType`** returns the parameter's type. **`getLength() → int`** returns the size in bytes. Parameters have an ordinal (0-based for parameters; use **`getReturn()`** for the return value). Use parameters to inspect or modify function signatures.

**Documentation (FunctionSignature).** **FunctionSignature** encapsulates a function's full signature (return type, name, parameters, calling convention). Obtain from **`function.getSignature()`** or **`function.getSignature(formalSignature)`**. Convert to string via **`toString()`** for display or comparison. The signature includes parameter types, names, and the return type. Use signatures to compare functions, generate prototypes, or match functions across binaries. See Ghidra Javadoc for detailed method signatures and manipulation.

**Documentation (StackFrame).** **StackFrame** (ghidra.program.model.listing) describes a function’s stack layout: local variables and their offsets. Obtain from **`function.getStackFrame()`**. Use **`getLocalVariableCount()`**, **`getVariableAt(offset)`**, **`getParameterOffset(ordinal)`**, and related methods to inspect or modify local storage. Required when working with custom variable storage or stack-based variables.

**Documentation (Variable / VariableFilter).** **Variable** (ghidra.program.model.listing) represents a function parameter or local variable; it has **`getName()`**, **`getDataType()`**, **`getLength()`**, and storage (address/register/stack). Obtain from **`function.getParameters()`**, **`getLocalVariables()`**, or **`getAllVariables()`**. **VariableFilter** filters variables by storage or type when calling **`getLocalVariables(filter)`** or **`getVariables(filter)`**; use when you need only parameters, only stack variables, etc. See Ghidra Javadoc for filter implementations.

**Documentation (PrototypeModel).** **PrototypeModel** (ghidra.program.model.lang) represents a calling convention. Obtain from **`functionManager.getCallingConvention(name)`** or **`function.getCallingConvention()`**. Use to get convention name, stack growth direction, and evaluation order; use when setting **`setCallingConvention(name)`** or comparing conventions across functions.

**Documentation (ExternalLocation).** **ExternalLocation** (ghidra.program.model.symbol) represents the definition of an external function or data (e.g. library import). Obtain from **`function.getExternalLocation()`** when **`function.isExternal()`** is true; otherwise it is null. Use **`getLabel()`** for the external name, **`getAddress()`** for the external address (if known), **`getLibraryName()`** for the library, and **`getDataType()`** for data externals. Use when resolving or displaying external references, or when matching imports across binaries.

---

## B.3 Address / AddressFactory (ghidra.program.model.address)

**Import:** `ghidra.program.model.address.Address`, `ghidra.program.model.address.AddressFactory`  
**Primary object:** `Address` or program’s `AddressFactory`.

### 4.1 Getters (Address)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddressableWordOffset` | — | `long` |
| `getAddressSpace` | — | `AddressSpace` |
| `getNewAddress` | `byteOffset: long` | `Address` |
| `getNewAddress` | `offset: long, isAddressableWordOffset: boolean` | `Address` |
| `getNewTruncatedAddress` | `offset: long, isAddressableWordOffset: boolean` | `Address` |
| `getOffset` | — | `long` |
| `getOffsetAsBigInteger` | — | `BigInteger` |
| `getPhysicalAddress` | — | `Address` |
| `getPointerSize` | — | `int` |
| `getSize` | — | `int` |
| `getUnsignedOffset` | — | `long` |
| `hasSameAddressSpace` | `addr: Address` | `boolean` |
| `isConstantAddress` | — | `boolean` |
| `isExternalAddress` | — | `boolean` |
| `isHashAddress` | — | `boolean` |
| `isLoadedMemoryAddress` | — | `boolean` |
| `isMemoryAddress` | — | `boolean` |
| `isNonLoadedMemoryAddress` | — | `boolean` |
| `isRegisterAddress` | — | `boolean` |
| `isStackAddress` | — | `boolean` |
| `isSuccessor` | `addr: Address` | `boolean` |
| `isUniqueAddress` | — | `boolean` |
| `isVariableAddress` | — | `boolean` |

**Documentation (Address getters).** **Address** is an immutable value in a single address space. — **`getOffset()`** / **`getAddressableWordOffset()`** / **`getUnsignedOffset()`**: Numeric offset in the space (word-offset vs byte-offset depending on addressability). — **`getOffsetAsBigInteger()`**: Offset as **BigInteger** for very large or unsigned arithmetic. — **`getAddressSpace()`**: The space this address belongs to (e.g. default, overlay). — **`getSize()`** / **`getPointerSize()`**: Size in bytes (e.g. for pointer size). — **`getNewAddress(offset)`** / **`getNewTruncatedAddress(offset, isAddressableWordOffset)`**: Create a new address in the same space; truncated variant wraps or truncates to space bounds. — **`hasSameAddressSpace(addr)`**: True if the other address is in the same space. — **`isLoadedMemoryAddress()`** / **`isMemoryAddress()`** / **`isNonLoadedMemoryAddress()`**: Kind of address. — **`isExternalAddress()`** / **`isStackAddress()`** / **`isRegisterAddress()`** / **`isVariableAddress()`** / **`isConstantAddress()`** / **`isHashAddress()`** / **`isUniqueAddress()`**: Other address kinds. — **`isSuccessor(addr)`**: True if this address immediately follows the other. — **`getPhysicalAddress()`**: Physical address when applicable. Use **`equals(obj)`** for comparison; do not use Python `==` across Java/Python boundary.

### 4.2 Other (Address)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | `addrString: String` | `Address` (static on space) |
| `add` | `displacement: long` | `Address` |
| `addNoWrap` | `displacement: long` or `BigInteger` | `Address` |
| `addWrap` | `displacement: long` | `Address` |
| `addWrapSpace` | `displacement: long` | `Address` |
| `equals` | `o: Object` | `boolean` (use for address comparison; do not rely on `==` across Java/Python boundary) |
| `next` | — | `Address` |
| `previous` | — | `Address` |
| `subtract` | `displacement: long` or `addr: Address` | `Address` or `long` |
| `subtractNoWrap` | `displacement: long` | `Address` |
| `subtractWrap` | `displacement: long` | `Address` |
| `subtractWrapSpace` | `displacement: long` | `Address` |
| `toString` | — or `showAddressSpace`, `pad`, `minNumDigits`, `prefix` | `String` |
| `max` | `a: Address, b: Address` | `Address` (static) |
| `min` | `a: Address, b: Address` | `Address` (static) |

**AddressFactory** (from `program.getAddressFactory()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getDefaultAddressSpace` | — | `AddressSpace` |
| `getAddress` | `offset: long` | `Address` (in default space) |
| `getAddress` | `addrString: String` | `Address` (parsed) |
| `getAddressSpace` | `name: String` | `AddressSpace` |

**Documentation (Address other).** — **`add(displacement)`** / **`subtract(displacement)`**: New address by offset; **`addNoWrap`** / **`addWrap`** / **`subtractNoWrap`** / **`subtractWrap`** handle overflow. — **`next()`** / **`previous()`**: Adjacent address in the space. — **`toString()`**: String form (optionally with space name, padding, prefix). — **`Address.max(a,b)`** / **`Address.min(a,b)`**: Static helpers for max/min of two addresses.

**Documentation (AddressFactory).** From **`program.getAddressFactory()`**. — **`getDefaultAddressSpace()`**: Default memory space. — **`getAddress(offset)`**: Address in default space. **`getAddress(addrStr)`**: Parse string to Address. — **`getAddressSpace(name)`**: Get a space by name.

**Documentation (AddressSpace).** **AddressSpace** represents a single address space (e.g. default memory, overlay, register space). Obtain from **`program.getAddressFactory().getDefaultAddressSpace()`** or **`getAddressSpace(name)`**. **`getAddress(offset: long) → Address`** creates an address in this space. Use the default space for most code/data addresses; use named or overlay spaces when the program has multiple spaces (e.g. for different memory regions or registers).

### B.3.1 AddressSetView / AddressRange / AddressRangeIterator (ghidra.program.model.address)

**Import:** `ghidra.program.model.address.AddressSetView`, `AddressRange`, `AddressRangeIterator`  
**Primary object:** e.g. `function.getBody()` returns **AddressSetView**; iterate via `getAddressRanges()`.

**AddressSetView** (e.g. from `Function.getBody()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddressRanges` | — | `AddressRangeIterator` |
| `getMinAddress` | — | `Address` |
| `getMaxAddress` | — | `Address` |
| `getNumAddresses` | — | `long` |
| `contains` | `addr: Address` | `boolean` |

**AddressRange** (from `AddressRangeIterator.next()`):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getMinAddress` | — | `Address` |
| `getMaxAddress` | — | `Address` |

**AddressRangeIterator**: Java iterator; use `next()` for next range (or iterate in Python with `hasNext()`/`next()` pattern). From `addressSetView.getAddressRanges()`.

**Documentation (AddressSetView).** Represents a read-only set of address ranges (e.g. function body). — **`getAddressRanges()`**: Returns AddressRangeIterator; use `hasNext()`/`next()` from Python. — **`getMinAddress()`** / **`getMaxAddress()`**: Bounds of the set. — **`getNumAddresses()`**: Total number of addresses. — **`contains(addr)`**: Membership test.

**Documentation (AddressRange).** Single contiguous range from **`AddressRangeIterator.next()`**. **`getMinAddress()`** / **`getMaxAddress()`** give the bounds.

**AddressRangeIterator**: Java iterator; use **`hasNext()`**/ **`next()`** to walk ranges.

**Documentation (AddressSet).** Mutable implementation of AddressSetView. Constructor **`AddressSet()`**; **`add(AddressRange)`** or **`add(AddressSetView)`** to add ranges; **`getAddressRanges()`**, **`getMinAddress()`**, **`getMaxAddress()`**, **`getNumAddresses()`**, **`contains(addr)`** as in AddressSetView. Use when building or modifying address sets (e.g. collecting ranges from multiple functions).

---

## B.4 Listing (ghidra.program.model.listing)

**Import:** `ghidra.program.model.listing.Listing`, `ghidra.program.model.listing.CodeUnit`, `ghidra.program.model.listing.CommentType`  
**Primary object:** `Program` (obtained via `program.getListing()`). Methods operate on addresses/code units.

**CommentType** (and int codes for `getComment(int, Address)`): Use with `Listing.getComment(type, address)` or `Listing.setComment(address, type, comment)`. Both overloads are supported; if `getComment(int, Address)` is not available (e.g. backend), use `CommentType` enum. Order: EOL=0, PRE=1, POST=2, PLATE=3, REPEATABLE=4.

| Constant (CodeUnit / CommentType) | Int code | Description |
|----------------------------------|----------|-------------|
| `EOL_COMMENT` / `CommentType.EOL` | 0 | End-of-line |
| `PRE_COMMENT` / `CommentType.PRE` | 1 | Pre-instruction |
| `POST_COMMENT` / `CommentType.POST` | 2 | Post-instruction |
| `PLATE_COMMENT` / `CommentType.PLATE` | 3 | Plate (block header) |
| `REPEATABLE_COMMENT` / `CommentType.REPEATABLE` | 4 | Repeatable |

**Listing comment API** — support both overloads for compatibility:
- `getComment(commentType: CommentType, address: Address)` → `String`
- `getComment(typeCode: int, address: Address)` → `String` (typeCode 0–4 as above)

**Documentation (CommentType).** Comment types: **EOL** (0) end-of-line; **PRE** (1) pre-instruction; **POST** (2) post-instruction; **PLATE** (3) plate/block header; **REPEATABLE** (4) repeatable (shown at all refs). Use with **`Listing.getComment(type, address)`** and **`Listing.setComment(address, type, comment)`**; pass `null`/None to clear. If the backend does not support **`getComment(int, Address)`**, use **CommentType** enum.

**CodeUnit** (ghidra.program.model.listing; base for Data, Instruction): From `getCodeUnitAt(addr)`, `getCodeUnitContaining(addr)`, or iterators.

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | — | `Address` |
| `getComment` | `typeCode: int` (0–4, same as CommentType) | `String` |

**Data** (subclass of CodeUnit): From `getDataAt(addr)`, `getDataContaining(addr)`, data iterators.

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | — | `Address` |
| `getLength` | — | `int` |
| `getDataType` | — | `DataType` |
| `getValue` | — | `Object` (scalar) or use getComponent for composites |

**Documentation (CodeUnit).** Base for an instruction or data at an address. **`getAddress()`**: Address of the unit. **`getComment(typeCode)`**: Comment for type 0–4 (same as CommentType).

**Documentation (Data).** **Data** (ghidra.program.model.listing) is a CodeUnit for defined data (e.g. struct, array, string). Obtain from **`listing.getDataAt(addr)`**, **`getDataContaining(addr)`**, or **Listing.getData(...)** (DataIterator). — **`getAddress()`** / **`getLength()`**: Location and byte length. — **`getDataType()`**: **DataType** of this data (e.g. **Structure**, **Pointer**, **Array**). — **`getValue()`**: For simple scalar data, the value object; for composites use **getComponent()** / **getNumComponents()**. Use Data when inspecting or modifying data layout; combine with **DataTypeManager** to resolve or create types for **createData**.

**Documentation (Instruction).** **Instruction** (ghidra.program.model.listing) is a CodeUnit representing one disassembled instruction. Obtain from **`listing.getInstructionAt(addr)`**, **`getInstructionContaining(addr)`**, or **Listing.getInstructions(...)** (InstructionIterator; use **hasNext()**/ **next()**). — **`getAddress()`** / **`getLength()`**: Address and byte length. — **`getMnemonicString()`**: Mnemonic (e.g. **"MOV"**, **"CALL"**). — **`getNumOperands()`**: Number of operands. — **`getDefaultOperandRepresentation(index)`**: String representation of the operand. — **`getOperandType(index)`**: Operand type (e.g. register, immediate, address). — **`getFlowType()`**: **FlowType** (fall-through, jump, call, etc.). Use Instruction when walking code, resolving call targets, or building control-flow; combine with **ReferenceManager** for references from the instruction.

**Documentation (FlowType).** **FlowType** (ghidra.program.model.pcode) describes the control flow of a single instruction. Obtain from **`instruction.getFlowType()`**. Use **`isCall()`** to detect function calls, **`isJump()`** for unconditional or conditional jumps, **`isTerminal()`** for instructions that do not fall through (e.g. return or trap), and **`isFallThrough()`** for normal sequential flow. Use FlowType when building control-flow graphs, enumerating call sites, or classifying branches; combine with **ReferenceManager.getReferencesFrom(addr)** to get the target address of calls or jumps.

**Instruction** (method summary): In addition to **CodeUnit** methods, **Instruction** provides **`getAddress()`** and **`getLength()`** (location and size), **`getMnemonicString()`**, **`getNumOperands()`**, **`getDefaultOperandRepresentation(index)`**, **`getOperandType(index)`**, and **`getFlowType()`**; see **Documentation (Instruction)** and **Documentation (FlowType)** for usage.

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | — | `Address` |
| `getLength` | — | `int` |

### 5.1 Getters (Listing)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAllComments` | `address: Address` | `CodeUnitComments` |
| `getCodeUnitAfter` | `addr: Address` | `CodeUnit` |
| `getCodeUnitAt` | `addr: Address` | `CodeUnit` |
| `getCodeUnitBefore` | `addr: Address` | `CodeUnit` |
| `getCodeUnitContaining` | `addr: Address` | `CodeUnit` |
| `getCodeUnitIterator` | `property: String, forward: boolean` | `CodeUnitIterator` |
| `getCodeUnitIterator` | `property: String, addr: Address, forward: boolean` | `CodeUnitIterator` |
| `getCodeUnitIterator` | `property: String, addrSet: AddressSetView, forward: boolean` | `CodeUnitIterator` |
| `getCodeUnits` | `forward: boolean` | `CodeUnitIterator` |
| `getCodeUnits` | `addr: Address, forward: boolean` | `CodeUnitIterator` |
| `getCodeUnits` | `addrSet: AddressSetView, forward: boolean` | `CodeUnitIterator` |
| `getCodeUnits` | `memory: Memory, forward: boolean` | `CodeUnitIterator` (over program memory) |
| `getComment` | `type: CommentType, address: Address` | `String` |
| `getCommentAddressCount` | — | `long` |
| `getCommentAddressIterator` | `addrSet: AddressSetView, forward: boolean` | `AddressIterator` |
| `getCommentAddressIterator` | `type: CommentType, addrSet: AddressSetView, forward: boolean` | `AddressIterator` |
| `getCommentCodeUnitIterator` | `type: CommentType, addrSet: AddressSetView` | `CodeUnitIterator` |
| `getCommentHistory` | `addr: Address, type: CommentType` | `CommentHistory[]` |
| `getData` | `forward: boolean` | `DataIterator` |
| `getData` | `addr: Address, forward: boolean` | `DataIterator` |
| `getData` | `addrSet: AddressSetView, forward: boolean` | `DataIterator` (Java iterator: `hasNext()`/`next()`) |
| `getDataAfter` | `addr: Address` | `Data` |
| `getDataAt` | `addr: Address` | `Data` |
| `getDataBefore` | `addr: Address` | `Data` |
| `getDataContaining` | `addr: Address` | `Data` |
| `getDataTypeManager` | — | `DataTypeManager` |
| `getDefaultRootModule` | — | `ProgramModule` |
| `getDefinedCodeUnitAfter` | `addr: Address` | `CodeUnit` |
| `getDefinedCodeUnitAt` | `addr: Address` | `CodeUnit` |
| `getDefinedCodeUnitBefore` | `addr: Address` | `CodeUnit` |
| `getDefinedDataAfter` | `addr: Address` | `Data` |
| `getDefinedDataAt` | `addr: Address` | `Data` |
| `getDefinedDataBefore` | `addr: Address` | `Data` |
| `getInstructionAt` | `addr: Address` | `Instruction` |
| `getInstructionContaining` | `addr: Address` | `Instruction` |
| `getInstructionAfter` | `addr: Address` | `Instruction` |
| `getInstructionBefore` | `addr: Address` | `Instruction` |
| `getInstructions` | `forward: boolean` | `InstructionIterator` (whole program) |
| `getInstructions` | `body: AddressSetView, forward: boolean` | `InstructionIterator` |

**Documentation (Listing getters).** **Listing** is obtained via **`program.getListing()`** and provides access to instructions, data, and comments. — **`getCodeUnitAt(addr)`** / **`getCodeUnitContaining(addr)`** / **`getCodeUnitAfter`** / **`getCodeUnitBefore`**: Code unit at or around an address. — **`getCodeUnitIterator(property, forward)`** / **`getCodeUnitIterator(property, addr, forward)`** / **`getCodeUnitIterator(property, addrSet, forward)`**: Iterate code units by a given property (e.g. "Instruction"); use **hasNext()**/ **next()**. — **`getInstructionAt(addr)`** / **`getInstructionContaining(addr)`** / **`getInstructionAfter`** / **`getInstructionBefore`**: Instruction at or around an address. — **`getDataAt(addr)`** / **`getDataContaining(addr)`** / **`getDataAfter`** / **`getDataBefore`**: Data at or around an address. — **`getDefinedDataAt`** / **`getDefinedCodeUnitAt`** (and After/Before): Only defined (non-default) units. — **`getCodeUnits(forward)`** / **`getCodeUnits(addr, forward)`** / **`getCodeUnits(addrSet, forward)`** / **`getCodeUnits(memory, forward)`**: Iterate code units; same pattern for **`getData(...)`** and **`getInstructions(...)`** (return DataIterator, InstructionIterator; use hasNext/next). — **`getComment(type, address)`**: Comment at address for given type (CommentType or int 0–4). — **`getAllComments(addr)`**: All comments at an address. — **`getCommentAddressCount()`**: Total number of addresses that have at least one comment; use for statistics or progress. — **`getCommentAddressIterator(addrSet, forward)`** / **`getCommentAddressIterator(type, addrSet, forward)`**: Iterate addresses that have comments (optionally for one CommentType). — **`getCommentCodeUnitIterator(type, addrSet)`**: Iterate code units that have a comment of the given type in the address set. — **`getCommentHistory(addr, type)`**: Returns **CommentHistory[]** — past versions of the comment at that address and type. — **`getDataTypeManager()`**: Same as **program.getDataTypeManager()**; use for parsing types or resolving **DataType** by path. — **`getDefaultRootModule()`**: Returns the **ProgramModule** at the root of the program tree (see **ProgramModule** below).

**Documentation (CodeUnitComments).** **CodeUnitComments** (ghidra.program.model.listing) holds all comment types at a single address. Obtain from **`listing.getAllComments(addr)`**. Use **`getComment(CommentType.EOL)`**, **`getComment(CommentType.PRE)`**, **`getComment(CommentType.POST)`**, **`getComment(CommentType.PLATE)`**, **`getComment(CommentType.REPEATABLE)`** to read each type, or iterate over the comment entries. Use when you need every comment at an address in one call instead of multiple **getComment(type, addr)** calls.

**Documentation (ProgramModule).** **ProgramModule** (ghidra.program.model.listing) is a node in the program tree (grouping of code blocks/modules). Obtain from **`listing.getDefaultRootModule()`**. Use **`getNumChildren()`**, **`getChild(name)`**, **`getTreeName()`**, and **`getAddressSet()`** to walk the tree or get address sets for modules. Used for program organization and view; see Ghidra Javadoc for full tree API.

**Documentation (CommentHistory).** **CommentHistory** (ghidra.program.model.listing) represents one historical version of a comment at an address and type. Obtain from **`listing.getCommentHistory(addr, commentType)`**, which returns an array of **CommentHistory** entries. Use each entry’s getters (e.g. **getComment()**, **getDate()**, **getUser()** — see Ghidra Javadoc) to display or compare comment history; use when implementing comment audit trails or undo-style comment views.

### 5.2 Setters (Listing)

| Method | Arguments | Returns |
|--------|------------|--------|
| `setComment` | `address: Address, commentType: CommentType, comment: String` | `void` |
| `setComment` | `address: Address, commentType: CommentType, null` | Passing `null`/`None` for comment **clears** the comment at that address/type. |
| `clearComments` | `startAddr: Address, endAddr: Address` | `void` |

### 5.3 Other (Listing)

| Method | Arguments | Returns |
|--------|------------|--------|
| `addInstructions` | `instructionSet: InstructionSet, overwrite: boolean` | `AddressSetView` |
| `clearAll` | `clearContext: boolean, monitor: TaskMonitor` | `void` |
| `clearCodeUnits` | `startAddr: Address, endAddr: Address, clearContext: boolean` | `void` |
| `clearCodeUnits` | `startAddr, endAddr, clearContext, monitor` | `void` |
| `clearProperties` | `startAddr: Address, endAddr: Address, monitor: TaskMonitor` | `void` |
| `createData` | `addr: Address, dataType: DataType` | `Data` |
| `createData` | `addr: Address, dataType: DataType, length: int` | `Data` |
| `createFunction` | `name: String, entryPoint: Address, body: AddressSetView, source: SourceType` | `Function` |
| `createFunction` | `name: String, nameSpace: Namespace, entryPoint: Address, body: AddressSetView, source: SourceType` | `Function` |
| `createInstruction` | `addr: Address, prototype: InstructionPrototype, memBuf: MemBuffer, context: ProcessorContextView, length: int` | `Instruction` |
| `createRootModule` | `treeName: String` | `ProgramModule` |

**Documentation (Listing setters).** — **`setComment(address, commentType, comment)`**: Set comment at address for that type; pass **`null`**/None to clear. — **`clearComments(startAddr, endAddr)`**: Remove all comments in the range.

**Documentation (Listing other).** — **`createData(addr, dataType)`** / **`createData(addr, dataType, length)`**: Create **Data** at address with the given **DataType**; use program’s **DataTypeManager** to resolve types. Returns the created **Data**. — **`createFunction(name, entryPoint, body, source)`**: Create a function; **body** is an **AddressSetView** (or use overload with **nameSpace**). Use **SourceType.USER_DEFINED** for user-created functions. — **`createInstruction(addr, prototype, memBuf, context, length)`**: Low-level creation of one **Instruction**; requires **InstructionPrototype**, **MemBuffer**, and **ProcessorContextView** from the language. Prefer analysis or **addInstructions** when possible. — **`addInstructions(instructionSet, overwrite)`**: Add an **InstructionSet** (batch of decoded instructions); **overwrite** controls replacing existing code. Returns **AddressSetView** of added addresses. — **`clearAll(clearContext, monitor)`**: Clear entire listing (and optionally context); use with care. — **`clearCodeUnits(startAddr, endAddr, clearContext)`** / **`clearCodeUnits(..., monitor)`**: Clear code units in the range; **clearContext** clears register/context state. — **`clearProperties(startAddr, endAddr, monitor)`**: Clear user-defined properties in the range. — **`createRootModule(treeName)`**: Create a new root **ProgramModule** (program tree node) with the given name.

**Documentation (InstructionSet).** **InstructionSet** (ghidra.program.model.listing) holds a batch of decoded instructions that can be added to the listing in one operation. You build it using the program’s **Language** and instruction decoder (e.g. **InstructionPrototype**, **MemBuffer**, **ProcessorContextView**); then pass the **InstructionSet** to **`listing.addInstructions(instructionSet, overwrite)`**. The **overwrite** flag controls whether existing code units at the same addresses are replaced. Use InstructionSet when you need to add or replace multiple instructions (e.g. after decoding from raw bytes or from another tool); for single-instruction creation see **createInstruction**, though **addInstructions** is preferred for bulk updates. See Ghidra **InstructionSet** and language/decoder APIs for how to construct the set.

---

## B.5 FunctionManager (ghidra.program.model.listing)

**Import:** `ghidra.program.model.listing.FunctionManager`  
**Primary object:** `Program` (via `program.getFunctionManager()`). Methods keyed by address/entry point.

### 6.1 Getters (FunctionManager)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getCallingConvention` | `name: String` | `PrototypeModel` |
| `getCallingConventionNames` | — | `Collection<String>` |
| `getDefaultCallingConvention` | — | `PrototypeModel` |
| `getExternalFunctions` | — | `FunctionIterator` |
| `getFunction` | `key: long` | `Function` |
| `getFunctionAt` | `entryPoint: Address` | `Function` |
| `getFunctionContaining` | `addr: Address` | `Function` |
| `getFunctionCount` | — | `int` |
| `getFunctions` | `forward: boolean` | `FunctionIterator` |
| `getFunctions` | `start: Address, forward: boolean` | `FunctionIterator` |
| `getFunctions` | `asv: AddressSetView, forward: boolean` | `FunctionIterator` |
| `getFunctionsNoStubs` | `forward: boolean` | `FunctionIterator` |
| `getFunctionsNoStubs` | `start: Address, forward: boolean` | `FunctionIterator` |
| `getFunctionsNoStubs` | `asv: AddressSetView, forward: boolean` | `FunctionIterator` |
| `getFunctionsOverlapping` | `set: AddressSetView` | `Iterator<Function>` |
| `getFunctionTagManager` | — | `FunctionTagManager` |
| `getProgram` | — | `Program` |
| `getReferencedFunction` | `address: Address` | `Function` |
| `getReferencedVariable` | `instrAddr: Address, storageAddr: Address, size: int, isRead: boolean` | `Variable` |
| `isInFunction` | `addr: Address` | `boolean` (true if addr is inside some function body) |
**Documentation (FunctionManager getters).** Obtain via **`program.getFunctionManager()`**. — **`getFunctionAt(entryPoint)`**: Function whose *entry* is this address; returns null if none. — **`getFunctionContaining(addr)`**: Function whose *body* contains this address; use when addr may be inside a function. Pattern: **`getFunctionContaining(addr) or getFunctionAt(addr)`** when addr might be the entry. — **`getFunction(key)`**: By internal key (long). — **`getFunctions(forward)`** / **`getFunctions(start, forward)`** / **`getFunctions(asv, forward)`**: Iterate functions (FunctionIterator; hasNext/next). — **`getFunctionsNoStubs(...)`**: Same but exclude stubs. — **`getFunctionsOverlapping(set)`**: Functions overlapping an AddressSetView. — **`getFunctionCount()`**: Total count. — **`getCallingConvention(name)`** / **`getDefaultCallingConvention()`** / **`getCallingConventionNames()`**: Calling conventions. — **`getExternalFunctions()`**: FunctionIterator of externals. — **`getReferencedFunction(address)`**: Function referenced from this address (e.g. call target). — **`getReferencedVariable(...)`**: Variable referenced at an instruction. — **`getFunctionTagManager()`**: Returns **FunctionTagManager** for creating and resolving function tags project-wide; use **getAllFunctionTags()**, **getFunctionTag(name)**, **createFunctionTag(name)** and related methods to manage the tag set. — **`getProgram()`**: Owning program. — **`isInFunction(addr)`**: True if addr is inside some function body.

### 6.2 Other (FunctionManager)

| Method | Arguments | Returns |
|--------|------------|--------|
| `createFunction` | `name: String, entryPoint: Address, body: AddressSetView, source: SourceType` | `Function` (body may be `null` to create stub or when body is inferred) |
| `createFunction` | `name: String, nameSpace: Namespace, entryPoint: Address, body: AddressSetView, source: SourceType` | `Function` |
| `createThunkFunction` | `name: String, nameSpace: Namespace, entryPoint: Address, body: AddressSetView, thunkedFunction: Function, source: SourceType` | `Function` |
| `invalidateCache` | `all: boolean` | `void` |
| `moveAddressRange` | `fromAddr: Address, toAddr: Address, length: long, monitor: TaskMonitor` | `void` |
| `removeFunction` | `entryPoint: Address` | `boolean` |

**Documentation (FunctionManager other).** — **`createFunction(name, entryPoint, body, source)`**: Create a function; body may be null for a stub. Overload with **Namespace** for non-global scope. — **`createThunkFunction(name, namespace, entryPoint, body, thunkedFunction, source)`**: Create a thunk. — **`removeFunction(entryPoint)`**: Remove the function at that entry; returns true if removed. — **`invalidateCache(all)`**: Invalidate internal caches. — **`moveAddressRange(from, to, length, monitor)`**: Move an address range (e.g. after base change).

**Documentation (FunctionTagManager).** **FunctionTagManager** (ghidra.program.model.listing) manages function tags for the program. Obtain from **`functionManager.getFunctionTagManager()`**. Use **`getAllFunctionTags()`** to iterate all tags, **`getFunctionTag(name)`** to get a tag by name, **`createFunctionTag(name)`** to create a new tag, and **`deleteFunctionTag(name)`** to remove one. Tags created here can be attached to functions via **`function.addTag(name)`**; use for project-wide categorization (e.g. "crypto", "network", "vulnerable").

---

## B.6 DecompInterface / DecompileOptions / DecompileResults (ghidra.app.decompiler)

**Import:** `ghidra.app.decompiler.DecompInterface`, `ghidra.app.decompiler.DecompileOptions`, `ghidra.app.decompiler.DecompileResults`  
**Primary object:** decompiler is driven by **Program** then **Function** (e.g. `openProgram(program)`, `decompileFunction(func, ...)`).

### 7.1 DecompInterface

| Method | Arguments | Returns |
|--------|------------|--------|
| `DecompInterface` | (constructor) | — |
| `openProgram` | `prog: Program` | `boolean` |
| `closeProgram` | — | `void` |
| `decompileFunction` | `func: Function, timeoutSecs: int, monitor: TaskMonitor` | `DecompileResults` |
| `getCompilerSpec` | — | `CompilerSpec` |
| `getDataTypeManager` | — | `PcodeDataTypeManager` |
| `getLanguage` | — | `Language` |
| `getLastMessage` | — | `String` |
| `getMajorVersion` | — | `short` |
| `getMinorVersion` | — | `short` |
| `getOptions` | — | `DecompileOptions` |
| `getProgram` | — | `Program` |
| `getSignatureSettings` | — | `int` |
| `getSimplificationStyle` | — | `String` |
| `setOptions` | `options: DecompileOptions` | `boolean` |
| `setSignatureSettings` | `value: int` | `boolean` |
| `setSimplificationStyle` | `actionstring: String` | `boolean` |
| `flushCache` | — | `int` |
| `resetDecompiler` | — | `void` |
| `stopProcess` | — | `void` |
| `dispose` | — | `void` |
| `toggleCCode` | `val: boolean` | `boolean` |
| `toggleSyntaxTree` | `val: boolean` | `boolean` |
| `toggleJumpLoads` | `val: boolean` | `boolean` |
| `toggleParamMeasures` | `val: boolean` | `boolean` |
| `debugSignatures` | `func: Function, timeoutSecs: int, monitor: TaskMonitor` | `ArrayList<DebugSignature>` |
| `generateSignatures` | `func: Function, keepcalllist: boolean, timeoutSecs: int, monitor: TaskMonitor` | `SignatureResult` |
| `structureGraph` | `ingraph: BlockGraph, timeoutSecs: int, monitor: TaskMonitor` | `BlockGraph` |
| `enableDebug` | `debugfile: File` | `void` |

**Documentation (DecompInterface).** Main entry point for decompilation. — **Constructor**: Create a **DecompInterface**. — **`openProgram(prog)`**: Attach to a program; must be called before **`decompileFunction`**. Returns true on success. — **`decompileFunction(func, timeoutSecs, monitor)`**: Decompile one function; returns **DecompileResults**. Check **`getDecompiledFunction()`** for null on timeout/failure. — **`closeProgram()`**: Detach from the current program. — **`getOptions()`** / **`setOptions(options)`**: Get or set **DecompileOptions** (e.g. timeout via **`grabFromProgram(program)`** then **`setTimeout(seconds)`**). — **`getProgram()`** / **`getLanguage()`** / **`getCompilerSpec()`** / **`getDataTypeManager()`**: Current program and language info. — **`getLastMessage()`**: Last decompiler message (e.g. error). — **`getMajorVersion()`** / **`getMinorVersion()`**: Decompiler version (short). — **`flushCache()`** / **`resetDecompiler()`** / **`stopProcess()`** / **`dispose()`**: Cache and lifecycle. — **`getSignatureSettings()`** / **`setSignatureSettings(value)`**: Get/set signature-related options (int bitmask). — **`getSimplificationStyle()`** / **`setSimplificationStyle(actionstring)`**: Get/set simplification style string. — **`toggleCCode(val)`** / **`toggleSyntaxTree(val)`** / **`toggleJumpLoads(val)`** / **`toggleParamMeasures(val)`**: Enable/disable C output, syntax-tree view, jump-load handling, or parameter-measure display; return previous state. — **`debugSignatures(func, timeoutSecs, monitor)`**: Return debug signature list for a function. — **`generateSignatures(func, keepcalllist, timeoutSecs, monitor)`**: Generate **SignatureResult** for BSim/signature matching. — **`structureGraph(ingraph, timeoutSecs, monitor)`**: Structure a **BlockGraph**. — **`enableDebug(debugfile)`**: Enable decompiler debug output to a file. **ClangTokenGroup** (from **getCCodeMarkup()**): Root of the token tree representing the decompiled C view; traverse for syntax highlighting or custom rendering.

**Documentation (Decompiler advanced types).** — **PcodeDataTypeManager** (from **DecompInterface.getDataTypeManager()**): Data type manager used by the decompiler for pcode/HighFunction type resolution; use when working with pcode or HighFunction types. — **DebugSignature** (from **debugSignatures(...)**): Element of the debug signature list for a function; see Ghidra Javadoc for fields. — **SignatureResult** (from **generateSignatures(...)**): Result of BSim/signature generation; contains signature data for matching or storage. — **BlockGraph**: Control-flow graph representation; **structureGraph(...)** returns a structured **BlockGraph**. Use these when integrating with BSim, signature matching, or custom decompiler/CFG workflows.

**Documentation (ClangTokenGroup).** **ClangTokenGroup** (ghidra.app.decompiler) is the root node of the decompiler’s C view token tree. Obtain it from **`DecompileResults.getCCodeMarkup()`**. It represents the decompiled C-like output as a hierarchy of tokens (keywords, identifiers, operators, etc.). Traverse the tree to implement syntax highlighting, custom formatting, or extraction of specific C elements (e.g. all function calls or variable uses). Child nodes are also **ClangNode** subtypes; use **getChildCount()**, **getChild(index)**, and token-type checks to walk the tree. Prefer **DecompiledFunction.getC()** when you only need the plain C string.

**Documentation (ClangNode).** **ClangNode** (ghidra.app.decompiler) is the base type for nodes in the decompiler’s C view token tree. **ClangTokenGroup** and other token nodes extend it. Use **`getChildCount()`** and **`getChild(index)`** to traverse the tree; check the concrete subtype (e.g. keyword, identifier, operator) to interpret the node. Use ClangNode when walking the C markup for custom rendering, syntax highlighting, or extracting specific elements; for plain C text use **DecompiledFunction.getC()** instead.

### 7.2 DecompileOptions

| Method | Arguments | Returns |
|--------|------------|--------|
| `DecompileOptions` | (constructor) | — |
| `grabFromProgram` | `program: Program` | `void` (copy options from program) |
| `setTimeout` | `seconds: int` | `void` |
| `getTimeout` | — | `int` |
| `setProtoEvalModel` | `model` (proto eval model) | `void` |
| (others) | brace style, max width, simplify double precision, etc. | see Ghidra DecompileOptions Javadoc |

**Documentation (DecompileOptions).** — **Constructor**: Create default options. — **`grabFromProgram(program)`**: Copy options from the program’s current decompiler settings. — **`setTimeout(seconds)`** / **`getTimeout()`**: Decompilation timeout in seconds. — **`setProtoEvalModel(model)`**: Set prototype evaluation model. — **Other options**: DecompileOptions also supports brace style (**setBraceStyle**), maximum output line width (**setMaxLineWidth**), simplify double-precision behavior, and similar display/analysis knobs; see Ghidra **DecompileOptions** Javadoc for the full list and defaults. Use: construct options, **`grabFromProgram(program)`**, then **`setTimeout(...)`** (and any other changes), then **`decompInterface.setOptions(options)`**.

### 7.3 DecompileResults

| Method | Arguments | Returns |
|--------|------------|--------|
| `decompileCompleted` | — | `boolean` |
| `getErrorMessage` | — | `String` |
| `getCCodeMarkup` | — | `ClangTokenGroup` |
| `getHighFunction` | — | `HighFunction` |
| `getDecompiledFunction` | — | `DecompiledFunction` or `null` (when timeout/failure) |

**Documentation (DecompileResults).** Returned by **`DecompInterface.decompileFunction(...)`**. — **`decompileCompleted()`**: True if decompilation finished successfully. — **`getErrorMessage()`**: Error string when failed or timeout. — **`getDecompiledFunction()`**: **DecompiledFunction** or **null** on failure/timeout; **always check for null** before calling **`getC()`** or **`getSignature()`**. — **`getHighFunction()`**: HighFunction (pcode/symbol map). — **`getCCodeMarkup()`**: Returns **ClangTokenGroup** (token tree for the C view); use for syntax highlighting or walking the AST. In JPype, **`result.decompiledFunction`** may be exposed as a property; same as **`getDecompiledFunction()`**; can be null.

### 7.4 DecompiledFunction (ghidra.app.decompiler)

**Import:** `ghidra.app.decompiler.DecompiledFunction` (from `DecompileResults.getDecompiledFunction()`).

| Method | Arguments | Returns |
|--------|------------|--------|
| `getC` | — | `String` (decompiled C-like source) |
| `getSignature` | — | `String` (or FunctionSignature; string representation used in repo) |

**Documentation (DecompiledFunction).** Obtained from **`DecompileResults.getDecompiledFunction()`** when not null. — **`getC()`**: Returns the decompiled C-like source string for the function. — **`getSignature()`**: Returns the function signature (string or FunctionSignature). When **`getDecompiledFunction()`** is null (timeout or failure), do **not** call these; use **`Function.getSignature()`** or fallback text instead.

### 7.5 HighFunction (ghidra.program.model.pcode)

**Import:** `ghidra.program.model.pcode.HighFunction` (from `DecompileResults.getHighFunction()`).

| Method | Arguments | Returns |
|--------|------------|--------|
| `getLocalSymbolMap` | — | (symbol map) |
**Documentation (HighFunction).** **HighFunction** (ghidra.program.model.pcode) is the pcode/symbol view of a decompiled function. Obtain from **`DecompileResults.getHighFunction()`**. — **`getLocalSymbolMap()`**: Returns the **LocalSymbolMap** for local variables and pcode symbols; use **`getSymbols()`** for an iterator of symbols (use **hasNext()**/ **next()** from Python). — **`getFunction()`**: The underlying **Function**. — **`getLLanguage()`** / **`getCompilerSpec()`**: Language and compiler spec. Use HighFunction when you need pcode-level or local-symbol analysis (dataflow, variable mapping, or custom decompiler-based scripts); for C source text use **DecompiledFunction.getC()** instead.

**Documentation (LocalSymbolMap).** **LocalSymbolMap** (ghidra.program.model.pcode) maps local variables and pcode symbols for a decompiled function. Obtain from **`highFunction.getLocalSymbolMap()`**. — **`getSymbols()`**: Iterator of **HighSymbol** (or similar) entries; use **hasNext()**/ **next()** from Python. Use to correlate decompiler locals with storage (registers, stack) or to enumerate symbols for dataflow; see Ghidra **LocalSymbolMap** Javadoc for **getSymbol()**, **getSymbolMap()**, and symbol-specific getters.

**Documentation (HighSymbol).** **HighSymbol** (ghidra.program.model.pcode) represents a single symbol in the decompiler’s local symbol map (e.g. a high-level variable or parameter). Obtain from **`highFunction.getLocalSymbolMap().getSymbols()`** (iterator) or via **getSymbol()** when a key is known. Use **getName()**, **getStorage()**, and type-related getters to map decompiler names to storage (register, stack offset, or unique) and to data types. Use HighSymbol when building dataflow or variable mapping between pcode and your analysis; for C source text use **DecompiledFunction.getC()** instead.

---

## B.7 FlatProgramAPI (ghidra.program.flatapi)

**Import:** `ghidra.program.flatapi.FlatProgramAPI`  
**Primary object:** built from a **Program** (and optional **TaskMonitor**). Methods delegate to program/listing/symbols/etc.

| Method | Arguments | Returns |
|--------|------------|--------|
| `FlatProgramAPI` | `program: Program` | — |
| `FlatProgramAPI` | `program: Program, monitor: TaskMonitor` | — |
| `getCurrentProgram` | — | `Program` |
| `toAddr` | `offset: long` (or int; script-style `toAddr(0x401000)`) | `Address` |
| `analyzeAll` | `program: Program` | `void` (run analysis) |
| `analyzeChanges` | `program: Program` | `void` (analyze only changed address sets) |
| `saveProgram` | `program: Program` | — |
| `getListing` | — | `Listing` (from current program) |
| `getMemory` | — | `Memory` |
| `getFunctionManager` | — | `FunctionManager` |
| `getSymbolTable` | — | `SymbolTable` |
| (other) | `clearListing`, `createLabel`, `find...`, `get...`, `remove...`, `set...`, etc. | see Ghidra FlatProgramAPI Javadoc for full list |

**Documentation (FlatProgramAPI).** Wraps a **Program** (and optional **TaskMonitor**) and exposes script-style helpers; used when opening via **`pyghidra.open_program()`** (deprecated) or when you want a single facade. — **Constructors**: **`FlatProgramAPI(program)`** or **`FlatProgramAPI(program, monitor)`**. — **`getCurrentProgram()`**: The wrapped program. — **`toAddr(offset)`**: Convert numeric offset (e.g. **`0x401000`**) to **Address** in the default space. — **`analyzeAll(program)`** / **`analyzeChanges(program)`**: Run full or incremental analysis. — **`saveProgram(program)`**: Save the program. — **`getListing()`** / **`getMemory()`** / **`getFunctionManager()`** / **`getSymbolTable()`**: Delegate to the current program. Many other methods (clearListing, createLabel, find/get/remove/set variants) exist; see Ghidra FlatProgramAPI Javadoc for the full list.

---

## B.8 Symbol / SymbolTable (ghidra.program.model.symbol)

**Import:** `ghidra.program.model.symbol.Symbol`, `ghidra.program.model.symbol.SymbolTable`, `SourceType`, `SymbolType`  
**Primary object:** **Program** (via `program.getSymbolTable()`); **Symbol** is per-symbol.

**Documentation (SourceType).** **SourceType** indicates the origin of a symbol name, label, or signature (user-defined, analysis, import, etc.). Use it when calling **`setName(name, source)`**, **`createLabel(addr, name, source)`**, **`setReturnType(dt, source)`**, or **`replaceParameters(..., source)`**. Common values: **`USER_DEFINED`** — user renames or labels; use this when the user or your tool explicitly sets a name or type. **`IMPORTED`** — from imports or external symbols. **`ANALYSIS`** — set by Ghidra analyzers (e.g. demangler, function start search). **`DEFAULT`** — default or inferred (e.g. param_1). Prefer **`USER_DEFINED`** for manual renames so Ghidra treats them as user overrides.

**Documentation (SymbolType).** **SymbolType** classifies a symbol; obtain it via **`symbol.getSymbolType()`**. Use it to filter or branch on symbol kind. Common values: **`FUNCTION`** — function entry symbol. **`LABEL`** — code or data label. **`CLASS`** — class namespace. **`NAMESPACE`** — other namespace. **`PARAMETER`**, **`LOCAL_VAR`** — parameter or local variable symbols. Compare with **`SymbolType.FUNCTION`**, **`SymbolType.LABEL`**, etc., to iterate only functions or only labels.

### 9.1 SymbolTable (program.getSymbolTable())

| Method | Arguments | Returns |
|--------|------------|--------|
| `getSymbol` | `ref: Reference` | `Symbol` |
| `getSymbol` | `addr: Address` | `Symbol` (or iterator) |
| `getSymbols` | `addr: Address` | `Symbol[]` or iterator |
| `getSymbols` | `name: String` | `Symbol[]` (by name) |
| `getSymbolIterator` | — | `SymbolIterator` |
| `getSymbolIterator` | `addr: Address, forward: boolean` | `SymbolIterator` |
| `getAllSymbols` | `includeDynamic: boolean` | `SymbolIterator` |
| `getExternalSymbols` | — | `SymbolIterator` |
| `createLabel` | `addr: Address, name: String, source: SourceType` | `Symbol` |
| `addExternalEntryPoint` | `addr: Address` | — |
| `getExternalRefIterator` | — | iterator |

**Documentation (SymbolTable).** Obtain via **`program.getSymbolTable()`**. — **`getSymbol(addr)`** / **`getSymbol(ref)`**: Symbol(s) at an address or for a reference; **getSymbol(addr)** may return a single Symbol or iterator depending on overload. — **`getSymbols(addr)`** / **`getSymbols(name)`**: All symbols at an address or with a given name (multiple if overloaded). — **`getSymbolIterator()`** / **`getSymbolIterator(addr, forward)`**: Iterate all symbols or from an address. — **`getAllSymbols(includeDynamic)`**: All symbols, optionally including dynamic. — **`getExternalSymbols()`**: External symbols only. — **`createLabel(addr, name, source)`**: Create a label at an address; use **SourceType.USER_DEFINED** for user labels. — **`addExternalEntryPoint(addr)`**: Mark address as external entry. — **`getExternalRefIterator()`**: Iterator over external references.

### 9.2 Symbol (getters and setters)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getAddress` | — | `Address` |
| `getName` | — | `String` |
| `getName` | `includeNamespace: boolean` | `String` (e.g. `true` for qualified name) |
| `setName` | `name: String, source: SourceType` | `void` |
| `getParentNamespace` | — | `Namespace` |
| `getSymbolType` | — | `SymbolType` (compare with `SymbolType.FUNCTION`, `SymbolType.LABEL`, etc., for filtering) |
| `getSource` | — | `SourceType` |
| `getReferencedSymbol` | — | `Symbol` (for thunks) |
| `getObject` | — | `Object` (e.g. Function, Namespace) |

**Documentation (Symbol).** A single symbol (function, label, namespace, etc.). — **`getAddress()`**: Address of the symbol. — **`getName()`** / **`getName(includeNamespace)`**: Name; use **true** for qualified name (e.g. **Namespace::name**). — **`setName(name, source)`**: Rename; use **SourceType.USER_DEFINED** for user renames. — **`getParentNamespace()`**: Parent namespace (can be null). — **`getSymbolType()`**: **SymbolType** (FUNCTION, LABEL, CLASS, NAMESPACE, etc.); use for filtering. — **`getSource()`**: **SourceType** (USER_DEFINED, IMPORTED, ANALYSIS, etc.). — **`getReferencedSymbol()`**: For thunks, the symbol referenced. — **`getObject()`**: Associated object (e.g. Function, Namespace).

---

## B.9 Reference / ReferenceManager (ghidra.program.model.symbol)

**Import:** `ghidra.program.model.symbol.Reference`, `ghidra.program.model.symbol.ReferenceManager`  
**Primary object:** **Program** (via `program.getReferenceManager()`); **Reference** is per-reference.

### 10.1 ReferenceManager (program.getReferenceManager())

| Method | Arguments | Returns |
|--------|------------|--------|
| `getReferencesTo` | `addr: Address` | `Reference[]` or iterator |
| `getReferencesFrom` | `addr: Address` | `Reference[]` |
| `getReferenceIteratorTo` | `addr: Address` | `ReferenceIterator` |
| `getReferenceIteratorFrom` | `addr: Address` | `ReferenceIterator` |
| `getReferenceIterator` | `fromAddr: Address` | `ReferenceIterator` (references *from* this address; same as getReferenceIteratorFrom) |
| `addMemoryReference` | `fromAddr: Address, toAddr: Address, refType: RefType, source: SourceType, operandIndex: int` | `Reference` |
| `addStackReference` | `fromAddr, stackOffset, refType, source, operandIndex` | `Reference` |
| `removeAllReferencesFrom` | `fromAddr: Address` | — |
| `getReferenceCount` | — | `int` |

**Documentation (ReferenceManager).** Obtain via **`program.getReferenceManager()`**. — **`getReferencesTo(addr)`**: All references *to* this address (e.g. who references this symbol). — **`getReferencesFrom(addr)`**: All references *from* this address (e.g. what this instruction references). — **`getReferenceIteratorTo(addr)`** / **`getReferenceIteratorFrom(addr)`** / **`getReferenceIterator(fromAddr)`**: Iterator over references (same **hasNext**/ **next** pattern). — **`addMemoryReference(fromAddr, toAddr, refType, source, operandIndex)`**: Add a memory reference; **refType** is **RefType** (e.g. **RefType.CALL** for calls, **RefType.DATA** for data refs, **RefType.READ**/ **RefType.WRITE**); **operandIndex** is the operand at fromAddr (e.g. 0, 1). — **`addStackReference(fromAddr, stackOffset, refType, source, operandIndex)`**: Add a stack reference. — **`removeAllReferencesFrom(fromAddr)`**: Remove all refs from an address. — **`getReferenceCount()`**: Total reference count. **ReferenceIterator**: Java iterator; use **`hasNext()`**/ **`next()`** from Python.

### 10.2 RefType (ghidra.program.model.symbol)

**Import:** `ghidra.program.model.symbol.RefType` (from `Reference.getReferenceType()`).

| Method | Arguments | Returns |
|--------|------------|--------|
| `isCall` | — | `boolean` (true if reference is a call) |
| `isData` | — | `boolean` |
| `isRead` | — | `boolean` |
| `isWrite` | — | `boolean` |

**Documentation (RefType).** From **`Reference.getReferenceType()`**. — **`isCall()`**: True if the reference is a call (e.g. function call). — **`isData()`** / **`isRead()`** / **`isWrite()`**: Data or read/write reference. Use **`ref.getReferenceType().isCall()`** to distinguish call refs from data/other.

### 10.3 Reference (getters)

| Method | Arguments | Returns |
|--------|------------|--------|
| `getFromAddress` | — | `Address` |
| `getToAddress` | — | `Address` |
| `getOperandIndex` | — | `int` |
| `getReferenceType` | — | `RefType` |
| `getSource` | — | `SourceType` |
| `getSymbolID` | — | `long` |
| `isEntryPointReference` | — | `boolean` |
| `isExternalReference` | — | `boolean` |
| `isMemoryReference` | — | `boolean` |
| `isMnemonicReference` | — | `boolean` |
| `isOffsetReference` | — | `boolean` |
| `isOperandReference` | — | `boolean` |
| `isPrimary` | — | `boolean` |
| `isRegisterReference` | — | `boolean` |
| `isStackReference` | — | `boolean` |

**Documentation (Reference).** A single reference from one address to another. — **`getFromAddress()`** / **`getToAddress()`**: Source and destination. — **`getReferenceType()`**: **RefType** (call, data, read, write, etc.). — **`getOperandIndex()`**: Operand index at the from-address. — **`getSource()`**: **SourceType**. — **`getSymbolID()`**: Symbol ID when applicable. — **`isEntryPointReference()`** / **`isExternalReference()`** / **`isMemoryReference()`** / **`isOperandReference()`** / **`isPrimary()`** / **`isStackReference()`** / **`isMnemonicReference()`** / **`isRegisterReference()`** / **`isOffsetReference()`**: Query reference kind.

---

## B.10 Other modules (detailed; used in repo)

### B.10.1 DomainFile, DomainFolder, ProjectLocator (ghidra.framework.model)

**Import:** `ghidra.framework.model.DomainFile`, `DomainFolder`, `ProjectLocator`

**DomainFile** (from `program.getDomainFile()` or project folder iteration):

| Method | Arguments | Returns |
|--------|------------|--------|
| `getPathname` | — | `String` (project path, e.g. `/binary.exe`) |
| (property) | `pathname` | JPype may expose `.pathname`; same as `getPathname()`. |
| `getName` | — | `String` (file name; DomainFile inherits from DomainObject) |
| `getParent` | — | `DomainFolder` (parent folder) |
| `getContentType` | — | `String` (e.g. `"Program"`) |
| `getProjectData` | — | `ProjectData` |
| `checkout` | `exclusive: boolean`, `monitor: TaskMonitor` | — (versioned files; requires no active transaction on program — end transaction before checkout/checkin to avoid "Unable to lock due to active transaction") |
| `checkin` | `handler: CheckinHandler`, `monitor: TaskMonitor` | — |
| `save` | `monitor: TaskMonitor` | — |
| `isVersioned` | — | `boolean` |
| `isCheckedOut` | — | `boolean` |
| `isCheckedOutExclusive` | — | `boolean` |
| `canCheckout` | — | `boolean` |
| `canCheckin` | — | `boolean` |
| `getLatestVersion` | — | `int` |
| `setName` | `name: String` | — |
| `release` | `consumer: Object` | — (release lock when done with domain object; pass same consumer used when obtaining the file/program) |

**Documentation (DomainFile).** Represents a file in a Ghidra project (e.g. a Program). From **`program.getDomainFile()`** or folder iteration. — **`getPathname()`**: Project path (e.g. **`/binary.exe`**). — **`getName()`** / **`getParent()`**: File name and parent **DomainFolder**. — **`getContentType()`**: e.g. **"Program"**. — **`getProjectData()`**: Project data for navigating the project. — **`checkout(exclusive, monitor)`**: Check out for edit (versioned projects); **end any active program transaction first** to avoid "Unable to lock due to active transaction". — **`checkin(handler, monitor)`**: Check in with a **CheckinHandler** (e.g. provide comment). — **`save(monitor)`**: Save to disk. — **`isVersioned()`** / **`isCheckedOut()`** / **`isCheckedOutExclusive()`** / **`canCheckout()`** / **`canCheckin()`**: Versioning state. — **`getLatestVersion()`** / **`setName(name)`** / **`release(consumer)`**: Version number, rename, and release lock.

**DomainFolder** (from `getRootFolder()`, `getFolder(path)`, or `DomainFile.getParent()`). **Import:** `ghidra.framework.model.DomainFolder` (not `ghidra.program.model.data`).

| Method | Arguments | Returns |
|--------|------------|--------|
| `getFolders` | — | `Iterable<DomainFolder>` |
| `getFiles` | — | `Iterable<DomainFile>` |
| `getFolder` | `name: String` | `DomainFolder` |
| `getPathname` | — | `String` |
| `getName` | — | `String` |
| `getProjectData` | — | `ProjectData` (when available on this build; otherwise obtain via project) |

**Documentation (DomainFolder).** **DomainFolder** represents a folder in a Ghidra project. Obtain from **`ProjectData.getRootFolder()`**, **`getFolder(path)`**, or **`DomainFile.getParent()`**. — **`getFolders()`**: Child folders (Iterable). — **`getFiles()`**: Child files (Iterable<DomainFile>). — **`getFolder(name)`**: Child folder by name. — **`getPathname()`** / **`getName()`**: Full path and folder name. — **`getProjectData()`**: Project data (when available); otherwise use the project reference. Use folders to walk the project tree or resolve paths like **`/folder/binary.exe`**.

**Documentation (Project).** **Project** (ghidra.framework.model) is the Java representation of an open Ghidra project. Obtain it via **`GhidraProject.getProject()`** (or from **pyghidra.open_project** which returns a **Project**). **`getProjectData() → ProjectData`** gives access to the project’s file tree and domain files. Use the Project when you need to navigate the project or obtain **ProjectData**; for opening programs use **GhidraProject** or **consume_program** with the project.

**Documentation (ProjectData).** **ProjectData** provides the project’s root folder and path-based folder lookup. Obtain via **`ghidra_project.getProject().getProjectData()`** or (on some builds) **`ghidra_project.getProjectData()`**. **`getRootFolder() → DomainFolder`** returns the project root. **`getFolder(path: String) → DomainFolder`** returns a folder by path (e.g. **`"/"`**, **`"/Subfolder"`**). Use **ProjectData** to walk the project tree, find **DomainFile** by path, or resolve **DomainFolder** for **saveAs** or import.

**Documentation (ProjectLocator).** **ProjectLocator** identifies a Ghidra project by directory and name. Constructor **`(projectDir: File, projectName: String)`**. **`getProjectDir()`** returns the project directory file; **`getMarkerFile()`** returns the project marker file used to detect a valid project. Use when you need to pass or compare project locations (e.g. for **GhidraProject.openProject** you typically build paths rather than a ProjectLocator; ProjectLocator is used internally and in some APIs).

### B.10.2 GhidraProject (ghidra.base.project)

**Import:** `ghidra.base.project.GhidraProject`

| Method | Arguments | Returns |
|--------|------------|--------|
| `openProject` | `projectDir: String`, `projectName: String`, `create: boolean` | `GhidraProject` (static; use `False` for open only) |
| `createProject` | `projectDir: String`, `projectName: String` | `GhidraProject` (static) |
| `openProgram` | `domainFile: DomainFile` | `Program` |
| `openProgram` | `domainFile: DomainFile`, `programName: String`, `readOnly: boolean` | `Program` |
| `getRootFolder` | — | `DomainFolder` |
| `getProject` | — | `Project` |
| `getProjectData` | — | `ProjectData` (some builds expose directly; otherwise `getProject().getProjectData()`) |
| `saveAs` | `program: Program`, `folderPath: String`, `name: String`, `overwrite: boolean` | — |
| `saveAsPackedFile` | `program: Program`, `file: java.io.File`, `overwrite: boolean` | — (use `java.io.File(pathString)` for file) |
| `close` | — | — |

**Documentation (Project / ProjectData).** **Project**: **`getProjectData() → ProjectData`**. **ProjectData**: **`getRootFolder() → DomainFolder`**, **`getFolder(path: String) → DomainFolder`**; obtain via **`ghidra_project.getProject().getProjectData()`** or (on some builds) **`ghidra_project.getProjectData()`**. **ProjectLocator**: **`(projectDir: File, projectName: String)`**; **`getProjectDir()`**, **`getMarkerFile()`** for project location.

**Documentation (GhidraProject).** High-level Ghidra project API. — **`openProject(projectDir, projectName, create)`** (static): Open (or create) a project; use **False** for open-only. — **`createProject(projectDir, projectName)`** (static): Create a new project. — **`openProgram(domainFile)`** / **`openProgram(domainFile, programName, readOnly)`**: Open a program from a DomainFile; for versioned (shared) projects, checkout before modify and checkin after. — **`getRootFolder()`** / **`getProject()`** / **`getProjectData()`**: Root folder, Project, ProjectData. — **`saveAs(program, folderPath, name, overwrite)`**: Save program to project path. — **`saveAsPackedFile(program, file, overwrite)`**: Save to a packed file; use **`java.io.File(pathString)`** for the file. — **`close()`**: Close the project.

### B.10.3 ghidra.program.util

**Import:** `ghidra.program.util.GhidraProgramUtilities`, `ProgramUtilities`, `DefaultLanguageService`, `DefinedDataIterator`, `DefinedStringIterator`, `ConsoleTaskMonitor`

| Symbol | Method / usage | Returns |
|--------|----------------|--------|
| `GhidraProgramUtilities` | `shouldAskToAnalyze(program)` | `boolean` |
| | `setAnalyzedFlag(program, boolean)` | — |
| | `markProgramAnalyzed(program)` | — |
| | `isAnalyzed(program)` | `boolean` |
| `ProgramUtilities` | `analyze(program, TaskMonitor)` | — |
| `DefaultLanguageService` | `getLanguageService()` | `LanguageService` |
| `ConsoleTaskMonitor` | constructor | `TaskMonitor` (console-backed) |
| `TaskMonitor.DUMMY` | (static) | `TaskMonitor` (no-op) |
| `DefinedDataIterator.definedStrings` | `program: Program` | iterator over string `Data` (use `hasNext()`/`next()`) |
| `DefinedStringIterator.forProgram` | `program: Program` | `DefinedStringIterator` (then `hasNext()`/`next()` over string Data) |

**Documentation (TaskMonitor).** **TaskMonitor** (ghidra.util.task) is used by long-running Ghidra operations (e.g. **analyze**, **decompileFunction**, **walk_programs**) for progress and cancellation. Pass a monitor when the API accepts one; the operation may call **`checkCanceled()`** and **`setProgress(value)`**. Use **`TaskMonitor.DUMMY`** when you do not need cancellation (e.g. **pyghidra.task_monitor(None)** returns DUMMY). For scripts, **ConsoleTaskMonitor** prints progress to the console. From Python, create a monitor via **pyghidra.task_monitor(timeout_seconds)** or use **TaskMonitor.DUMMY**; implement or use a monitor that supports **cancel()** if you need to interrupt analysis or decompilation.

**Documentation (B.10.3).** — **GhidraProgramUtilities**: **`shouldAskToAnalyze(program)`**, **`setAnalyzedFlag(program, boolean)`**, **`markProgramAnalyzed(program)`**, **`isAnalyzed(program)`** for analysis state. — **ProgramUtilities**: **`analyze(program, TaskMonitor)`** to run analysis. — **DefaultLanguageService**: **`getLanguageService()`** returns a **LanguageService**; see **Documentation (LanguageService)**. — **ConsoleTaskMonitor**: Constructor returns a **TaskMonitor** with console output. — **TaskMonitor.DUMMY**: No-op monitor when no cancellation is needed. — **DefinedDataIterator.definedStrings(program)** / **DefinedStringIterator.forProgram(program)**: Iterate over string **Data** in the program; use **hasNext()**/ **next()**.

**Documentation (DefinedDataIterator / DefinedStringIterator).** **DefinedDataIterator** and **DefinedStringIterator** (ghidra.program.util) iterate over **Data** code units in a program that represent defined strings (e.g. ASCII or Unicode strings discovered by analysis). **DefinedDataIterator.definedStrings(program)** returns an iterator over string **Data**; **DefinedStringIterator.forProgram(program)** returns a **DefinedStringIterator** that you iterate with **hasNext()**/ **next()** from Python. Use these when you need to enumerate or analyze all defined strings in the binary (e.g. for string-based search or export). Each element is a **Data** instance; use **getAddress()**, **getValue()**, and **getLength()** to get location and content.

**Documentation (LanguageService).** **LanguageService** (ghidra.program.model.lang) provides lookup of **Language** and **CompilerSpec** by ID or name. Obtain from **`DefaultLanguageService.getLanguageService()`**. Use **`getLanguage(LanguageID)`** or **`getLanguage(name)`** to resolve a language, and **`getCompilerSpec(LanguageID, CompilerSpecID)`** (or similar) for a compiler spec. Use when you need to resolve a language/compiler from a string or ID (e.g. when loading a program with a specific language); the program’s **getLanguage()** / **getCompilerSpec()** are usually sufficient for the open program.

### B.10.4 DataTypeParser (ghidra.util.data)

**Import:** `ghidra.util.data.DataTypeParser`

| Method | Arguments | Returns |
|--------|------------|--------|
| `DataTypeParser` | `dtm: DataTypeManager`, `dtm2: DataTypeManager`, `options: Object`, `allowedTypes: AllowedDataTypes` | — |
| `parse` | `str: String` (or program-specific overload) | `DataType` (parsed type) |
| `AllowedDataTypes.ALL` | (static) | allow all types when parsing |

**Documentation (DataTypeParser).** Parses type strings into **DataType** instances. Constructor: **DataTypeParser(dtm, dtm2, options, allowedTypes)**; use **DataTypeParser.AllowedDataTypes.ALL** to allow all types. — **`parse(str)`**: Parse a type string (e.g. **"int"**, **"char *"**, **"struct Foo"**) and return a **DataType** from the manager; use that type in **createData(addr, dataType)**, **setReturnType(dt, source)**, or **ApplyFunctionDataTypesCmd**. Typical usage: **`parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)`** then **`dt = parser.parse("int *")`**.

**Documentation (AllowedDataTypes).** **AllowedDataTypes** (ghidra.util.data) is an enum or options type used when constructing **DataTypeParser** to restrict which kinds of types can be parsed (e.g. only primitives, or only from a given category). **AllowedDataTypes.ALL** allows all types and is the typical value when you want full C-like type strings; use a more restrictive value when parsing user input or applying a type-whitelist policy.

### B.10.5 CppExporter, other exporters (ghidra.app.util.exporter)

**Import:** `ghidra.app.util.exporter.CppExporter`, `AsciiExporter`, `XmlExporter`, `HtmlExporter`, `GzfExporter`

**CppExporter** (export program to C/C++):

| Method | Arguments | Returns |
|--------|------------|--------|
| `CppExporter` | (constructor; optional options) | — |
| `export` | `outputStream: OutputStream`, `program: Program`, `memory: Memory`, `monitor: TaskMonitor` | — |

**Documentation (CppExporter).** Exports program to C/C++ source. Constructor (optional options); **`export(outputStream, program, memory, monitor)`** writes to the stream. Use **`program.getMemory()`** for the memory argument. — **AsciiExporter**: Exports listing as plain text (disassembly/listing). — **XmlExporter**: Exports program or selection as Ghidra XML. — **HtmlExporter**: Exports to HTML. — **GzfExporter**: Exports to gzipped format. Each has an **export**-style method; see Ghidra **ghidra.app.util.exporter** Javadoc for constructor and **export** signatures.

### B.10.6 DemanglerUtil (ghidra.app.util.demangler)

**Import:** `ghidra.app.util.demangler.DemanglerUtil`

| Method | Arguments | Returns |
|--------|------------|--------|
| `demangle` | `program: Program`, `name: String` | `String` (demangled name) |

**Documentation (DemanglerUtil).** **`demangle(program, name)`**: Returns the demangled string for a mangled symbol name (e.g. C++ or compiler mangling); use for display or matching.

### B.10.7 ApplyFunctionDataTypesCmd (ghidra.app.cmd.function)

**Import:** `ghidra.app.cmd.function.ApplyFunctionDataTypesCmd`

| Method | Arguments | Returns |
|--------|------------|--------|
| `ApplyFunctionDataTypesCmd` | `archiveDTM: List<DataTypeManager>`, `options`, `sourceType: SourceType`, `alwaysReplace: boolean`, `createBookmarks: boolean` | — |
| `applyTo` | `program: Program` (or equivalent) | — |

**Documentation (ApplyFunctionDataTypesCmd).** Applies data types from an archive (e.g. header type archive) to the program’s functions. Constructor: **ApplyFunctionDataTypesCmd(archiveDTM list, options, sourceType, alwaysReplace, createBookmarks)**; then **`applyTo(program)`**. Use **SourceType.USER_DEFINED** for user-applied types. From JPype build the list with **`JClass("java.util.List").of(archiveDTM)`** (Java **List.of**).

### B.10.8 CheckinHandler, OpenMode, CheckoutType (ghidra.framework.data / store)

**Import:** `ghidra.framework.data.CheckinHandler`, `OpenMode`; `ghidra.framework.store.CheckoutType`

**Documentation (B.10.8).** — **CheckinHandler**: Abstract class used when checking in a versioned domain file. Subclass **CheckinHandler** and override **`getComment() → String`** to return the comment that will be stored with the check-in (e.g. "Applied symbol renames"). Pass an instance to **`domainFile.checkin(handler, TaskMonitor.DUMMY)`** after you have ended any active program transaction. Use when automating check-in from scripts or tools so the version history has a meaningful comment. — **OpenMode**: Enum (ghidra.framework.data) that specifies how a program or domain file is opened when using **ProgramDB** or low-level open APIs. Values typically include read-only, read-write, and upgrade modes. Use when opening a program from raw bytes or a packed file (e.g. **ProgramDB.open(...)**); choose read-only when you only need to inspect, read-write when you will modify. See Ghidra **OpenMode** Javadoc for the full set. — **CheckoutType**: Enum (ghidra.framework.store) for versioned file checkout. **Exclusive** checkout means only one user can modify the file until check-in; use it when your tool will edit the program. **Non-exclusive** allows multiple checkouts; merge may be required on check-in. Pass the appropriate value when calling **domainFile.checkout(...)** or **RepositoryAdapter** checkout methods; for script-driven edits prefer exclusive so you avoid merge conflicts.

### B.10.9 ClientUtil, PasswordClientAuthenticator (ghidra.framework.client)

**Import:** `ghidra.framework.client.ClientUtil`, `PasswordClientAuthenticator`

| Symbol | Method | Returns |
|--------|--------|--------|
| `ClientUtil` | `setClientAuthenticator(authenticator)` | — |
| | `clearRepositoryAdapter()` | — |
| | `clearRepositoryAdapter(serverHost: String, serverPort: int)` | — (overload used in repo) |
| | `getRepositoryServer(host, port, allowPrompt)` | — |
| `PasswordClientAuthenticator` | constructor `(serverUser, serverPassword)` | — |

**Documentation (ClientUtil / PasswordClientAuthenticator).** For shared Ghidra repository authentication. **ClientUtil**: **`setClientAuthenticator(authenticator)`**, **`clearRepositoryAdapter()`**, **`clearRepositoryAdapter(host, port)`**, **`getRepositoryServer(host, port, allowPrompt)`**. **PasswordClientAuthenticator**: Constructor **`(serverUser, serverPassword)`**; set via **ClientUtil.setClientAuthenticator(...)**.

### B.10.10 SystemUtilities (ghidra.util)

**Import:** `ghidra.util.SystemUtilities`

| Method | Arguments | Returns |
|--------|------------|--------|
| `class_` | (reflection helper) | — |
| `getDeclaredField` | e.g. `name: String` (e.g. `"userName"`) | (reflection; used in shared server context) |

**Documentation (SystemUtilities).** **SystemUtilities** provides reflection helpers for internal Ghidra use. **`class_`**: Reflection helper for class lookup. **`getDeclaredField(name)`**: Returns a declared field by name (e.g. **"userName"**); used in shared-server context for internal state access. Use only when you need to reach non-public Java state; prefer public APIs when available.

### B.10.11 ProgramDB (ghidra.program.database)

**Import:** `ghidra.program.database.ProgramDB`

**Documentation (ProgramDB).** **ProgramDB** (ghidra.program.database) is the low-level program storage implementation. Use when opening a program from raw bytes or a packed file without going through **DomainFile** or **GhidraProject.openProgram**. Open with **OpenMode** (e.g. read-only vs read-write); the exact static method (e.g. **open** or **create**) depends on Ghidra version — see **ghidra.program.database.ProgramDB** and **ghidra.framework.data.OpenMode** Javadoc. Most scripts use **consume_program** or **GhidraProject.openProgram** instead; use ProgramDB when you need direct byte-based or file-based program creation.

### B.10.12 BSim: FunctionDatabase, GenSignatures (ghidra.features.bsim.query)

**Import:** `ghidra.features.bsim.query.FunctionDatabase`, `GenSignatures`; `ghidra.features.bsim.query.description.DescriptionManager`

| Symbol | Method | Returns |
|--------|--------|--------|
| `GenSignatures` | `openProgram(program: Program, ...)` | (opens program for signature generation) |
| | `addFunctionTags(...)` | (used with BSim / match-function) |

**Documentation (BSim / GenSignatures).** **FunctionDatabase** and **GenSignatures** support BSim semantic similarity and match-function style features. **GenSignatures**: **`openProgram(program, ...)`** for signature generation, **`addFunctionTags(...)`** for tagging. **RepositoryAdapter** (versioned shared projects): **`checkout(folderPath, itemName, checkoutType, programPath)`** (or equivalent) for program checkout; see Ghidra shared-project API. **DescriptionManager** (ghidra.features.bsim.query.description) works with **FunctionDatabase** and BSim to manage function descriptions and signatures for similarity search; use when building or querying BSim databases. See Ghidra BSim documentation for **DescriptionManager** and related types.

**Documentation (RepositoryAdapter).** **RepositoryAdapter** (ghidra.framework.store) is the interface to a versioned Ghidra repository (shared server or local versioned project). Use it to **checkout** a domain file (e.g. a Program) for editing — **`checkout(folderPath, itemName, checkoutType, programPath)`** (or overloads) — and to **checkin** after changes. It works with **CheckoutType** (exclusive vs non-exclusive). Obtain a RepositoryAdapter from the project or server connection when using shared/versioned projects; for local non-versioned projects you typically use **DomainFile** and **GhidraProject** directly.

### B.10.13 Remaining import paths (reference only)

| Import path | Symbols |
|-------------|--------|
| `ghidra.app.script` | `GhidraScriptUtil` (`acquireBundleHostReference`, `releaseBundleHostReference`) |
| `ghidra.app.plugin.core.analysis` | `PdbAnalyzer`, `PdbUniversalAnalyzer`, `AutoAnalysisManager` (`getAnalysisManager(Program) → AutoAnalysisManager` static; `reAnalyzeAll(AddressSetView)`, `scheduleOneTimeAnalysis(Analyzer, AddressSetView)`) |
| `ghidra.app.util.pdb` | `PdbProgramAttributes` |
| `ghidra.app.util.cparser` | `CParser` |
| `ghidra.framework.options` | `ToolOptions` |
| `ghidra.framework.main` | `AppInfo` (`getActiveProject() → GhidraProject`/Project; GUI/headless context) |
| `ghidra.framework.protocol.ghidra` | `GhidraURL` (`getProjectURL(folderURL) → String`; used for BSim/shared project URLs) |
| `ghidra.framework` | `Application` (`findFilesByExtensionInApplication`) |
| `ghidra.program.model.data` | `FileDataTypeManager`, `CategoryPath`, `StructureDataType`, `UnionDataType`, `Component`. **DataType**: `getLength() → int`. **Composite** (Structure/Union): `getNumComponents() → int`, `getComponent(index) → Component`, `getComponentAt(offset) → Component`, `add(dataType, length, name, comment)`. **Component**: `getLength() → int`, `setComment(String)`, `getComment() → String`. **Variable**: `getComment() → String`, `getLength() → int`. |
| `ghidra.program.model.lang` | `CompilerSpecID`, `LanguageID` |
| `ghidra.util.task` | `ConsoleTaskMonitor`, `TaskMonitor` |
| `ghidra.feature.vt` | `api as vtapi` |
| `ghidra_builtins` | `from ghidra_builtins import *` → script env: `currentProgram`, `getAddress`, `toAddr`, `getMemory`, `getListing`, `getSymbolTable`, `getFunctionManager`, `getBookmarkManager` (and other script globals; see PyGhidra script docs). |

**Documentation (B.10.13).** — **GhidraScriptUtil** (ghidra.app.script): Manages the script bundle host reference used when running Ghidra scripts. Call **`acquireBundleHostReference()`** before script execution and **`releaseBundleHostReference()`** when done so the script environment has access to the correct class loader and resources. Use when embedding or invoking Ghidra scripts programmatically (e.g. from **ghidra_script** or a custom runner). — **AutoAnalysisManager**: **`getAnalysisManager(Program)`** (static); **`reAnalyzeAll(AddressSetView)`**, **`scheduleOneTimeAnalysis(Analyzer, AddressSetView)`** for (re)running analyzers. **Analyzer** (ghidra.app.plugin.core.analysis): Interface for a single analysis pass; pass an **Analyzer** instance to **scheduleOneTimeAnalysis** to run that analyzer on an address set. — **PdbAnalyzer** / **PdbUniversalAnalyzer** / **PdbProgramAttributes**: **PdbAnalyzer** and **PdbUniversalAnalyzer** are analyzers that apply PDB (Program Database) information to the program (e.g. symbols, types). **PdbProgramAttributes** holds PDB-related program attributes. Use when analyzing Windows binaries with PDB files; schedule via **AutoAnalysisManager.scheduleOneTimeAnalysis** or run as part of full analysis. — **CParser** (ghidra.app.util.cparser): C/C++ parser for parsing header or type definitions into Ghidra data types. **ToolOptions** (ghidra.framework.options): Tool-level options storage. **AppInfo** (ghidra.framework.main): **`getActiveProject()`** returns the currently active **GhidraProject** or **Project** (GUI/headless context). **GhidraURL** (ghidra.framework.protocol.ghidra): **`getProjectURL(folderURL)`** returns a Ghidra URL string for the project/folder; used for BSim and shared-project URLs. **Application** (ghidra.framework): **`findFilesByExtensionInApplication(extension)`** searches the Ghidra application for files by extension. — **DataType**, **Component**, **Variable**, **StructureDataType**, **UnionDataType**, **FileDataTypeManager**, **CategoryPath**: See **Documentation (DataType)** and **Documentation (Composite types and FileDataTypeManager)** below. — **CompilerSpecID** / **LanguageID** (ghidra.program.model.lang): Immutable identifiers for a compiler spec and a language. Use when calling APIs that require an ID (e.g. **setLanguage(language, compilerSpecID, ...)**) or when comparing or storing language/compiler identity across sessions. — **TaskMonitor**, **ConsoleTaskMonitor**: Progress/cancellation; see **Documentation (TaskMonitor)** in B.10.3. — **ghidra.feature.vt**: Version tracking (VT) API for comparing and merging program versions. — **ghidra_builtins**: When running a PyGhidra or Ghidra script, **`from ghidra_builtins import *`** injects script globals such as **currentProgram**, **getAddress**, **toAddr**, **getMemory**, **getListing**, **getSymbolTable**, **getFunctionManager**, **getBookmarkManager**. Use these inside scripts for quick access to the current program and helpers; in non-script code obtain the program and managers explicitly (e.g. from **program_context** or **consume_program**). See PyGhidra script documentation for the full list of builtins.

**Documentation (Composite types and FileDataTypeManager).** — **StructureDataType** / **UnionDataType** (ghidra.program.model.data): Composite types with components. **`getNumComponents()`**, **`getComponent(index)`**, **`getComponentAt(offset)`**: Inspect components. **`add(dataType, length, name, comment)`**: Add a component (use inside a transaction when modifying program types). — **Component**: A single field in a structure/union; **`getLength()`**, **`getDataType()`**, **`getOffset()`**, **`setComment(String)`** / **`getComment()`**, **getFieldName()** (or **getName()**). — **FileDataTypeManager**: Opens or creates a data type archive (e.g. **.gdt** file); use **open(File, boolean)** (or equivalent) to load an archive, then pass the **DataTypeManager** to **ApplyFunctionDataTypesCmd** or **DataTypeParser**. Use to apply types from header/archive files to the program.

---

## Edge cases and behavior notes

This section summarizes important behavioral details and pitfalls so you can use the APIs correctly. Follow these when implementing tools or scripts.

- **Listing.getComment**: The **Listing** API supports two overloads for **`getComment`**: **`getComment(int, Address)`** (typeCode 0–4) and **`getComment(CommentType, Address)`**. Some backends may not support the int overload, so try int first and fall back to **CommentType** enum if the backend reports "no matching overloads". This ensures compatibility across different Ghidra versions and configurations.

- **Listing.setComment(..., null)**: When setting a comment, passing **`null`**/ **`None`** for the comment argument **clears** that comment type at that address. This is the standard way to remove comments: **`listing.setComment(address, CommentType.EOL, None)`** removes the EOL comment at that address.

- **DecompiledFunction null handling**: When **`DecompileResults.getDecompiledFunction()`** returns **`null`** (due to timeout, failure, or incomplete decompilation), **do not** call **`getC()`** or **`getSignature()`** on the null result. Instead, use **`Function.getSignature()`** for the signature or provide fallback text. Always check **`decompileCompleted()`** or test for null before accessing decompiled content.

- **DomainFile checkout/checkin transaction requirement**: Before calling **`domainFile.checkout()`**, **`domainFile.checkin()`**, or **`domainFile.save()`**, you **must** end any active program transaction. Call **`program.endTransaction(transactionId, commit)`** first, otherwise you'll get "Unable to lock due to active transaction". This is critical for versioned (shared) projects where checkout/checkin operations require exclusive locks.

- **GhidraProject.openProgram overloads**: **`GhidraProject.openProgram`** has two overloads: one with just **`domainFile`**, and another with **`domainFile, programName, readOnly`**. For versioned (shared) projects, you must **checkout** the program before modifying it, and **checkin** after changes. Use the **`readOnly`** parameter to open without checkout when you only need to read.

- **getFunctionAt vs getFunctionContaining**: These methods serve different purposes. **`getFunctionAt(addr)`** returns the function whose **entry point** is exactly `addr` (returns null if no function starts there). **`getFunctionContaining(addr)`** returns the function whose **body contains** `addr` (returns null if the address is not inside any function). Common pattern when you're not sure if `addr` is an entry or inside a function: **`getFunctionContaining(addr) or getFunctionAt(addr)`** to handle both cases.

- **Java iterators from Python**: All Ghidra iterators are Java iterators; you **cannot** use Python's **`for x in iterator`** directly. Use **`while iterator.hasNext(): item = iterator.next()`**. **Documentation (iterator types).** — **CodeUnitIterator** (from **Listing.getCodeUnits()**, **getCodeUnitIterator()**): yields **CodeUnit** (Instruction or Data). — **InstructionIterator** (from **Listing.getInstructions()**): yields **Instruction**. — **DataIterator** (from **Listing.getData()**): yields **Data**. — **SymbolIterator** (from **SymbolTable.getSymbolIterator()** etc.): yields **Symbol**. — **BookmarkIterator** (from **BookmarkManager.getBookmarksIterator()**): yields **Bookmark**. — **FunctionIterator** (from **FunctionManager.getFunctions()** etc.): yields **Function**. — **ReferenceIterator** (from **ReferenceManager.getReferenceIteratorTo/From()**): yields **Reference**. — **AddressRangeIterator** (from **AddressSetView.getAddressRanges()**): yields **AddressRange**. — **AddressIterator** (from **Listing.getCommentAddressIterator()** etc.): yields **Address**. In all cases use **hasNext()** then **next()** from Python; **getReferencesTo**/ **getReferencesFrom** and **SymbolTable.getSymbols(addr)** may return arrays or iterators—use the same pattern when you receive an iterator.

- **java.io.File construction**: When APIs require a **`java.io.File`** (e.g. **`saveAsPackedFile(program, file, overwrite)`**), construct it via JPype: **`JClass("java.io.File")(str(path))`**. This creates a Java File object from a Python string path. Do not pass Python **`Path`** objects directly; convert to string first.

- **Java collections from Python**: When APIs require **`List<T>`** or other Java collections (e.g. **`ApplyFunctionDataTypesCmd(List.of(archiveDTM), ...)`**), use Java's collection factories via JPype: **`JClass("java.util.List").of(item)`** for **`List.of(...)`**, or build the collection in Java and pass it. Python lists are not automatically converted to Java collections.

- **DataIterator iteration**: **DataIterator** from **`Listing.getData(...)`** follows the same Java iterator pattern: use **`hasNext()`**/ **`next()`** from Python. This applies to all Ghidra iterators; there is no direct Python iteration support unless you wrap the iterator yourself.

---

## Type hints (TYPE_CHECKING) — canonical pattern for `src/`

Use this **exact** pattern so static type checkers (e.g. pyright) get accurate Ghidra/PyGhidra types without requiring the JVM at analysis time:

1. **Import** `TYPE_CHECKING` from `typing`.
2. **Put all ghidra/pyghidra imports used only for annotations** inside:
   ```python
   if TYPE_CHECKING:
       from ghidra.<path> import ...  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
   ```
3. **One pyright comment per import line** (or per multi-line `from ... import (...)` block):  
   `# pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]`
4. **Import paths must match this document**: Part A for `pyghidra`; Part B and B.10 for `ghidra.*`.
5. **Runtime imports** of ghidra/pyghidra stay inside the functions that need them (when JVM is up); do not move those into `TYPE_CHECKING`.

Example (authoritative):

```python
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface,
        DecompileOptions,
        DecompileResults,
    )
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.framework.model import DomainFile, DomainFolder, ProjectLocator  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.address import Address, AddressFactory  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.listing import Function, Program  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.symbol import Symbol, SourceType, SymbolType, RefType  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.util.task import TaskMonitor, ConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
```

Use type aliases when helpful (e.g. `Program as GhidraProgram`) and keep runtime `from ghidra...` inside the functions that execute under PyGhidra.

---

## Sources

- **pyghidra Python package:** `.venv/Lib/site-packages/pyghidra/` (v3.0.2) — `__init__.py`, `api.py`, `core.py`, `launcher.py`, `script.py`, `version.py`, `__main__.py`, `converters.py`
- **Context7:** `/websites/ghidra_re_ghidra_docs_api`, `/nationalsecurityagency/ghidra`
- **Ghidra API (ghidra.re):** Program, Function, Address, Listing, FunctionManager, DecompInterface, Memory, SymbolTable, ReferenceManager, DomainFile, GhidraProject
- **Repo research:** `agentdecompile` codebase PyGhidra/ghidra import paths and call patterns (src/agentdecompile_cli, ghidrecomp, mcp_server/providers)
