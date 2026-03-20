# PyGhidra API Reference — Audit Report

Full audit of `docs/PyGhidra_API_Reference.md` against actual PyGhidra/Ghidra API usage in `src/agentdecompile_cli` (including `mcp_server/providers`, `mcp_utils`, `ghidrecomp`, `tools`).  
Focus: symbols **used in code** but missing or incompletely documented in the reference.

---

## (A) Missing APIs — symbols used but not fully documented

Each entry: **symbol** (type), **where used**, **what the reference currently says**, **what would make it complete**.

### A.1 Program / DomainObject

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| `Program.getDomainFile()` | project.py, getfunction.py, context.py, launcher.py, bsim.py, import_export.py, etc. | Mentioned in B.1 footnote only ("e.g. getDomainFile()"). | Add to Program getters: `getDomainFile() → DomainFile`; note can be null in some contexts. |

### A.2 Function

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| `Function.getSymbol()` | wrappers.py (98, 138, 143, 147, 149, 891), callgraph.py (676, 686, 709, 718, 725, etc.), context.py (606) | Not listed in B.2 Function getters. | Add: `getSymbol() → Symbol` (symbol for this function's entry point). |
| `Function.entryPoint` | wrappers.py (98, 841), decompile.py (46), callgraph.py (1119), decompile_tool.py (199) | Only `getEntryPoint()` is documented. | Add note: JPype may expose `func.entryPoint` as well as `getEntryPoint()`; same value. |

### A.3 Listing

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| `Listing.getCodeUnits(mem, forward)` with **Memory** | analysis_dump.py:83, _collectors.py:260 — `listing.getCodeUnits(mem, True)`, `mem = program.getMemory()` | Reference only lists `getCodeUnits(forward)`, `getCodeUnits(addr, forward)`, `getCodeUnits(addrSet, forward)`. | Add overload: `getCodeUnits(memory: Memory, forward: boolean) → CodeUnitIterator` (or clarify that Memory is not valid and document correct pattern, e.g. address range). |
| `Listing.getInstructions(forward)` single-arg | _collectors.py:552 — `listing.getInstructions(True)` | Reference only has `getInstructions(body: AddressSetView, forward: boolean)`. | Add: `getInstructions(forward: boolean) → InstructionIterator` (whole program). |
| `Listing.setComment(address, type, null)` to clear | comments.py:217 — `listing.setComment(addr, self._resolve_comment_type(ctype), None)` | B.5.2 only documents `setComment(address, commentType, comment: String)`. | Add: passing `null`/`None` for comment clears the comment at that address/type. |

### A.4 CodeUnit / Data / Instruction

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **CodeUnit.getComment(typeCode)** | _collectors.py:52, 268; dissect.py:342; analysis_dump.py:91 — `cu.getComment(code)` | CodeUnit is imported in B.4 but no CodeUnit method table. CommentType int codes are documented for **Listing** only. | Add subsection **CodeUnit** (ghidra.program.model.listing): `getComment(typeCode: int) → String` (typeCode 0–4; same as Listing comment types). |
| **CodeUnit.getAddress()** | analysis_dump.py:86, _collectors.py (implicit via cu) | Not documented. | Add: `getAddress() → Address`. |
| **Data.getAddress()**, **Data.getLength()** | import_export.py, vtable.py:108,111, structures.py, datatypes.py, data.py, _collectors.py (getLength), dissect.py (var.getLength()) | Data appears in Listing table as return type only. | Add **Data** (subclass of CodeUnit): `getAddress() → Address`, `getLength() → int`. |
| **Instruction** (getAddress) | tool_providers.py:1341, dissect.py (it.next()), search_everything.py:818 | Instruction only as return type. | Add **Instruction**: `getAddress() → Address`; note InstructionIterator has `hasNext()`/`next()`. |

### A.5 SymbolTable

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| `SymbolTable.getSymbols(addr)` return type | xrefs.py:143–146 — used with `hasNext()`/`next()` | B.9.1 says `getSymbols(addr: Address) → Symbol[] or iterator`. | Specify: can return a **SymbolIterator**; use Java iteration (`hasNext()`/`next()`) from Python. |
| `SymbolTable.getSymbols(name)` | wrappers.py:186, 193; xrefs.py:143 | Documented as `getSymbols(name: String) → Symbol[]`. | Add note if it can return iterator in some backends; document Python iteration. |

### A.6 ReferenceManager

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| `ReferenceManager.getReferencesTo(addr)` return type | xrefs.py, wrappers.py:411,484,496, callgraph.py:589, strings.py, dissect.py | B.10.1 says "Reference[] or iterator". | Specify exact type (e.g. `ReferenceIterator` or array) and that Python can iterate with `for ref in ref_mgr.getReferencesTo(addr)` or `hasNext()`/`next()`. |

### A.7 DomainFile / DomainFolder

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **DomainFile.pathname** | context.py:341, 810, 817, 821, 910, 911, 915; launcher.py:500, 509, 1013, 1020, 1026, 1118, 1123; project.py (implied) | Only `getPathname()` is in table. | Add: JPype may expose `.pathname` as property in addition to `getPathname()`; same value. |
| **DomainFile.getParent()** | bsim.py:153 — `prog.getDomainFile().getParent()`; launcher.py:1020 — `df.getParent().pathname` | Not in B.10.1 DomainFile table. | Add: `getParent() → DomainFolder`. |
| **DomainFile.getContentType()** | domain_folder_listing.py:46, launcher.py:159, import_export.py:409 | Not in B.10.1. | Add: `getContentType() → String` (e.g. `"Program"`). |
| **DomainFolder** (full API) | domain_folder_listing.py, context.py, launcher.py, project.py, search_everything.py | B.10.1 lists DomainFolder in import; B.10.2 has getRootFolder() → DomainFolder. No method table. | Add **DomainFolder**: `getFolders() → Iterable<DomainFolder>`, `getFiles() → Iterable<DomainFile>`, `getFolder(name: String) → DomainFolder`, `getPathname() → String`, `getName() → String`. |
| **Import path for DomainFolder** | domain_folder_listing.py:19 — `from ghidra.program.model.data import DomainFolder` | Reference says `ghidra.framework.model.DomainFile, DomainFolder`. | Clarify: standard Ghidra is `ghidra.framework.model.DomainFolder`. Code in domain_folder_listing may be wrong package (program.model.data vs framework.model). |

### A.8 Project / ProjectData / GhidraProject

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **Project** (ghidra.framework.model) | utility.py:16 (TYPE_CHECKING), project.py (getProject()), launcher.py, auto_match_worker.py | Mentioned as return of getProject(); no subsection. | Add **Project**: `getProjectData() → ProjectData`. |
| **ProjectData** | project.py, domain_folder_listing.py, tool_providers.py, import_export.py, auto_match_worker.py | Referenced only indirectly. | Add **ProjectData**: `getRootFolder() → DomainFolder`, `getFolder(path: String) → DomainFolder`; note used from `ghidra_project.getProject().getProjectData()`. |
| **GhidraProject.saveAs** | import_export.py:770 — `ghidra_project.saveAs(program, dest_folder, name, True)` | B.10.2 says "saveAsPackedFile (see API)". | Add: `saveAs(program: Program, folderPath: String, name: String, overwrite: boolean) → void` (or per Ghidra API). |
| **GhidraProject.saveAsPackedFile** | launcher.py:1120, import_export.py:904, utility.py:130 — `project.saveAsPackedFile(program, File(...), True)` | "(see API)" only. | Add: `saveAsPackedFile(program: Program, file: java.io.File, overwrite: boolean)` (or equivalent). |
| **GhidraProject.getProjectData()** | tool_providers.py:1712 — `ghidra_project.getProjectData()` | B.10.2 says "via getProject().getProjectData() when needed". | Document that some builds expose `getProjectData()` directly on GhidraProject. |

### A.9 Namespace / Function

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **Namespace.getParentNamespace()** | symbol_util.py:142, dissect.py:219,225; Symbol.getParentNamespace() is in reference | Symbol has getParentNamespace(); Namespace not tabled. | Add **Namespace**: `getParentNamespace() → Namespace` (for walking up; can be null). |

### A.10 DataType / Structure / Component

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **DataType.getLength()** | structures.py, datatypes.py, data.py, _collectors.py, dissect.py (Variable.getLength) | B.10.13 lists "StructureDataType", "Component" but no method table. | Add: **DataType**: `getLength() → int`; **Composite** (Structure/Union): `getNumComponents() → int`, `getComponent(index: int) → Component`, `getComponentAt(offset: int) → Component`, `add(dataType, length, name, comment)`. **Component**: `getLength() → int`, `setComment(comment: String)`, `getComment() → String`. |
| **Structure.getNumComponents()** | structures.py:172, 253, 267; _collectors.py:513, 525 | — | As above. |
| **Variable.getComment()**, **Variable.getLength()** | dissect.py:488, 486; _collectors (variable info) | — | Add **Variable**: `getComment() → String`, `getLength() → int` (and other getters used). |

### A.11 Address / AddressSpace

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **Address.add(long)** | structures.py:380, 426; data.py:172; datatypes.py:189, 207 — `addr.add(dt.getLength() - 1)` | B.3 lists `add(displacement: long) → Address`. | Already present; ensure documented as primary way to compute address offset. |
| **Address.equals(Object)** | auto_match_worker.py:295 — `bm.getAddress().equals(source_entry_addr)`; symbol_util.py:187 | Not in B.3. | Add: `equals(o: Object) → boolean` (use for address comparison; do not use `==` across Java/Python boundary). |
| **AddressSpace.getAddress(long)** | address_util.py:79 — `default_space.getAddress(int(clean, base))`; vtable.py:143 | AddressFactory has getAddress(offset) and getAddress(addrString); AddressSpace not fully tabled. | Add **AddressSpace**: `getAddress(offset: long) → Address` (in that space). |

### A.12 AddressSetView / body

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **AddressSetView.getNumAddresses()** | analysis_dump.py:115, import_export.py:92,144,170, dissect.py:196, _collectors.py:218, functions.py:296 | B.3.1 has getNumAddresses(). | Already in reference. |
| **Function.getBody()** | Many files | In B.2. | Already present. |

### A.13 DecompileResults / DecompiledFunction

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **result.decompiledFunction** (property) | wrappers.py:301–302, decompile_tool.py:153–154, ghidrecomp/decompile.py:162–163 | Only getDecompiledFunction() is documented. | Add note: In JPype, `result.decompiledFunction` may be exposed as property; same as getDecompiledFunction(); can be null. |

### A.14 HighFunction / P-code

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **HighFunction.getLocalSymbolMap().getSymbols()** | dataflow.py:172 — `hfunc.getLocalSymbolMap().getSymbols()` | B.7.5 says "iterable of local/pcode symbols". | Add: return type (e.g. iterable/array); document Python iteration. PcodeOp iterator (hasNext/next) used in dataflow.py:197–198. |

### A.15 ghidra.program.util

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **DefinedDataIterator.definedStrings(program)** | analysis_dump.py:161, _collectors.py:386, wrappers.py:369 | In B.10.3 import list only; no method row. | Add: `DefinedDataIterator.definedStrings(program: Program) → Iterable<Data>` (or iterator). |
| **DefinedStringIterator.forProgram(program)** | wrappers.py:363 — `DefinedStringIterator.forProgram(self.program)` | Same. | Add: `DefinedStringIterator.forProgram(program: Program) → DefinedStringIterator` (then hasNext/next over string Data). |

### A.16 CheckinHandler

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **CheckinHandler** (method to override) | getfunction.py:839, 1010; import_export.py:1431, 1549; auto_match_worker.py:319 | B.10.8: "subclass and override to provide check-in behavior". | Add: method(s) to override (e.g. `getComment() → String` for check-in comment); constructor/usage with `domainFile.checkin(handler, TaskMonitor.DUMMY)`. |

### A.17 ClientUtil

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **ClientUtil.clearRepositoryAdapter(host, port)** | project.py:847 | B.10.9 has `clearRepositoryAdapter()` with no args. | Add overload: `clearRepositoryAdapter(serverHost: String, serverPort: int)` (or as in Ghidra API). |

### A.18 AppInfo (ghidra.framework.main)

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **AppInfo.getActiveProject()** | import_export.py:1942 — `AppInfo.getActiveProject().getProjectData()` | B.10.13 lists "ghidra.framework.main / AppInfo" in table only. | Add: `AppInfo.getActiveProject() → GhidraProject` (or Project); note GUI/headless context. |

### A.19 RepositoryAdapter

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **RepositoryAdapter.checkout(...)** | project.py:3586, 3590–3591, 3595, 3597 | Not in reference. | Add: `checkout(folderPath: String, itemName: String, checkoutType: CheckoutType, programPath: String)` (or equivalent); note used for versioned shared projects. |

### A.20 BSim / GenSignatures

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **GenSignatures.openProgram(prog, ...)** | ghidrecomp/bsim.py:171 | B.10.12 says "opens program for signature generation". | Add full signature: e.g. `openProgram(program, ...) → void` and `addFunctionTags(...)` (bsim.py:150). |

### A.21 FunctionTag

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **FunctionTag.getName()** | auto_match_worker.py:241–242 — `[t.getName() for t in source_func.getTags()]` | Function getTags() → Set<FunctionTag> in B.2. | Add **FunctionTag**: `getName() → String`. |

### A.22 java.io.File

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **java.io.File** | launcher.py:1120, import_export.py:904, utility.py:130 — `File(str(path))` | Not mentioned. | Add note: Used with saveAsPackedFile(program, File(...), True); construct with `java.io.File(pathString)`. |

### A.23 ClangTokenGroup

| Symbol | Where used | Reference | To add |
|--------|------------|-----------|--------|
| **ClangTokenGroup** | script.py:99, 238 (decompiler list) | Only in DecompileResults.getCCodeMarkup() return type. | No code usage of methods; optional to add type note. |

---

## (B) Incomplete rows — section + row text + what to add

| Section | Row / text | What to add |
|---------|-------------|-------------|
| B.1 (Program) | Footnote: "DomainObject (e.g. getDomainFile(), getName(), getOptions(), save(), startTransaction(), endTransaction(), etc.)" | Replace "etc." with full list of DomainObject methods used in repo: at least getDomainFile(), getName(), getOptions(), save(), startTransaction(), endTransaction(); add return types. |
| B.7.2 DecompileOptions | "(getters/setters) \| e.g. timeout, brace style, max width, proto eval model, simplify double precision \| various \|" | Replace "various" with: list each getter/setter used (timeout, proto eval model) with signature and return type; or add "DecompileOptions: setTimeout(int), getTimeout(), setProtoEvalModel(...), etc. — see Ghidra API for full list." |
| B.7 FlatProgramAPI | "(other) \| clear..., create..., find..., get..., remove..., save, set..., to... \| see Ghidra FlatProgramAPI for full list \|" | Either list every FlatProgramAPI method actually used in repo (getCurrentProgram, toAddr, analyzeAll, saveProgram, getListing, getMemory, getFunctionManager, getSymbolTable) with full signatures, or add a table with those and note "others per Ghidra FlatProgramAPI". |
| B.10 RefType | "(others) \| isData, isRead, isWrite, etc. \| per Ghidra RefType \|" | Replace with explicit list: `isData() → boolean`, `isRead() → boolean`, `isWrite() → boolean` (and any other RefType methods used). |
| B.10.13 Remaining | "ghidra_builtins \| from ghidra_builtins import * → currentProgram, getAddress, toAddr, etc. (script env) \|" | Replace "etc." with full list of builtins used in script env (currentProgram, getAddress, toAddr, and any others referenced in repo or docs). |

---

## (C) Missing edge cases and behavior notes

1. **Listing.getComment overload resolution**  
   Already noted in reference: support both `getComment(int, Address)` and `getComment(CommentType, Address)`; try int first, fall back to CommentType on "no matching overloads". Code in comments.py does exactly this; keep this edge case in the reference.

2. **Listing.setComment(..., null) to clear**  
   Code passes `None` to clear a comment (comments.py:217). Document: passing `null`/`None` for the comment argument clears that comment type at that address.

3. **DecompiledFunction null**  
   Already documented. Ensure all code paths check `df`/`getDecompiledFunction()` before calling getC()/getSignature().

4. **Java iterators from Python**  
   Reference mentions ReferenceIterator, AddressRangeIterator with hasNext()/next(). Add explicit note for:
   - **CodeUnitIterator**, **InstructionIterator**, **SymbolIterator**, **BookmarkIterator**, **FunctionIterator**: all use `hasNext()`/`next()` in Python; no Python `for x in it` unless wrapped.
   - **getReferencesTo** / **getReferencesFrom**: document whether they return array (Python-iterable) or iterator (hasNext/next).

5. **DomainFile checkout/checkin**  
   Already documented: end active transaction before checkout/checkin/save to avoid "Unable to lock due to active transaction".

6. **GhidraProject.openProgram**  
   Overloads documented. Add: for versioned (shared) projects, checkout before modify and checkin after; openProgram can raise if file is not checked out when write is required.

7. **Symbol.getSymbolType()**  
   Returns SymbolType enum; document that comparing with SymbolType.FUNCTION, etc., is used for filtering (symbols.py, analysis_dump.py).

8. **getFunctionAt vs getFunctionContaining**  
   Code often uses `getFunctionContaining(addr) or getFunctionAt(addr)`. Document: getFunctionAt(addr) returns function whose entry point is addr; getFunctionContaining(addr) returns function whose body contains addr (or null); order of fallback matters.

9. **DomainFolder import**  
   Code in domain_folder_listing.py imports DomainFolder from `ghidra.program.model.data`; reference and rest of code use `ghidra.framework.model`. Document correct import and flag possible bug in domain_folder_listing.

10. **Memory.getBlocks()**  
    Returns Java Iterator<MemoryBlock>; document hasNext()/next() when iterating from Python.

---

## (D) Other recommendations for exhaustive coverage

1. **CodeUnit constants**  
   Code uses `CodeUnit.EOL_COMMENT`, `PRE_COMMENT`, `POST_COMMENT`, `PLATE_COMMENT`, `REPEATABLE_COMMENT` (getfunction.py, auto_match_worker.py). Reference has CommentType and int codes; add explicit "CodeUnit.EOL_COMMENT = 0", etc., or cross-reference to CommentType table.

2. **Program.getName()**  
   Used everywhere; ensure it is in Program/DomainObject getters with return type String.

3. **Consistent iterator documentation**  
   For every API that returns an iterator (getCodeUnits, getInstructions, getFunctions, getSymbolIterator, getReferencesTo, getAddressRanges, getBlocks, etc.), add one line: "Java iterator; in Python use hasNext()/next() or wrap in a loop."

4. **TYPE_CHECKING import paths**  
   Reference already says "Import paths must match this document". After filling gaps, run a quick grep for `from ghidra` in `src/` and ensure each import path appears in the reference (and fix domain_folder_listing if DomainFolder is wrong).

5. **Version-specific notes**  
   Where behavior differs by Ghidra or PyGhidra version (e.g. getComment(int vs CommentType, getProjectData() on GhidraProject), keep a short "Version note" in the reference.

6. **Index / quick reference**  
   Consider adding an alphabetical index of all documented symbols (Program, Function, Listing, ...) with section numbers for faster lookup.

---

**Summary**

- **Missing APIs (A):** 40+ symbols or method overloads used in code but missing or under-specified in the reference; highest impact: CodeUnit (getComment, getAddress), DomainFile (getParent, pathname, getContentType), DomainFolder (full API), ProjectData, Function.getSymbol(), Listing getCodeUnits(Memory) and getInstructions(boolean), setComment(..., null), DefinedDataIterator/DefinedStringIterator, CheckinHandler override method, Component/DataType/Structure/Variable methods, Address.equals, AddressSpace.getAddress.
- **Incomplete rows (B):** 5 rows with "per API", "various", "etc.", or "see ... docs" that should be replaced with concrete signatures or explicit lists.
- **Edge cases (C):** 10 items (null clearing, iterators, overload resolution, DomainFolder import, etc.).
- **Recommendations (D):** 6 (CodeUnit constants, iterator consistency, TYPE_CHECKING alignment, version notes, index).

Applying (A)–(D) will align the reference with actual usage across `src/agentdecompile_cli` and support both implementors and static type-checking.
