"""Builds a CorpusDump from a decomp project's assembly (and C) source tree.

Ports the pure-logic core of the upstream indexer.ts: incremental
content-hash diffing (its "Phase 3"), unmatched-assembly-function scanning
("Phase 2", via asm_utils), map-file-based ROM-address lookup, and embedding
of new/changed functions (via semantic_embedder). This is the missing link
between "a project on disk" and a queryable DecompFunctionCorpus.

Deliberately NOT ported, and why:
  - Node `fs.watch` / CLI progress-bar plumbing. Not applicable outside a
    Node CLI; `on_progress` here is a plain callback, same shape as
    upstream's, but nothing drives a spinner with it.
  - The `@ast-grep/napi`-based C-AST walk upstream uses for its "Phase 1"
    (scanning-c): finding `function_definition` nodes, and skipping
    NONMATCH-wrapped, `#if 0`-wrapped, and `static inline` functions by
    inspecting tree-sitter AST structure. This codebase has no ported C/
    tree-sitter parser (that's a much bigger, separate undertaking), so
    `CFunctionRecord` is accepted as an input seam instead: whatever a
    future C-parsing step extracts, already filtered the way ast-grep
    filters upstream, gets handed to `index_codebase` directly.
  - Objdiff-based assembly extraction from compiled `.o` files, which needs
    the native `objdiff` tool. Upstream's own spec tests never actually
    exercise a working objdiff path either (there are no real object files
    in the test fixtures -- objdiff always throws and execution falls
    through to the `matchingAsmFolders` fallback). That fallback -- scanning
    per-function `.s` files under e.g. `asm/matchings/` and matching by
    function name -- is pure logic buildable from asm_utils alone, so it's
    the only assembly-resolution strategy ported here for matched functions.
    If it can't find assembly for a given C function record, that record is
    silently skipped (upstream raises after collecting all such failures;
    skipping is a deliberate simplification given there's no second
    resolution strategy backing it up here).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Literal

from .asm_embedding import preprocess_for_embedding
from .asm_utils import (
    ArmOrMips,
    count_body_lines_from_asm_function,
    extract_function_calls_from_assembly,
    list_functions_from_asm_module,
)
from .decomp_function_corpus import (
    DECOMP_FUNCTION_CORPUS_VERSION,
    CorpusDump,
    DecompFunctionDoc,
    VectorEntry,
)
from .map_file import parse_map_file_addresses
from .semantic_embedder import SemanticEmbedder

DECOMP_INDEX_FILENAME = "decomp-function-index.json"

ASM_FILE_SUFFIXES = (".s", ".S", ".asm")

IndexPhase = Literal["scanning-c", "scanning-asm", "diffing", "writing"]


@dataclass
class IndexProgress:
    phase: IndexPhase
    current: int
    total: int
    message: str


ProgressCallback = Callable[[IndexProgress], None]


@dataclass
class CFunctionRecord:
    """A C function definition, as an external C/AST parser would extract it.

    Stands in for what upstream's `@ast-grep/napi` walk produces. See the
    module docstring for why that walk isn't ported here.
    """

    name: str
    c_code: str
    c_module_path: str


@dataclass
class IndexCodebaseConfig:
    project_root: Path
    map_file_path: Path
    platform: ArmOrMips
    non_matching_asm_folders: list[str] = field(default_factory=list)
    matching_asm_folders: list[str] = field(default_factory=list)
    exclude_from_scan: list[str] = field(default_factory=list)
    c_functions: list[CFunctionRecord] = field(default_factory=list)


@dataclass
class IndexStats:
    matched_functions: int
    unmatched_functions: int
    new_count: int
    updated_count: int
    unchanged_count: int
    removed_count: int


@dataclass
class IndexResult:
    dump: CorpusDump
    content_hashes: dict[str, str]
    stats: IndexStats


_END_NONMATCH_RE = re.compile(r"^END_NONMATCH\s*")


def clean_function_text(text: str) -> str:
    """Strip a leading END_NONMATCH macro artifact from extracted C function text.

    Tree-sitter doesn't run the C preprocessor, so macros like END_NONMATCH
    (which expand to nothing) get parsed as part of the function's return
    type, leaving the macro text at the start of the extracted node text.
    """
    return _END_NONMATCH_RE.sub("", text)


def content_hash(asm_code: str, c_code: str | None = None) -> str:
    """Content hash for a function's code, used to detect changes for incremental indexing."""
    hasher = hashlib.sha256()
    hasher.update(asm_code.encode("utf-8"))
    hasher.update((c_code or "").encode("utf-8"))
    return hasher.hexdigest()


def _glob_asm_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.rglob("*") if p.is_file() and p.suffix in ASM_FILE_SUFFIXES)


def _build_matching_asm_lookup(
    project_root: Path,
    platform: ArmOrMips,
    matching_asm_folders: list[str],
) -> dict[str, tuple[str, str]]:
    """Map function name -> (asm code, asm module path) from per-function .s files."""
    lookup: dict[str, tuple[str, str]] = {}
    for folder in matching_asm_folders:
        asm_dir = project_root / folder
        for asm_file in _glob_asm_files(asm_dir):
            try:
                content = asm_file.read_text(encoding="utf-8")
            except OSError:
                continue
            asm_module_path = str(asm_file.relative_to(project_root))
            for fn in list_functions_from_asm_module(platform, content):
                name, code = fn["name"], fn["code"]
                if name not in lookup and count_body_lines_from_asm_function(platform, code) > 0:
                    lookup[name] = (code, asm_module_path)
    return lookup


def _scan_matched_functions(
    config: IndexCodebaseConfig,
    address_map: dict[str, int],
    on_progress: ProgressCallback | None,
) -> dict[str, DecompFunctionDoc]:
    functions: dict[str, DecompFunctionDoc] = {}

    c_functions = [
        cf
        for cf in config.c_functions
        if not any(cf.c_module_path.startswith(d + "/") for d in config.exclude_from_scan)
    ]

    if on_progress:
        on_progress(
            IndexProgress(
                phase="scanning-c",
                current=0,
                total=len(c_functions),
                message=f"Found {len(c_functions)} C functions. Extracting assembly...",
            )
        )

    matching_lookup = _build_matching_asm_lookup(config.project_root, config.platform, config.matching_asm_folders)

    for processed, cf in enumerate(c_functions, start=1):
        if cf.name in functions:
            continue

        fallback = matching_lookup.get(cf.name)
        if fallback is None:
            continue

        asm_code, asm_module_path = fallback
        c_code = clean_function_text(cf.c_code)
        calls_functions = extract_function_calls_from_assembly(config.platform, asm_code)
        rom_address = address_map.get(cf.name)

        functions[cf.name] = DecompFunctionDoc(
            id=cf.name,
            name=cf.name,
            rom_address=rom_address,
            c_code=c_code,
            c_module_path=cf.c_module_path,
            asm_code=asm_code,
            asm_module_path=asm_module_path,
            calls_functions=calls_functions,
        )

        if on_progress and processed % 50 == 0:
            on_progress(
                IndexProgress(
                    phase="scanning-c",
                    current=processed,
                    total=len(c_functions),
                    message=f"Processing C functions: {processed}/{len(c_functions)}",
                )
            )

    return functions


def _scan_unmatched_functions(
    project_root: Path,
    platform: ArmOrMips,
    non_matching_asm_folders: list[str],
    matched_functions: dict[str, DecompFunctionDoc],
    address_map: dict[str, int],
    on_progress: ProgressCallback | None,
) -> dict[str, DecompFunctionDoc]:
    functions: dict[str, DecompFunctionDoc] = {}

    asm_files: list[Path] = []
    for folder in non_matching_asm_folders:
        asm_files.extend(_glob_asm_files(project_root / folder))
    total_files = len(asm_files)

    for processed, asm_file in enumerate(asm_files, start=1):
        try:
            content = asm_file.read_text(encoding="utf-8")
        except OSError:
            continue

        asm_module_path = str(asm_file.relative_to(project_root))
        for fn in list_functions_from_asm_module(platform, content):
            name, code = fn["name"], fn["code"]
            if name in matched_functions or name in functions:
                continue
            if count_body_lines_from_asm_function(platform, code) == 0:
                continue

            calls_functions = extract_function_calls_from_assembly(platform, code)
            rom_address = address_map.get(name)
            functions[name] = DecompFunctionDoc(
                id=name,
                name=name,
                rom_address=rom_address,
                asm_code=code,
                asm_module_path=asm_module_path,
                calls_functions=calls_functions,
            )

        if on_progress and processed % 20 == 0:
            on_progress(
                IndexProgress(
                    phase="scanning-asm",
                    current=processed,
                    total=total_files,
                    message=f"Processing assembly files: {processed}/{total_files}",
                )
            )

    return functions


def index_codebase(
    config: IndexCodebaseConfig,
    *,
    existing_dump: CorpusDump | None = None,
    existing_content_hashes: dict[str, str] | None = None,
    embedder: SemanticEmbedder | None = None,
    on_progress: ProgressCallback | None = None,
) -> IndexResult:
    """Index a decomp project codebase into a CorpusDump.

    Scans for matched (C) and unmatched (assembly-only) functions, performs
    incremental diffing against `existing_content_hashes` if supplied, and
    returns the resulting CorpusDump plus the new content hashes and stats.

    Functions whose content hash is unchanged reuse their embedding from
    `existing_dump.vectors`. New/changed functions are embedded via
    `embedder` if one is supplied (using `asm_embedding.preprocess_for_embedding`
    to normalize the assembly text first); otherwise they're left unembedded,
    matching upstream's split between indexing and the (separately invoked)
    embedder.
    """
    map_content = config.map_file_path.read_text(encoding="utf-8")
    address_map = parse_map_file_addresses(map_content)

    existing_hashes = existing_content_hashes or {}
    existing_vectors_by_id = {v.id: v.embedding for v in (existing_dump.vectors if existing_dump else [])}

    if on_progress:
        on_progress(
            IndexProgress(
                phase="scanning-c", current=0, total=0, message="Scanning C files for function definitions..."
            )
        )
    matched_functions = _scan_matched_functions(config, address_map, on_progress)

    if on_progress:
        on_progress(
            IndexProgress(
                phase="scanning-asm",
                current=0,
                total=0,
                message="Scanning assembly files for unmatched functions...",
            )
        )
    unmatched_functions = _scan_unmatched_functions(
        config.project_root,
        config.platform,
        config.non_matching_asm_folders,
        matched_functions,
        address_map,
        on_progress,
    )

    all_functions = [*matched_functions.values(), *unmatched_functions.values()]

    if on_progress:
        on_progress(
            IndexProgress(
                phase="diffing", current=0, total=len(all_functions), message="Computing incremental diff..."
            )
        )

    new_content_hashes: dict[str, str] = {}
    new_count = updated_count = unchanged_count = 0
    for fn in all_functions:
        h = content_hash(fn.asm_code, fn.c_code)
        new_content_hashes[fn.id] = h
        if fn.id not in existing_hashes:
            new_count += 1
        elif existing_hashes[fn.id] != h:
            updated_count += 1
        else:
            unchanged_count += 1

    all_ids = {fn.id for fn in all_functions}
    removed_count = sum(1 for id_ in existing_hashes if id_ not in all_ids)

    vectors: list[VectorEntry] = []
    to_embed: list[DecompFunctionDoc] = []
    for fn in all_functions:
        h = new_content_hashes[fn.id]
        if existing_hashes.get(fn.id) == h and fn.id in existing_vectors_by_id:
            vectors.append(VectorEntry(id=fn.id, embedding=existing_vectors_by_id[fn.id]))
        else:
            to_embed.append(fn)

    if embedder is not None and to_embed:
        texts = [preprocess_for_embedding(config.platform, fn.asm_code) for fn in to_embed]
        embeddings = embedder.embed_all(texts)
        for fn, embedding in zip(to_embed, embeddings):
            vectors.append(VectorEntry(id=fn.id, embedding=embedding))

    dump = CorpusDump(platform=config.platform, functions=all_functions, vectors=vectors)

    if on_progress:
        on_progress(
            IndexProgress(
                phase="writing",
                current=len(all_functions),
                total=len(all_functions),
                message=f"Done. {len(matched_functions)} matched, {len(unmatched_functions)} unmatched.",
            )
        )

    stats = IndexStats(
        matched_functions=len(matched_functions),
        unmatched_functions=len(unmatched_functions),
        new_count=new_count,
        updated_count=updated_count,
        unchanged_count=unchanged_count,
        removed_count=removed_count,
    )
    return IndexResult(dump=dump, content_hashes=new_content_hashes, stats=stats)


def write_index(project_root: Path, dump: CorpusDump, content_hashes: dict[str, str]) -> None:
    """Write a CorpusDump plus its content hashes atomically (temp file + rename)."""
    db_path = project_root / DECOMP_INDEX_FILENAME
    tmp_path = db_path.with_name(db_path.name + ".tmp")

    payload = {
        "version": dump.version,
        "platform": dump.platform,
        "functions": [asdict(fn) for fn in dump.functions],
        "vectors": [asdict(v) for v in dump.vectors],
        "content_hashes": content_hashes,
    }
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_path.replace(db_path)


def load_existing_index(project_root: Path) -> tuple[CorpusDump | None, dict[str, str]]:
    """Load a previously written index from `project_root`, if present and version-compatible."""
    db_path = project_root / DECOMP_INDEX_FILENAME
    try:
        parsed = json.loads(db_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, {}

    if parsed.get("version") != DECOMP_FUNCTION_CORPUS_VERSION:
        return None, {}

    functions = [DecompFunctionDoc(**fn) for fn in parsed.get("functions", [])]
    vectors = [VectorEntry(**v) for v in parsed.get("vectors", [])]
    dump = CorpusDump(platform=parsed["platform"], functions=functions, vectors=vectors, version=parsed["version"])
    return dump, dict(parsed.get("content_hashes", {}))
