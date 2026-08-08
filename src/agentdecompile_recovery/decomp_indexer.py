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
    AsmPlatform,
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
    platform: AsmPlatform
    # Optional: a decomp project supplies a GNU ld map for ROM addresses, but
    # a work dir carries the address per case instead. No map, no rom_address.
    map_file_path: Path | None = None
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
    platform: AsmPlatform,
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
    platform: AsmPlatform,
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
    address_map: dict[str, int] = {}
    if config.map_file_path is not None:
        address_map = parse_map_file_addresses(config.map_file_path.read_text(encoding="utf-8"))

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

    return _build_index_result(
        platform=config.platform,
        matched_functions=list(matched_functions.values()),
        unmatched_functions=list(unmatched_functions.values()),
        existing_dump=existing_dump,
        existing_content_hashes=existing_content_hashes,
        embedder=embedder,
        on_progress=on_progress,
    )


def _build_index_result(
    *,
    platform: AsmPlatform,
    matched_functions: list[DecompFunctionDoc],
    unmatched_functions: list[DecompFunctionDoc],
    existing_dump: CorpusDump | None,
    existing_content_hashes: dict[str, str] | None,
    embedder: SemanticEmbedder | None,
    on_progress: ProgressCallback | None,
) -> IndexResult:
    """Incremental diff, embedding, and packaging -- shared by both front doors."""
    existing_hashes = existing_content_hashes or {}
    existing_vectors_by_id = {v.id: v.embedding for v in (existing_dump.vectors if existing_dump else [])}

    all_functions = [*matched_functions, *unmatched_functions]

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
        texts = [preprocess_for_embedding(platform, fn.asm_code) for fn in to_embed]
        embeddings = embedder.embed_all(texts)
        for fn, embedding in zip(to_embed, embeddings):
            vectors.append(VectorEntry(id=fn.id, embedding=embedding))

    dump = CorpusDump(platform=platform, functions=all_functions, vectors=vectors)

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


# --- Second front door: a source-parity work dir ------------------------------
#
# `index_codebase` above assumes a decomp project: per-function `.s` files in
# `asm/matchings/`, C sources ast-grep can walk, a linker map. This project's
# own target has none of that. What it has is a work dir under
# `target/agentdecompile-reconstruct/<name>/source-synthesis/cases/`, where each
# case directory holds a candidate `candidate.c` and, per compiler profile, a
# `verify.json` recording an objdiff run: `alignedDiff` rows carrying the
# target and candidate x86 disassembly side by side, plus the objdiff report
# the similarity comes from.
#
# That is strictly *more* information than the decomp-project layout: every
# function arrives with a measured match outcome attached. The retrieval layer
# wants exactly that, so the work dir is read directly rather than being
# transcoded into a fake decomp project first.

CASE_VERIFY_FILENAME = "verify.json"
CASE_GENERATION_FILENAME = "generation.json"
CASE_CANDIDATE_FILENAME = "candidate.c"

# Byte-emission rules produce MASM `DB 06ah, 0ffh, ...` blobs that reproduce
# the target bytes exactly and therefore always "match". They are worthless as
# worked examples -- a model shown one learns to emit bytes, which is the very
# cheat `rewrite_context` bans -- so they are excluded by default.
BYTE_EMISSION_RULE_MARKER = "masm"


@dataclass
class ParityCaseIndexConfig:
    work_dir: Path
    platform: AsmPlatform = "x86"
    # Keep only cases whose best profile scored at least this. `None` keeps
    # every case that produced any objdiff result at all.
    min_match_percent: float | None = None
    exclude_byte_emission_rules: bool = True
    max_workers: int = 32


def _best_symbol_match_percent(objdiff_output: str) -> float | None:
    """Highest per-symbol `match_percent` in an objdiff JSON report."""
    try:
        parsed = json.loads(objdiff_output)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None

    best: float | None = None
    for side in ("left", "right"):
        side_object = parsed.get(side)
        if not isinstance(side_object, dict):
            continue
        for symbol in side_object.get("symbols") or []:
            if not isinstance(symbol, dict) or symbol.get("kind") == "SYMBOL_SECTION":
                continue
            value = symbol.get("match_percent")
            if isinstance(value, (int, float)):
                best = float(value) if best is None else max(best, float(value))
    if best is not None:
        return best

    for side in ("left", "right"):
        side_object = parsed.get(side)
        if not isinstance(side_object, dict):
            continue
        for section in side_object.get("sections") or []:
            if not isinstance(section, dict) or section.get("kind") != "SECTION_CODE":
                continue
            value = section.get("match_percent")
            if isinstance(value, (int, float)):
                best = float(value) if best is None else max(best, float(value))
    return best


def _read_json(path: Path) -> dict | None:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _aligned_column(rows: list, key: str) -> str:
    return "\n".join(
        str(row[key]) for row in rows if isinstance(row, dict) and isinstance(row.get(key), str) and row[key]
    )


def _scan_parity_case(case_dir: Path, config: ParityCaseIndexConfig) -> DecompFunctionDoc | None:
    """Best-scoring profile of one case, as a corpus document.

    Returns None when the case never produced an objdiff result, or when its
    rule is excluded, or when its best score is below the configured floor.
    """
    generation = _read_json(case_dir / CASE_GENERATION_FILENAME) or {}
    rule = str(generation.get("rule") or "")
    variant = str(generation.get("variant") or "")
    if config.exclude_byte_emission_rules and (
        BYTE_EMISSION_RULE_MARKER in rule or BYTE_EMISSION_RULE_MARKER in variant
    ):
        return None

    best_score: float | None = None
    best_profile: Path | None = None
    best_rows: list = []
    for profile_dir in sorted(case_dir.glob("profile_*")):
        report = _read_json(profile_dir / CASE_VERIFY_FILENAME)
        if report is None:
            continue
        score = _best_symbol_match_percent(str(report.get("output") or ""))
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score = score
            best_profile = profile_dir
            best_rows = report.get("alignedDiff") or []

    if best_score is None or best_profile is None:
        return None
    if config.min_match_percent is not None and best_score < config.min_match_percent:
        return None

    target_asm = _aligned_column(best_rows, "target")
    if not target_asm:
        return None

    name = str(generation.get("name") or case_dir.name)
    try:
        c_code = (case_dir / CASE_CANDIDATE_FILENAME).read_text(encoding="utf-8")
    except OSError:
        c_code = None

    # Call edges come from the *candidate* column. The target object in this
    # corpus is assembled from raw bytes and carries no relocations, so its
    # `call 0x223d30` is an intra-object offset; the MSVC-compiled candidate
    # is relocated and names its callees. See asm_utils' stated boundary.
    candidate_asm = _aligned_column(best_rows, "candidate")
    calls_functions = extract_function_calls_from_assembly(config.platform, candidate_asm)

    entry = str(generation.get("entry") or "")
    try:
        rom_address = int(entry, 16) if entry else None
    except ValueError:
        rom_address = None

    return DecompFunctionDoc(
        id=name,
        name=name,
        rom_address=rom_address,
        c_code=c_code,
        c_module_path=str(case_dir / CASE_CANDIDATE_FILENAME),
        asm_code=target_asm,
        asm_module_path=str(best_profile / CASE_VERIFY_FILENAME),
        calls_functions=calls_functions,
        match_percent=best_score,
    )


def index_parity_work_dir(
    config: ParityCaseIndexConfig,
    *,
    existing_dump: CorpusDump | None = None,
    existing_content_hashes: dict[str, str] | None = None,
    embedder: SemanticEmbedder | None = None,
    on_progress: ProgressCallback | None = None,
) -> IndexResult:
    """Index a source-parity work dir's synthesis cases into a CorpusDump.

    Cases are read concurrently: the cost is per-file IO latency on a work dir
    that routinely holds thousands of case directories, not CPU. Measured on
    this project's 2,337-case KOTOR work dir (rotational USB disk), a serial
    pass ran at roughly 1.2 s per case; 32 threads brought the whole scan to
    about 110 s.

    Documents land in `matched_functions` when they carry C source and in
    `unmatched_functions` when only assembly survived, mirroring
    `index_codebase`'s split.
    """
    from concurrent.futures import ThreadPoolExecutor

    cases_root = config.work_dir / "source-synthesis" / "cases"
    if not cases_root.is_dir():
        raise ValueError(f"No source-synthesis/cases directory under {config.work_dir}")

    case_dirs = sorted(path for path in cases_root.iterdir() if path.is_dir())
    if on_progress:
        on_progress(
            IndexProgress(
                phase="scanning-asm",
                current=0,
                total=len(case_dirs),
                message=f"Scanning {len(case_dirs)} synthesis cases...",
            )
        )

    documents: list[DecompFunctionDoc] = []
    with ThreadPoolExecutor(max_workers=max(1, config.max_workers)) as pool:
        for processed, document in enumerate(
            pool.map(lambda case_dir: _scan_parity_case(case_dir, config), case_dirs), start=1
        ):
            if document is not None:
                documents.append(document)
            if on_progress and processed % 200 == 0:
                on_progress(
                    IndexProgress(
                        phase="scanning-asm",
                        current=processed,
                        total=len(case_dirs),
                        message=f"Scanned {processed}/{len(case_dirs)} cases; kept {len(documents)}",
                    )
                )

    # One document per function: a function reached by several cases keeps its
    # best-scoring one.
    by_name: dict[str, DecompFunctionDoc] = {}
    for document in documents:
        existing = by_name.get(document.id)
        if existing is None or (document.match_percent or 0.0) > (existing.match_percent or 0.0):
            by_name[document.id] = document

    matched = [doc for doc in by_name.values() if doc.c_code]
    unmatched = [doc for doc in by_name.values() if not doc.c_code]

    return _build_index_result(
        platform=config.platform,
        matched_functions=matched,
        unmatched_functions=unmatched,
        existing_dump=existing_dump,
        existing_content_hashes=existing_content_hashes,
        embedder=embedder,
        on_progress=on_progress,
    )


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
