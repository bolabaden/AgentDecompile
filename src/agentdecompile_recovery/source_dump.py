"""Layered source dump with verified vs advisory claim layers."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from .match_cache import is_proven_zero
from .source_cleanup import clean_source_text, format_source_text
from .source_export import (
    claim_boundary_for,
    dedupe_best_matches,
    is_exportable_match,
    iter_rows,
    resolve_match_source_text,
)
from .verify_pool import resolve_workers


DEFAULT_MODULES = (
    "recovered/unmapped",
)

BYTE_EMITTER_MARKERS = (
    "__asm",
    "_asm",
    "_emit",
    ".byte",
    "incbin",
    "BYTE_EMIT",
    "nonsemantic-bootstrap",
)

# MASM data directives (standalone lines like `payload db 90h, 90h`).
_ASM_DATA_DIRECTIVE = re.compile(r"(?im)^\s*\w+\s+d[bwdq]\b")
# Const hex blob copied via memcpy — byte-emission shape, not high-level C.
_MEMCPY_HEX_BLOB = re.compile(
    r"unsigned\s+char\s+\w+\s*\[\s*\]\s*=\s*\{[^}]*0x[0-9a-fA-F]{2}",
    re.DOTALL,
)

_FORMAT_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}


class PendingWrites:
    """In-memory path → text map flushed to disk in one parallel batch."""

    def __init__(self) -> None:
        self._files: dict[Path, str] = {}

    def add(self, path: Path, text: str) -> None:
        self._files[path] = text

    def items(self) -> list[tuple[Path, str]]:
        return list(self._files.items())

    def __len__(self) -> int:
        return len(self._files)

    def format_c_like_files(self) -> None:
        """Run clang-format once per assembled .c/.cpp/.h artifact."""

        for path, text in list(self._files.items()):
            suffix = path.suffix.lower()
            if suffix not in _FORMAT_SUFFIXES:
                continue
            formatted, _meta = format_source_text(text, suffix)
            self._files[path] = formatted

    def flush(self, *, workers: int | None = None) -> int:
        """Create parent dirs once, then write all files with a bounded thread pool."""

        if not self._files:
            return 0
        parents = {path.parent for path in self._files}
        for parent in sorted(parents, key=lambda p: len(p.parts)):
            parent.mkdir(parents=True, exist_ok=True)

        def _write(item: tuple[Path, str]) -> None:
            path, text = item
            path.write_text(text, encoding="utf-8")

        count = resolve_workers(workers)
        items = list(self._files.items())
        if count == 1 or len(items) == 1:
            for item in items:
                _write(item)
            return len(items)

        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(_write, item) for item in items]
            for future in as_completed(futures):
                future.result()
        return len(items)


def allman_brace_style(source: str) -> str:
    """Move opening braces to their own line for function definitions (Allman brace style)."""

    lines = source.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    for line in lines:
        stripped = line.rstrip()
        if re.search(r"\)\s*\{\s*$", stripped) and not stripped.lstrip().startswith(
            ("if ", "for ", "while ", "switch ", "else", "do ")
        ):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(re.sub(r"\)\s*\{\s*$", ")", stripped))
            out.append(f"{indent}{{")
            continue
        out.append(stripped)
    return "\n".join(out).rstrip() + "\n"


# Back-compat alias for older call sites / imports.
borealis_brace_style = allman_brace_style


def strip_ghidra_noise(source: str) -> str:
    """Drop Ghidra WARNING / library-match banner lines that hurt Port readability."""

    text = source.replace("\r\n", "\n")
    # Remove multi-line /* WARNING: ... */ and /* Library Function ... */ blocks.
    text = re.sub(
        r"/\*\s*(?:WARNING:|Library Function -).*?\*/\s*",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # Collapse excess blank lines left behind.
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.lstrip("\n")


def style_c_source(source: str) -> str:
    """In-process Allman brace style + banner/noise strip (no clang-format subprocess)."""

    return allman_brace_style(strip_claim_banners(strip_ghidra_noise(source)))


def strip_claim_banners(source: str) -> str:
    """Remove stacked Authority / claimBoundary comment banners so dump headers stay single."""

    text = source.replace("\r\n", "\n")
    # Drop leading block comments that only carry dump/advisory metadata.
    while True:
        stripped = text.lstrip()
        if not stripped.startswith("/*"):
            break
        end = stripped.find("*/")
        if end < 0:
            break
        block = stripped[: end + 2]
        lower = block.lower()
        if not any(
            marker in lower
            for marker in (
                "authority:",
                "claimboundary:",
                "entry=",
                "generated by source-parity",
                "acceptance requires objdiff",
            )
        ):
            break
        text = stripped[end + 2 :].lstrip("\n")
    return text


def format_c_source(source: str) -> str:
    styled = style_c_source(source)
    formatted, _meta = format_source_text(styled, ".c")
    return formatted


def looks_like_byte_emitter(source: str, row: dict[str, Any] | None = None) -> bool:
    """Conservative byte-emitter detector. Bias toward rejection: a false reject
    only drops a unit from ``verified/`` into the module tree, but a false accept
    would present copied target bytes as original-dev C (a hard honesty break)."""

    quality = str((row or {}).get("sourceQuality") or "").lower()
    # Any assembly/byte-emission quality is a hard reject, including inline-asm-c
    # (which reproduces bytes via __asm/_emit rather than real high-level C).
    if quality in {"byte-emission-asm", "nonsemantic-bootstrap", "inline-asm-c", "masm"}:
        return True
    name = str((row or {}).get("name") or "").lower()
    if "full-binary" in name or name.endswith("_emit"):
        return True
    lowered = source.lower()
    # Any single unambiguous emitter marker is enough to reject.
    if any(marker.lower() in lowered for marker in BYTE_EMITTER_MARKERS):
        return True
    if _ASM_DATA_DIRECTIVE.search(source):
        return True
    if "memcpy" in lowered and _MEMCPY_HEX_BLOB.search(source):
        return True
    return False


def normalize_entry_hex(raw: Any) -> str:
    """Normalize an entry/entryOffset (hex string, '0x…', or int) to bare lowercase hex."""

    if raw is None:
        return ""
    if isinstance(raw, int):
        return f"{raw:08x}"
    text = str(raw).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if text and all(c in "0123456789abcdef" for c in text):
        return text
    try:
        return f"{int(text):08x}"
    except (TypeError, ValueError):
        return text


def module_for_entry(entry: str, kind: str | None, *, profile: str = "binary", va_bands: list | None = None) -> str:
    """Resolve module path for an entry via evidence resolver (optional VA bands)."""
    from .module_resolver import FALLBACK_MODULE, ModuleResolver

    try:
        addr = int(entry, 16) if isinstance(entry, str) else int(entry)
    except (TypeError, ValueError):
        return FALLBACK_MODULE
    _ = kind, profile
    return ModuleResolver(va_bands=list(va_bands or [])).resolve(addr).module


def authority_label(row: dict[str, Any]) -> str:
    # verified/ labels require a proven objdiff differences==0 receipt. A row that
    # is merely "exportable" (e.g. a source-shape row without a zero proof) is NOT
    # verified — treat it as advisory so it never lands under verified/.
    status = str(row.get("status") or "")
    if not is_proven_zero(row):
        return "ghidra-advisory"
    if status == "matched":
        return "objdiff-matched"
    if status in {"code-slice-matched", "source-shape-code-slice-matched"}:
        return "code-slice-matched"
    return "ghidra-advisory"


def file_stem_for(kind: str | None, authority: str, rule: str | None = None) -> str:
    kind = (kind or "function").lower()
    rule = (rule or "").lower()
    if authority == "ghidra-advisory":
        return "ghidra_decompiled"
    if "virtual" in kind or "vtable" in kind or "virtual" in rule or "vtable" in rule:
        return "matched_vtables"
    if "reloc" in kind or "wrapper" in kind or "thunk" in kind:
        return "matched_thunks"
    if "trivial" in kind or "accessor" in kind or "return" in kind or "field" in kind:
        return "matched_accessors"
    if authority == "code-slice-matched":
        return "matched_synthesized"
    return "matched_functions"


def render_cpp_module(banner: list[str], bodies: list[str], header_include: str) -> str:
    chunks = ["/*", *banner, " */", "", f'#include "{header_include}"', "", *bodies]
    return "\n".join(chunks).rstrip() + "\n"


def render_header(path_name: str, prototypes: list[str], banner: list[str]) -> str:
    guard = re.sub(r"[^A-Z0-9]", "_", path_name.upper())
    chunks = [
        "/*",
        *banner,
        " */",
        "",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
        *prototypes,
        "",
        "#ifdef __cplusplus",
        "}",
        "#endif",
        "",
        f"#endif /* {guard} */",
        "",
    ]
    return "\n".join(chunks)


def write_cpp_module(path: Path, banner: list[str], bodies: list[str], header_include: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cpp_module(banner, bodies, header_include), encoding="utf-8")


def write_header(path: Path, prototypes: list[str], banner: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_header(path.name, prototypes, banner), encoding="utf-8")


def prototype_from_source(source: str) -> str | None:
    text = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    text = re.sub(r"//.*?$", "", text, flags=re.M)
    text = re.sub(r"^extern\s+.+?;\s*", "", text.strip(), flags=re.M)
    match = re.search(
        r"((?:[\w\s\*]+)\s+(?:__\w+\s+)?[\w:]+\s*\([^;]*\))\s*\{",
        text,
        flags=re.S,
    )
    if not match:
        return None
    proto = re.sub(r"\s+", " ", match.group(1)).strip()
    return proto + ";"


def collect_matched(summaries: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for summary in summaries:
        if summary.exists():
            rows.extend(row for row in iter_rows(summary) if is_exportable_match(row))
    return dedupe_best_matches(rows)


def collect_ghidra(facts: Path | None) -> list[dict[str, Any]]:
    if not facts or not facts.exists():
        return []
    rows = []
    for row in iter_rows(facts):
        if row.get("entityKind") not in {None, "function"} and row.get("kind") not in {None, "function"}:
            # Accept both agentdecompile and Mizuchi fact shapes.
            if not row.get("decompiled"):
                continue
        if not row.get("decompiled"):
            continue
        status = row.get("decompilationStatus")
        if status and status != "complete":
            continue
        rows.append(row)
    return rows


def prefetch_matched_sources(
    rows: Iterable[dict[str, Any]],
    *,
    workers: int | None = None,
) -> dict[str, str]:
    """Resolve match source text, reading only legacy path-only rows in parallel."""

    material = list(rows)
    out: dict[str, str] = {}
    legacy_rows: list[dict[str, Any]] = []
    for row in material:
        key = match_source_key(row)
        if row.get("sourceText") is not None:
            out[key] = resolve_match_source_text(row)
        else:
            legacy_rows.append(row)

    def _read(row: dict[str, Any]) -> tuple[str, str | None]:
        try:
            return match_source_key(row), resolve_match_source_text(row)
        except (OSError, FileNotFoundError):
            return match_source_key(row), None

    count = resolve_workers(workers)
    if count == 1 or len(legacy_rows) == 1:
        for row in legacy_rows:
            key, text = _read(row)
            if text is not None:
                out[key] = text
        return out

    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(_read, row) for row in legacy_rows]
        for future in as_completed(futures):
            key, text = future.result()
            if text is not None:
                out[key] = text
    return out


def match_source_key(row: dict[str, Any]) -> str:
    """Stable key for associating prefetched text with a match receipt."""

    return "|".join(
        (
            str(row.get("entry") or ""),
            str(row.get("name") or ""),
            str(row.get("source") or ""),
        )
    )


def parse_dump_layers(raw: str | Iterable[str] | None) -> set[str]:
    """Parse dump layer set. Empty/None → all layers."""

    if raw is None:
        return {"verified", "port", "advisory"}
    if isinstance(raw, str):
        parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    else:
        parts = [str(p).strip().lower() for p in raw if str(p).strip()]
    if not parts:
        return {"verified", "port", "advisory"}
    allowed = {"verified", "port", "advisory"}
    selected = {p for p in parts if p in allowed}
    return selected or allowed


def dump_source_tree(
    *,
    out_dir: Path,
    summaries: list[Path],
    ghidra_facts: Path | None = None,
    advisory_dir: Path | None = None,
    target_name: str = "binary",
    reference_root: Path | None = None,
    clean: bool = True,
    layers: str | Iterable[str] | None = None,
    profile: str = "binary",
    module_hints: dict[str, dict[str, Any]] | None = None,
    curated_hints: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write verified/ + advisory/ghidra/ + Port/CODE + README/MANIFEST/CLAIMS.

    `curated_hints` is the `{entryHex: {"locals": [...], "plateComment": ...}}`
    shape from `curated_enrichment.curated_hints_to_json` -- when present for
    an entry, curated parameter names are substituted for `param_N`-style
    Ghidra identifiers in that function's emitted body and prototype, and a
    curated Plate/EOL/Pre comment is added as a header line. Entries with no
    curated hint are emitted exactly as before.
    """

    from .module_resolver import passes_readability_gate

    selected_layers = parse_dump_layers(layers)
    write_verified = "verified" in selected_layers
    write_port = "port" in selected_layers
    write_advisory = "advisory" in selected_layers
    hints = module_hints or {}
    curated = curated_hints or {}

    matched = collect_matched(summaries)
    ghidra_rows = collect_ghidra(ghidra_facts) if write_advisory else []
    # Prefer explicit facts JSONL when present. Re-reading advisory_dir on top of
    # the same facts double-counts units and produces nested banners / double-
    # prefixed filenames (entry_entry_FUN_…).
    if write_advisory and advisory_dir and advisory_dir.is_dir() and not ghidra_rows:
        for path in sorted(advisory_dir.glob("**/*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            stem = path.stem
            entry = ""
            name = stem
            entry_m = re.search(r"entry=([0-9a-fA-F]+)", text)
            name_m = re.search(r"\b(FUN_[0-9a-fA-F]+)\b", text)
            if entry_m:
                entry = normalize_entry_hex(entry_m.group(1))
            elif "_" in stem:
                entry = normalize_entry_hex(stem.split("_", 1)[0])
            if name_m:
                name = name_m.group(1)
            elif entry and stem.startswith(f"{entry}_"):
                name = stem[len(entry) + 1 :]
            ghidra_rows.append(
                {
                    "name": name,
                    "entry": entry or stem,
                    "decompiled": text,
                    "decompilationStatus": "complete",
                    "entityKind": "function",
                    "tool": "advisory-dir",
                }
            )

    # One advisory unit per entry — last write wins only after preferring facts.
    deduped_ghidra: dict[str, dict[str, Any]] = {}
    for row in ghidra_rows:
        entry = normalize_entry_hex(row.get("entryOffset") or row.get("entry") or 0)
        if not entry:
            continue
        row = {**row, "entry": entry, "entryOffset": entry}
        deduped_ghidra[entry] = row
    ghidra_rows = list(deduped_ghidra.values())

    # Build into a sibling temp dir and swap on success, so a mid-build crash
    # never destroys the previous good dump (destroy-before-write hazard).
    final_dir = out_dir
    build_dir = out_dir.parent / f".{out_dir.name}.build-{os.getpid()}"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if not clean and final_dir.exists():
        # Merge mode: seed the build from the existing dump, then overlay new output.
        shutil.copytree(final_dir, build_dir)
    else:
        build_dir.mkdir(parents=True, exist_ok=True)

    code = build_dir / "Port" / "CODE"
    verified_dir = build_dir / "verified"
    advisory_out = build_dir / "advisory" / "ghidra"
    for module in DEFAULT_MODULES:
        (code / module / "include").mkdir(parents=True, exist_ok=True)
    (code / "include").mkdir(parents=True, exist_ok=True)
    verified_dir.mkdir(parents=True, exist_ok=True)
    advisory_out.mkdir(parents=True, exist_ok=True)

    pending = PendingWrites()
    source_texts = prefetch_matched_sources(matched)

    buckets: dict[tuple[str, str], list[tuple[dict[str, Any], str]]] = defaultdict(list)
    rejected_emitters = 0
    verified_count = 0
    code_slice_count = 0
    readability_excluded = 0
    named_count = 0
    module_resolved_count = 0

    for row in matched:
        source = source_texts.get(match_source_key(row))
        if source is None:
            continue
        if looks_like_byte_emitter(source, row):
            rejected_emitters += 1
            continue
        entry = str(row.get("entry") or "")
        kind = str(row.get("kind") or row.get("rule") or "")
        authority = authority_label(row)
        hint = hints.get(normalize_entry_hex(entry)) or {}
        module = str(hint.get("module") or module_for_entry(entry, kind, profile=profile))
        module_provenance = str(hint.get("moduleProvenance") or "fallback")
        stem = file_stem_for(kind, authority, rule=str(row.get("rule") or ""))
        styled = style_c_source(source)
        curated_row = curated.get(normalize_entry_hex(entry)) or {}
        curated_locals = curated_row.get("locals") or []
        if curated_locals:
            styled, _ = clean_source_text(styled, {"locals": curated_locals})
        header_lines = [
            f"/* {row.get('name')} entry={entry} kind={kind}",
            f" * Authority: {authority} ({claim_boundary_for(row)}).",
            f" * ModuleProvenance: {module_provenance}",
        ]
        if curated_row.get("plateComment"):
            header_lines.append(f" * Comment: {curated_row['plateComment']}")
        header_lines.extend([" */", ""])
        header = "\n".join(header_lines)
        body = header + styled
        if write_port:
            buckets[(module, stem)].append((row, body))

        # Per-function verified shard (objdiff 0 full-object only).
        if write_verified and authority == "objdiff-matched":
            verified_count += 1
            shard = verified_dir / f"{entry}_{row.get('name')}.c"
            pending.add(shard, body)
        elif write_verified and authority == "code-slice-matched":
            code_slice_count += 1
            shard = verified_dir / "code-slice" / f"{entry}_{row.get('name')}.c"
            pending.add(shard, body.replace("Authority:", "Authority (code-slice):", 1))

    verified_entries = {
        normalize_entry_hex(m.get("entry")) for m in matched if is_proven_zero(m)
    }
    for row in ghidra_rows:
        entry = normalize_entry_hex(row.get("entryOffset") or row.get("entry") or 0)
        # Skip if already verified for this entry (compare normalized hex on both sides).
        if entry in verified_entries:
            continue
        decompiled = style_c_source(str(row["decompiled"]))
        hint = hints.get(entry) or {}
        module = str(hint.get("module") or module_for_entry(entry, "ghidra", profile=profile))
        module_provenance = str(hint.get("moduleProvenance") or "fallback")
        name = str(row.get("name") or f"FUN_{entry}")
        if not str(name).startswith("FUN_"):
            named_count += 1
        if module_provenance not in {"fallback", ""} and module != "recovered/unmapped":
            module_resolved_count += 1
        stem = file_stem_for("ghidra", "ghidra-advisory")
        curated_row = curated.get(entry) or {}
        curated_locals = curated_row.get("locals") or []
        prototype = row.get("prototype")
        if curated_locals:
            decompiled, _ = clean_source_text(decompiled, {"locals": curated_locals})
            if prototype:
                prototype, _ = clean_source_text(str(prototype), {"locals": curated_locals})
        header_lines = [
            f"/* {name} entry={entry} bodyBytes={row.get('bodyBytes')}",
            " * Authority: Ghidra / agentdecompile-cli advisory — NOT objdiff-matched.",
            f" * Prototype: {prototype}",
            f" * ModuleProvenance: {module_provenance}",
        ]
        if curated_row.get("plateComment"):
            header_lines.append(f" * Comment: {curated_row['plateComment']}")
        header_lines.extend([" * claimBoundary: readability only.", " */", ""])
        header = "\n".join(header_lines)
        body = header + decompiled
        if write_port:
            if not passes_readability_gate(
                name=name, module=module, module_provenance=module_provenance
            ):
                readability_excluded += 1
            else:
                buckets[(module, stem)].append((row, body))
        adv_path = advisory_out / f"{entry}_{name}.c"
        pending.add(adv_path, body)

    if not write_port:
        buckets.clear()

    manifest_functions: list[dict[str, Any]] = []
    written_files: list[str] = []
    for (module, stem), items in sorted(buckets.items()):
        cpp_rel = Path(module) / f"{stem}.cpp"
        hdr_name = f"{stem}.h"
        hdr_rel = Path(module) / "include" / hdr_name
        prototypes: list[str] = []
        bodies: list[str] = []
        for row, body in items:
            bodies.append(body.rstrip() + "\n")
            proto = prototype_from_source(body)
            if proto:
                prototypes.append(proto)
            name = str(row.get("name"))
            entry = str(row.get("entry") or f"{int(row.get('entryOffset') or 0):08x}")
            authority = authority_label(row) if row.get("status") else "ghidra-advisory"
            if row.get("decompiled") and not is_exportable_match(row):
                authority = "ghidra-advisory"
            manifest_functions.append(
                {
                    "name": name,
                    "entry": entry,
                    "module": module,
                    "source": str(cpp_rel),
                    "authority": authority,
                    "kind": row.get("kind") or row.get("rule") or row.get("tool"),
                    "sourceQuality": row.get("sourceQuality"),
                }
            )
        authorities = {
            mf["authority"]
            for mf in manifest_functions
            if mf["module"] == module and Path(mf["source"]).stem == stem
        }
        has_verified = bool(authorities & {"objdiff-matched", "code-slice-matched"})
        has_advisory = "ghidra-advisory" in authorities
        banner = [
            f" * Module: {module}/{stem}",
            f" * Target: {target_name}",
            " * Style: recovered Port/CODE layout",
        ]
        if has_verified:
            banner.append(" * Matched units: objdiff differences == 0")
        if has_advisory:
            banner.append(" * Ghidra units: readability only, not byte-matched")
        pending.add(
            code / hdr_rel,
            render_header(hdr_name, prototypes, banner + [f" * Header for {stem}.cpp"]),
        )
        pending.add(
            code / cpp_rel,
            render_cpp_module(banner, bodies, f"include/{hdr_name}"),
        )
        written_files.extend([str(cpp_rel), str(hdr_rel)])

    ref = reference_root
    ghidra_count = sum(1 for f in manifest_functions if f["authority"] == "ghidra-advisory")
    matched_count = sum(1 for f in manifest_functions if f["authority"] == "objdiff-matched")
    slice_count = sum(1 for f in manifest_functions if f["authority"] == "code-slice-matched")

    pending.add(
        build_dir / "README.md",
        "\n".join(
            [
                f"# {target_name} recovered source dump",
                "",
                "How to read claim layers:",
                "",
                "1. **verified/** — objdiff `differences==0` only (full-object under root; code-slice under `verified/code-slice/`).",
                "2. **advisory/ghidra/** — Ghidra / `agentdecompile-cli` C — pretty, **not** proof.",
                "3. **Port/CODE/** — Port/CODE-shaped modules for reading; authority still follows the layers above.",
                "",
                "Never treat byte-emitters / `_emit` / full-binary packages as original-dev C.",
                "",
                f"- Full-object matched: {matched_count}",
                f"- Code-slice matched: {slice_count}",
                f"- Ghidra advisory: {ghidra_count}",
                f"- Rejected byte-emitters: {rejected_emitters}",
                f"- Reference tree: `{ref}`",
                "",
            ]
        ),
    )
    pending.add(
        build_dir / "CLAIMS.md",
        "\n".join(
            [
                "# Explicit non-claims",
                "",
                "- This dump is **not** whole-EXE original-dev parity.",
                "- Advisory Ghidra C is **not** matched until compile+objdiff reports 0.",
                "- Byte-emission / `.incbin` / full-binary emitters are **never** promoted to `verified/`.",
                "- Ladder metrics (1% / 5% / 20% of inventoried functions) remain the honesty gate.",
                "",
            ]
        ),
    )
    pending.add(
        code / "BOREALIS_LAYOUT.md",
        "\n".join(
            [
                "# Layout correspondence",
                "",
                "Module paths are evidence-ranked (assert/RTTI/callgraph); optional VA bands are operator-supplied.",
                f"Compare with `{ref}/Port/CODE`.",
                "",
            ]
        ),
    )

    repair_summary = None
    if ghidra_facts is not None:
        facts_path = Path(ghidra_facts)
        work_dir_guess = facts_path.parent.parent if facts_path.parent.name == "facts" else facts_path.parent
        from .readability_repair import load_repair_queue_summary

        repair_summary = load_repair_queue_summary(work_dir_guess)

    manifest = {
        "schema": "agentdecompile.source-dump.v1",
        "status": "complete",
        "outDir": str(final_dir),
        "codeRoot": str(final_dir / "Port" / "CODE"),
        "verifiedDir": str(final_dir / "verified"),
        "advisoryDir": str(final_dir / "advisory" / "ghidra"),
        "matchedSummaries": [str(p) for p in summaries],
        "ghidraFacts": str(ghidra_facts) if ghidra_facts else None,
        "functionCount": len(manifest_functions),
        "matchedCount": matched_count,
        "codeSliceMatchedCount": slice_count,
        "ghidraCount": ghidra_count,
        "rejectedByteEmitters": rejected_emitters,
        "verifiedShardCount": verified_count,
        "codeSliceShardCount": code_slice_count,
        "profile": profile,
        "namedCount": named_count,
        "moduleResolvedCount": module_resolved_count,
        "readabilityExcludedFromPort": readability_excluded,
        "readabilityThreshold": {
            "requiresNonFunName": True,
            "requiresNonFallbackModule": True,
            "advisoryOnly": True,
        },
        **({"readabilityRepairQueue": repair_summary} if repair_summary else {}),
        "layers": sorted(selected_layers),
        "files": written_files,
        "functions": manifest_functions,
        "claimBoundary": (
            "objdiff-matched units are full-object verified C. "
            "code-slice-matched units reproduce the target function code slice at objdiff zero. "
            "Ghidra units are advisory. This is not whole-program rebuild parity. "
            "Readability metrics (namedCount / moduleResolvedCount) are advisory and do not inflate proof."
        ),
    }
    pending.add(
        build_dir / "MANIFEST.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )

    pending.format_c_like_files()
    pending.flush()

    # Atomic-ish swap: only remove the prior good dump once the new build is complete.
    if final_dir.exists():
        shutil.rmtree(final_dir)
    build_dir.rename(final_dir)
    return manifest
