"""Borealis-shaped source dump with verified vs advisory claim layers."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .match_cache import is_proven_zero
from .source_cleanup import format_source_text
from .source_export import (
    claim_boundary_for,
    dedupe_best_matches,
    is_exportable_match,
    iter_rows,
    source_path_for,
)


BOREALIS_MODULES = (
    "game/clientcore",
    "game/servercore",
    "game/swmain",
    "libsource/exobase",
    "libsource/nwscript",
    "libsource/AURORA",
    "libsource/recovered",
)

BYTE_EMITTER_MARKERS = (
    "__asm",
    "_emit",
    ".byte",
    "incbin",
    "BYTE_EMIT",
    "nonsemantic-bootstrap",
)


def borealis_brace_style(source: str) -> str:
    """Move opening braces to their own line for function definitions (Borealis style)."""

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


def format_c_source(source: str) -> str:
    styled = borealis_brace_style(source)
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
    return any(marker.lower() in lowered for marker in BYTE_EMITTER_MARKERS)


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


def module_for_entry(entry: str, kind: str | None) -> str:
    try:
        addr = int(entry, 16)
    except (TypeError, ValueError):
        return "libsource/recovered"
    kind = (kind or "").lower()
    if "thunk" in kind or "reloc" in kind or "wrapper" in kind:
        return "libsource/recovered"
    if addr < 0x00480000:
        return "game/swmain"
    if addr < 0x00500000:
        return "game/clientcore"
    if addr < 0x00600000:
        return "libsource/AURORA"
    if addr < 0x00680000:
        return "libsource/nwscript"
    if addr < 0x00700000:
        return "game/servercore"
    return "libsource/exobase"


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


def write_cpp_module(path: Path, banner: list[str], bodies: list[str], header_include: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    chunks = ["/*", *banner, " */", "", f'#include "{header_include}"', "", *bodies]
    path.write_text("\n".join(chunks).rstrip() + "\n", encoding="utf-8")


def write_header(path: Path, prototypes: list[str], banner: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    guard = re.sub(r"[^A-Z0-9]", "_", path.name.upper())
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
    path.write_text("\n".join(chunks), encoding="utf-8")


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


def dump_source_tree(
    *,
    out_dir: Path,
    summaries: list[Path],
    ghidra_facts: Path | None = None,
    advisory_dir: Path | None = None,
    target_name: str = "swkotor.exe",
    borealis_reference: Path | None = None,
    clean: bool = True,
) -> dict[str, Any]:
    """Write verified/ + advisory/ghidra/ + Port/CODE + README/MANIFEST/CLAIMS."""

    matched = collect_matched(summaries)
    ghidra_rows = collect_ghidra(ghidra_facts)
    if advisory_dir and advisory_dir.is_dir():
        for path in sorted(advisory_dir.glob("**/*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            ghidra_rows.append(
                {
                    "name": path.stem,
                    "entry": path.stem.split("_")[0] if "_" in path.stem else path.stem,
                    "decompiled": text,
                    "decompilationStatus": "complete",
                    "entityKind": "function",
                    "tool": "advisory-dir",
                }
            )

    # Build into a sibling temp dir and swap on success, so a mid-build crash
    # never destroys the previous good dump (destroy-before-write hazard).
    final_dir = out_dir
    build_dir = out_dir.parent / f".{out_dir.name}.build-{os.getpid()}"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if not clean and final_dir.exists():
        # Merge mode: seed the build from the existing dump, then overlay new output.
        shutil.copytree(final_dir, build_dir)
    out_dir = build_dir
    code = out_dir / "Port" / "CODE"
    verified_dir = out_dir / "verified"
    advisory_out = out_dir / "advisory" / "ghidra"
    for module in BOREALIS_MODULES:
        (code / module / "include").mkdir(parents=True, exist_ok=True)
    (code / "include").mkdir(parents=True, exist_ok=True)
    verified_dir.mkdir(parents=True, exist_ok=True)
    advisory_out.mkdir(parents=True, exist_ok=True)

    buckets: dict[tuple[str, str], list[tuple[dict[str, Any], str]]] = defaultdict(list)
    rejected_emitters = 0
    verified_count = 0
    code_slice_count = 0

    for row in matched:
        try:
            source = source_path_for(row).read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            continue
        if looks_like_byte_emitter(source, row):
            rejected_emitters += 1
            continue
        entry = str(row.get("entry") or "")
        kind = str(row.get("kind") or row.get("rule") or "")
        authority = authority_label(row)
        module = module_for_entry(entry, kind)
        stem = file_stem_for(kind, authority, rule=str(row.get("rule") or ""))
        formatted = format_c_source(source)
        header = "\n".join(
            [
                f"/* {row.get('name')} entry={entry} kind={kind}",
                f" * Authority: {authority} ({claim_boundary_for(row)}).",
                " */",
                "",
            ]
        )
        body = header + formatted
        buckets[(module, stem)].append((row, body))

        # Per-function verified shard (objdiff 0 full-object only).
        if authority == "objdiff-matched":
            verified_count += 1
            shard = verified_dir / f"{entry}_{row.get('name')}.c"
            shard.write_text(body, encoding="utf-8")
        elif authority == "code-slice-matched":
            code_slice_count += 1
            shard = verified_dir / "code-slice" / f"{entry}_{row.get('name')}.c"
            shard.parent.mkdir(parents=True, exist_ok=True)
            shard.write_text(
                body.replace("Authority:", "Authority (code-slice):", 1),
                encoding="utf-8",
            )

    verified_entries = {
        normalize_entry_hex(m.get("entry")) for m in matched if is_proven_zero(m)
    }
    for row in ghidra_rows:
        entry = normalize_entry_hex(row.get("entryOffset") or row.get("entry") or 0)
        # Skip if already verified for this entry (compare normalized hex on both sides).
        if entry in verified_entries:
            continue
        decompiled = format_c_source(str(row["decompiled"]))
        module = module_for_entry(entry, "ghidra")
        stem = file_stem_for("ghidra", "ghidra-advisory")
        header = "\n".join(
            [
                f"/* {row.get('name')} entry={entry} bodyBytes={row.get('bodyBytes')}",
                " * Authority: Ghidra / agentdecompile-cli advisory — NOT objdiff-matched.",
                f" * Prototype: {row.get('prototype')}",
                " * claimBoundary: readability only.",
                " */",
                "",
            ]
        )
        body = header + decompiled
        buckets[(module, stem)].append((row, body))
        adv_path = advisory_out / f"{entry}_{row.get('name')}.c"
        adv_path.write_text(body, encoding="utf-8")

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
        authorities = {mf["authority"] for mf in manifest_functions if mf["module"] == module and Path(mf["source"]).stem == stem}
        has_verified = bool(authorities & {"objdiff-matched", "code-slice-matched"})
        has_advisory = "ghidra-advisory" in authorities
        banner = [
            f" * Module: {module}/{stem}",
            f" * Target: {target_name}",
            " * Style: Project Borealis / Odyssey Port/CODE layout",
        ]
        if has_verified:
            banner.append(" * Matched units: objdiff differences == 0")
        if has_advisory:
            banner.append(" * Ghidra units: readability only, not byte-matched")
        write_header(code / hdr_rel, prototypes, banner + [f" * Header for {stem}.cpp"])
        write_cpp_module(code / cpp_rel, banner, bodies, f"include/{hdr_name}")
        written_files.extend([str(cpp_rel), str(hdr_rel)])

    ref = borealis_reference or (Path.home() / "Desktop/ProjectBorealisJune4th")
    ghidra_count = sum(1 for f in manifest_functions if f["authority"] == "ghidra-advisory")
    matched_count = sum(1 for f in manifest_functions if f["authority"] == "objdiff-matched")
    slice_count = sum(1 for f in manifest_functions if f["authority"] == "code-slice-matched")

    (out_dir / "README.md").write_text(
        "\n".join(
            [
                f"# {target_name} recovered source dump",
                "",
                "How to read claim layers:",
                "",
                "1. **verified/** — objdiff `differences==0` only (full-object under root; code-slice under `verified/code-slice/`).",
                "2. **advisory/ghidra/** — Ghidra / `agentdecompile-cli` C — pretty, **not** proof.",
                "3. **Port/CODE/** — Borealis-shaped modules for reading; authority still follows the layers above.",
                "",
                "Never treat byte-emitters / `_emit` / full-binary packages as original-dev C.",
                "",
                f"- Full-object matched: {matched_count}",
                f"- Code-slice matched: {slice_count}",
                f"- Ghidra advisory: {ghidra_count}",
                f"- Rejected byte-emitters: {rejected_emitters}",
                f"- Borealis reference: `{ref}`",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (out_dir / "CLAIMS.md").write_text(
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
        encoding="utf-8",
    )
    (code / "BOREALIS_LAYOUT.md").write_text(
        "\n".join(
            [
                "# Layout correspondence",
                "",
                "Address banding into Borealis modules is heuristic (no PDB).",
                f"Compare with `{ref}/Port/CODE`.",
                "",
            ]
        ),
        encoding="utf-8",
    )

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
        "files": written_files,
        "functions": manifest_functions,
        "claimBoundary": (
            "objdiff-matched units are full-object verified C. "
            "code-slice-matched units reproduce the target function code slice at objdiff zero. "
            "Ghidra units are advisory. This is not whole-program rebuild parity."
        ),
    }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Atomic-ish swap: only remove the prior good dump once the new build is complete.
    if final_dir.exists():
        shutil.rmtree(final_dir)
    build_dir.rename(final_dir)
    return manifest
