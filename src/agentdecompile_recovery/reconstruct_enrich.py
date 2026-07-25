"""Enrich-before-decompile for the default reconstruct path.

Reuses ``pyghidra_enrich`` / ``module_resolver`` so one-shot and reconstruct
share behavior. Soft-degrades when PyGhidra is unavailable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .module_resolver import ModuleResolver, load_va_bands, normalize_code_path
from .pyghidra_enrich import (
    PyGhidraEnrichProgram,
    build_names_by_entry,
    run_enrich_pipeline,
)
from .rtti_recover import (
    RttiClass,
    extract_assert_code_paths,
    extract_ghidra_rtti_classes,
    merge_rtti_classes,
    rtti_scan_receipt,
)
from .targets import sha256_file


SCHEMA = "agentdecompile.reconstruct-enrich.v1"


def analysis_binary_from_work_dir(work_dir: Path) -> Path | None:
    analysis_path = work_dir / "analysis-target.json"
    if not analysis_path.exists():
        return None
    try:
        payload = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = payload.get("analysisBinaryPath")
    if not raw:
        return None
    path = Path(str(raw))
    return path if path.is_file() else None


def boundaries_from_candidates(candidates_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Map reconstruct function-candidates into enrich boundary rows."""
    boundaries: list[dict[str, Any]] = []
    for row in candidates_payload.get("candidates") or []:
        raw = row.get("address")
        if raw is None:
            raw = row.get("rva")
        try:
            entry = int(raw)
        except (TypeError, ValueError):
            continue
        length = row.get("size") or row.get("length")
        try:
            length_i = int(length) if length not in (None, 0, "0") else None
        except (TypeError, ValueError):
            length_i = None
        boundaries.append(
            {
                "entry": entry,
                "length": length_i,
                "name": row.get("name"),
                "section": ((row.get("evidence") or {}).get("section")),
                "provenance": str(row.get("source") or "function-candidate"),
            }
        )
    return boundaries


def load_work_dir_va_bands(work_dir: Path) -> list[tuple[int, str]]:
    """Load optional PE VA band profile from work-dir metadata."""

    work_dir = work_dir.resolve()
    for path in (
        work_dir / "facts" / "pe-module-profile.json",
        work_dir / "target.json",
        work_dir / "analysis-target.json",
    ):
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        raw = payload.get("vaBands") or payload.get("va_bands") or payload.get("moduleVaBands")
        bands = load_va_bands(raw)
        if bands:
            return bands
    return []


def run_reconstruct_enrich(
    *,
    binary: Path,
    work_dir: Path,
    candidates_payload: dict[str, Any],
    skip: bool = False,
) -> dict[str, Any]:
    """Run enrich+module-map into ``work_dir/facts/``."""
    facts_dir = work_dir / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    facts_path = facts_dir / "function-facts.jsonl"
    module_map_path = facts_dir / "module-map.json"
    # Also mirror at work-dir root for legacy default_function_facts_path lookup.
    root_facts = work_dir / "function-facts.jsonl"

    if skip:
        receipt = {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "skip-enrichment",
            "claimBoundary": "enrichment skipped; decompiler facts may be absent or acquisition-supplied only",
        }
        (facts_dir / "enrich-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt

    boundaries = boundaries_from_candidates(candidates_payload)
    if not boundaries:
        receipt = {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "no-function-candidates",
            "claimBoundary": "enrichment skipped; no boundaries to decompile",
        }
        (facts_dir / "enrich-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt

    assert_paths = extract_assert_code_paths(binary)
    rtti = rtti_scan_receipt(binary)
    string_classes = [RttiClass(mangled=c["mangled"], name=c["name"], provenance=c.get("provenance") or "rtti-typeinfo") for c in rtti.get("classes") or []]
    rtti_classes = list(string_classes)

    from .symbol_provenance import ingest_symbol_provenance

    provenance_path = facts_dir / "symbol-provenance.json"
    if not provenance_path.is_file():
        ingest_symbol_provenance(work_dir, binary_path=binary)

    va_bands = load_work_dir_va_bands(work_dir)

    try:
        import pyghidra

        from .ghidra_analysis import resolve_project_name
    except Exception as exc:  # noqa: BLE001 - soft degrade without Ghidra
        receipt = {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "pyghidra-unavailable",
            "error": str(exc)[:500],
            "claimBoundary": "enrichment skipped; install Ghidra/PyGhidra for typed decompiles",
        }
        (facts_dir / "enrich-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt

    project_root = work_dir / "pyghidra-project"
    project_root.mkdir(parents=True, exist_ok=True)
    project_name = resolve_project_name(binary)
    resolver = ModuleResolver(va_bands=va_bands)
    discovered: list[dict[str, Any]] = []
    module_entries: dict[str, dict[str, Any]] = {}
    names_by_entry: dict[int, tuple[str, str]] = {}
    module_by_entry: dict[int, str] = {}
    summary: dict[str, Any]

    try:
        with pyghidra.open_program(
            binary,
            project_location=project_root,
            project_name=project_name,
            analyze=True,
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            function_manager = program.getFunctionManager()
            reference_manager = program.getReferenceManager()
            listing = program.getListing()
            for function in function_manager.getFunctions(True):
                body = function.getBody()
                discovered.append(
                    {
                        "entry": int(function.getEntryPoint().getOffset()),
                        "name": str(function.getName()),
                        "length": int(body.getNumAddresses()) if body is not None else None,
                    }
                )
            for data in listing.getDefinedData(True):
                try:
                    value = str(data.getValue() or "")
                except Exception:  # noqa: BLE001
                    continue
                lowered = value.lower()
                if not (
                    "/code/" in lowered
                    or "\\code\\" in lowered
                    or lowered.endswith((".cpp", ".c", ".cc", ".cxx", ".h", ".hpp"))
                ):
                    continue
                for reference in reference_manager.getReferencesTo(data.getAddress()):
                    function = function_manager.getFunctionContaining(reference.getFromAddress())
                    if function is None:
                        continue
                    entry = int(function.getEntryPoint().getOffset())
                    resolver.assert_paths_by_entry[entry] = value

            ghidra_classes = extract_ghidra_rtti_classes(program)
            rtti_classes = merge_rtti_classes(ghidra_classes, string_classes)

            names_by_entry = build_names_by_entry(
                discovered=discovered,
                rtti_classes=rtti_classes,
                corpus=None,
            )
            from .symbol_provenance import load_symbol_provenance_names

            for entry_hex, prov_name in load_symbol_provenance_names(work_dir).items():
                try:
                    entry = int(entry_hex, 16)
                except (TypeError, ValueError):
                    continue
                if entry not in names_by_entry:
                    names_by_entry[entry] = (prov_name, "symbol-provenance")
            # Prefer candidate names when Ghidra still has FUN_*.
            for row in boundaries:
                entry = int(row["entry"])
                name = str(row.get("name") or "")
                if name and not name.startswith("FUN_") and entry not in names_by_entry:
                    names_by_entry[entry] = (name, "function-candidate")

            for row in boundaries:
                entry = int(row["entry"])
                evidence = resolver.resolve(entry)
                module_by_entry[entry] = evidence.module
                module_entries[f"{entry:08x}"] = {
                    "module": evidence.module,
                    "moduleProvenance": evidence.provenance,
                    "score": evidence.score,
                }

            summary = run_enrich_pipeline(
                boundaries=boundaries,
                corpus=None,
                rtti_classes=rtti_classes,
                out_facts=facts_path,
                program_factory=lambda: PyGhidraEnrichProgram(flat_api),
                module_by_entry=module_by_entry,
                names_by_entry=names_by_entry,
            )
    except Exception as exc:  # noqa: BLE001 - soft degrade; reconstruct continues
        receipt = {
            "schema": SCHEMA,
            "status": "failed",
            "reason": "enrich-session-error",
            "error": str(exc)[:1000],
            "claimBoundary": "enrichment failed; recovery continues without typed decompiles",
        }
        (facts_dir / "enrich-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt

    if facts_path.exists():
        root_facts.write_text(facts_path.read_text(encoding="utf-8"), encoding="utf-8")

    rtti = {
        **rtti,
        "classCount": len(rtti_classes),
        "classes": [
            {"name": c.name, "mangled": c.mangled, "provenance": c.provenance} for c in rtti_classes
        ],
        "stringClassCount": len(string_classes),
        "ghidraMerged": True,
    }
    module_payload = {
        "schema": "agentdecompile.module-map.v1",
        "assertCodePaths": assert_paths,
        "normalizedAssertPaths": [normalize_code_path(p) for p in assert_paths],
        "entries": module_entries,
        "xrefMapped": len(resolver.assert_paths_by_entry),
        "vaBandCount": len(va_bands),
    }
    module_map_path.write_text(
        json.dumps(module_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (facts_dir / "rtti-scan.json").write_text(
        json.dumps(rtti, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    receipt = {
        "schema": SCHEMA,
        "status": "complete",
        "factsJsonl": str(facts_path),
        "moduleMap": str(module_map_path),
        "functionCount": summary.get("functionCount"),
        "namedCount": summary.get("namedCount"),
        "namesApplied": len(names_by_entry),
        "boundaryCount": len(boundaries),
        "assertPathCount": len(assert_paths),
        "rttiClassCount": len(rtti_classes),
        "analysisBinarySha256": sha256_file(binary),
        "ghidraProjectPath": str(project_root),
        "ghidraProjectName": project_name,
        "singleSession": True,
        "claimBoundary": "enrichment facts are advisory decompilation; objdiff 0 still required for verified/",
    }
    (facts_dir / "enrich-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if facts_path.exists():
        from .readability_repair import write_readability_repair_queue

        write_readability_repair_queue(work_dir)
    return receipt
