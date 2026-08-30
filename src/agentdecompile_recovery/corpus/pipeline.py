"""Run the corpus pipeline in contract order.

Default stop is `compile`: priority 1 is a complete linked executable from
the STABS/DWARF donor project. Cross-match of source happens only after
units compile. Byte-accuracy is last and is a separate property.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .callgraph import build_call_graph
from .compile_link import compile_unit, find_c_compiler, link_executable
from .contract import CLAIM_BOUNDARY, SCHEMA, stages_through
from .ghidra_sanitize import compile_preamble, sanitize_body
from .identity import bind_identities, propagate_compiling_source
from .llm_cleanup import cleanup_ghidra_c, function_identifier, program_path_for_row
from .naming import choose_name, resolve_members
from .registry import CorpusManifest
from .source_claims import is_recovered_source
from .ui import probe_live_ui, write_ui_receipt
from .workspace import fill_function, write_skeleton


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_function_snapshot(corpus: CorpusManifest, snapshot_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Each binary may have `{id}.functions.json` listing extracted functions."""
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in corpus.binaries:
        if entry.exclude:
            out[entry.id] = []
            continue
        path = snapshot_dir / f"{entry.id}.functions.json"
        if path.is_file():
            rows = _read_json(path)
            out[entry.id] = list(rows) if isinstance(rows, list) else list(rows.get("functions") or [])
        else:
            out[entry.id] = []
    return out


def merge_names(functions_by_binary: dict[str, list[dict[str, Any]]]) -> None:
    for rows in functions_by_binary.values():
        for row in rows:
            name, tier = choose_name(
                row.get("name"),
                row.get("name_tier"),
                row.get("incoming_name"),
                str(row.get("incoming_tier") or "ghidra"),
            )
            row["name"] = name
            row["name_tier"] = tier


def recover_units(functions_by_binary: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Keep Ghidra C that is real source. Do not preparse here."""
    accepted = 0
    rejected = 0
    for rows in functions_by_binary.values():
        for row in rows:
            raw = row.get("source") or row.get("body") or ""
            if not is_recovered_source(raw):
                row["source_claim"] = "not-source"
                rejected += 1
                continue
            row["source"] = raw
            row["source_claim"] = "recovered"
            accepted += 1
    return {"accepted": accepted, "rejectedShimsOrEmpty": rejected}


def preparse_units(
    functions_by_binary: dict[str, list[dict[str, Any]]],
    *,
    known_globals: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Mechanical Ghidra-C cleanup. Measured helpers only. Not an LLM."""
    cleaned = 0
    for rows in functions_by_binary.values():
        for row in rows:
            if row.get("source_claim") != "recovered":
                continue
            body = sanitize_body(row.get("source") or "")
            row["source"] = body
            row["preamble"] = compile_preamble(known_globals=known_globals, body=body)
            cleaned += 1
    return {"cleaned": cleaned}


def run_corpus_pipeline(
    corpus: CorpusManifest,
    *,
    work_dir: Path,
    snapshot_dir: Path,
    stop_after: str = "compile",
    compiler: str | None = None,
    llm: bool = False,
    llm_model: str | None = None,
    llm_runner: Any | None = None,
    get_function_runner: Any | None = None,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    receipts: dict[str, Any] = {}
    planned = stages_through(stop_after)
    functions = load_function_snapshot(corpus, snapshot_dir)
    compiled_ids: set[str] = set()
    bindings: list[dict[str, Any]] = []
    ui = probe_live_ui(
        dashboard_port=corpus.dashboard_port,
        atlas_port=corpus.atlas_port,
        report_port=corpus.report_port,
    )
    write_ui_receipt(work_dir / "ui-health.json", ui)

    donor = corpus.donor()
    workspace = work_dir / "workspace"
    if "extract" in planned:
        extracted = {bid: len(rows) for bid, rows in functions.items()}
        receipts["extract"] = {
            "functions": extracted,
            "total": sum(extracted.values()),
        }
        _write_json(work_dir / "extract.json", receipts["extract"])

    if "identify" in planned:
        thresholds = {}
        for pair in corpus.pair_thresholds:
            thresholds[(pair.left, pair.right)] = pair.min_confidence
        metas = {
            entry.id: {
                "arch": entry.arch,
                "bits": entry.bits,
                "format": entry.format,
                "game": entry.game,
            }
            for entry in corpus.binaries
        }
        bindings = bind_identities(functions, thresholds=thresholds, metas=metas)
        receipts["identify"] = {"bindings": len(bindings), "rows": bindings}
        _write_json(work_dir / "identify.json", receipts["identify"])

    if "merge-knowledge" in planned:
        merge_names(functions)
        by_logical: dict[str, list] = {}
        for rows in functions.values():
            for row in rows:
                key = str(row.get("logical_id") or row.get("name") or "")
                if key:
                    by_logical.setdefault(key, []).append(row)
        for members in by_logical.values():
            if len(members) < 2:
                continue
            won = resolve_members(members)
            if won.get("name"):
                for row in members:
                    row["name"], row["name_tier"] = won["name"], won["tier"]
        receipts["merge-knowledge"] = {"named": sum(1 for rows in functions.values() for r in rows if r.get("name"))}
        _write_json(work_dir / "merge-knowledge.json", receipts["merge-knowledge"])

    if "generate-projects" in planned:
        donor_rows = functions.get(donor.id, []) if donor else []
        skeleton = write_skeleton(workspace, donor_rows)
        receipts["generate-projects"] = skeleton
        _write_json(work_dir / "generate-projects.json", skeleton)

    if "recover-source" in planned:
        receipts["recover-source"] = recover_units(functions)
        _write_json(work_dir / "recover-source.json", receipts["recover-source"])

    if "preparse" in planned:
        receipts["preparse"] = preparse_units(functions, known_globals=corpus.known_globals)
        _write_json(work_dir / "preparse.json", receipts["preparse"])

    objects: list[Path] = []
    cc = compiler or find_c_compiler()
    build_dir = work_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)

    if "compile" in planned:
        compile_rows: list[dict[str, Any]] = []
        if not cc:
            receipts["compile"] = {"ok": False, "reason": "no C compiler on PATH"}
        else:
            for binary_id, rows in functions.items():
                is_donor = donor is not None and binary_id == donor.id
                for row in rows:
                    body = row.get("source") or row.get("body") or ""
                    if row.get("source_claim") != "recovered":
                        continue
                    name = str(row.get("id") or row.get("name") or "fn")
                    src = build_dir / f"{binary_id}_{name}.c"
                    text = (row.get("preamble") or "") + "\n" + body.rstrip() + "\n"
                    src.write_text(text, encoding="utf-8")
                    obj = build_dir / f"{binary_id}_{name}.o"
                    result = compile_unit(cc, src, obj)
                    if (not result["ok"]) and llm:
                        ident = function_identifier(row, fallback=name)
                        try:
                            prog = program_path_for_row(row, fallback=corpus.binary(binary_id).path)
                        except KeyError:
                            prog = program_path_for_row(row)
                        supplied = str(row.get("get_function") or row.get("getFunction") or "")
                        edited = cleanup_ghidra_c(
                            body=body,
                            errors=str(result.get("stderr") or ""),
                            header=row.get("preamble") or "",
                            get_function=supplied or None,
                            program_path=prog,
                            identifier=ident,
                            model=llm_model,
                            runner=llm_runner,
                            get_function_runner=get_function_runner,
                        )
                        result["llmAttempted"] = True
                        result["llmReason"] = edited.get("reason")
                        if edited.get("ok") and edited.get("source"):
                            body = edited["source"]
                            row["source"] = body
                            row["llm_cleanup"] = True
                            src.write_text((row.get("preamble") or "") + "\n" + body.rstrip() + "\n", encoding="utf-8")
                            result = compile_unit(cc, src, obj)
                            result["llmCleanup"] = True
                            result["llmAttempted"] = True
                    compile_rows.append({"id": row.get("id"), "binary": binary_id, **result})
                    if result["ok"]:
                        compiled_ids.add(str(row.get("id")))
                        if is_donor:
                            objects.append(obj)
                        src_file = str(row.get("source_file") or row.get("sourceFile") or "")
                        if src_file:
                            fill_function(workspace, src_file, str(row.get("id")), body)
            exe = work_dir / "linked" / ((donor.id if donor else corpus.id) + ".recovered")
            link = link_executable(cc, objects, exe) if objects else {"ok": False, "reason": "no donor objects"}
            receipts["compile"] = {
                "units": compile_rows,
                "compiledCount": len(compiled_ids),
                "llmAttempted": sum(1 for u in compile_rows if u.get("llmAttempted")),
                "llmKept": sum(1 for u in compile_rows if u.get("llmCleanup") and u.get("ok")),
                "link": link,
                "completeExecutable": bool(link.get("ok")),
            }
        _write_json(work_dir / "compile.json", receipts["compile"])

    if "apply-cross-build" in planned:
        placements = propagate_compiling_source(functions, bindings, compiled_ids)
        receipts["apply-cross-build"] = {"placements": placements, "count": len(placements)}
        _write_json(work_dir / "apply-cross-build.json", receipts["apply-cross-build"])

    if "llm-cleanup" in planned:
        leftover = [
            {"binary": bid, "id": row.get("id"), "name": row.get("name")}
            for bid, rows in functions.items()
            for row in rows
            if row.get("source_claim") == "recovered" and str(row.get("id")) not in compiled_ids
        ]
        llm_ran = bool(llm) and bool(cc) and "compile" in planned
        receipts["llm-cleanup"] = {
            "queued": leftover,
            "count": len(leftover),
            "ran": llm_ran,
            "attempted": (receipts.get("compile") or {}).get("llmAttempted", 0),
            "kept": (receipts.get("compile") or {}).get("llmKept", 0),
            "reason": (
                "LLM edited leftover Ghidra C after preparse+compile failed. "
                "Edits are kept only if the compiler then accepts them."
                if llm_ran
                else "Pass --llm (and have a C compiler) to edit leftover Ghidra C with the local claude CLI."
            ),
        }
        _write_json(work_dir / "llm-cleanup.json", receipts["llm-cleanup"])

    if "verify-byte-accuracy" in planned:
        receipts["verify-byte-accuracy"] = {
            "status": "not-run" if not receipts.get("compile", {}).get("completeExecutable") else "pending-compare",
            "realC": receipts.get("recover-source", {}),
            "byteAccuracy": None,
            "claimBoundary": (
                "Byte-accuracy is independent of compile success. This receipt "
                "does not invent a match."
            ),
        }
        _write_json(work_dir / "verify-byte-accuracy.json", receipts["verify-byte-accuracy"])

    graph = build_call_graph(functions, bindings)
    _write_json(work_dir / "call-graph.json", graph)

    summary = {
        "schema": SCHEMA,
        "corpusId": corpus.id,
        "stagesRun": list(planned),
        "receipts": {key: _summarize(value) for key, value in receipts.items()},
        "completeExecutable": bool((receipts.get("compile") or {}).get("completeExecutable")),
        "ui": {key: val.get("ok") for key, val in ui.items() if isinstance(val, dict)},
        "claimBoundary": CLAIM_BOUNDARY,
        "priority": "compile-complete-executable",
    }
    _write_json(work_dir / "corpus-run.json", summary)
    _write_json(work_dir / "functions-state.json", functions)
    return summary


def _summarize(value: Any) -> Any:
    if isinstance(value, dict):
        skip = {"rows", "units", "placements", "queued"}
        return {k: (len(v) if k in skip and isinstance(v, list) else v) for k, v in value.items() if k not in skip}
    return value
