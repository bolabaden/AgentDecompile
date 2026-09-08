"""Run the corpus pipeline in contract order.

Default stop is `compile`, which aliases to `recover-source`: snapshot C
compiled in-process. Cross-place of source happens only after that. Byte
accuracy is last and is a separate property. corpus.run does not subprocess
ghidra-bulk.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .callgraph import build_call_graph
from .compile_link import compile_unit, find_c_compiler, link_executable
from .contract import CLAIM_BOUNDARY, SCHEMA, resolve_stage, stages_through
from .ghidra_sanitize import compile_preamble, sanitize_body
from .identity import bind_identities, propagate_compiling_source
from .io import read_json, write_json
from .llm_cleanup import cleanup_ghidra_c, function_identifier, program_path_for_row
from .naming import choose_name, resolve_members
from .registry import CorpusManifest
from .source_claims import is_recovered_source
from .ui import probe_live_ui, write_ui_receipt
from .workspace import fill_function, write_skeleton


def load_function_snapshot(corpus: CorpusManifest, snapshot_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Each binary may have `{id}.functions.json` listing extracted functions."""
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in corpus.binaries:
        if entry.exclude:
            out[entry.id] = []
            continue
        path = snapshot_dir / f"{entry.id}.functions.json"
        if path.is_file():
            rows = read_json(path)
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


def write_calibrate_global_receipt(
    work_dir: Path,
    *,
    db: Path | None = None,
    types_header: Path | None = None,
    compiler_profile: Path | None = None,
) -> dict[str, Any]:
    """Compose compiler/types fragments. Never start Wine.

    Missing fragment → state=partial. Fragment exception → state=error.
    Empty types header → partial with types=missing. An existing compiler
    profile file is reused as-is.
    """
    from .io import write_json as _write

    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    dest = work_dir / "calibrate-global.json"
    gaps: list[str] = []
    errors: list[str] = []
    fragments: dict[str, Any] = {}
    compiler: dict[str, Any] = {"state": "missing"}
    types: dict[str, Any] | str = {"state": "missing"}

    profile_hits = []
    if compiler_profile is not None and Path(compiler_profile).is_file():
        profile_hits.append(Path(compiler_profile))
    for cand in (
        work_dir / "compiler-profile.json",
        work_dir / "compiler-profile-corpus.json",
        work_dir / "compiler-profile-artifacts.json",
    ):
        if cand.is_file():
            profile_hits.append(cand)
    if profile_hits:
        compiler = {"state": "present", "path": str(profile_hits[0])}
        fragments["compiler-profile-corpus"] = {"state": "present", "path": str(profile_hits[0])}
    else:
        gaps.append("compiler")
        fragments["compiler-profile-corpus"] = {"state": "missing"}

    header = Path(types_header) if types_header is not None else work_dir / "ghidra_types.h"
    if header.is_file() and header.stat().st_size > 0:
        types = {"state": "present", "path": str(header), "bytes": header.stat().st_size}
        fragments["build-types-header"] = {"state": "present", "path": str(header)}
        fragments["export-types"] = {"state": "present", "source": "header-file"}
        fragments["propagate"] = {"state": "skipped", "reason": "header-file"}
    elif db is not None and Path(db).is_file():
        try:
            from .build_types_header import build_header
            from .export_types import SCHEMA, export as export_types
            from .propagate_types import apply_adoptions, plan_adoptions
            from .store import connect

            con = connect(Path(db))
            con.executescript(SCHEMA)
            existing = int(con.execute("SELECT COUNT(*) FROM ghidra_type").fetchone()[0])
            if existing:
                fragments["export-types"] = {"state": "present", "rows": existing}
            else:
                repos = [
                    str(row[0])
                    for row in con.execute("SELECT repo_path FROM binary")
                    if row[0]
                ]
                if not repos:
                    fragments["export-types"] = {"state": "missing", "reason": "no-binary"}
                else:
                    # Never boot Ghidra from this receipt. Live export is a
                    # separate catalog job; here we only reuse store rows.
                    stats = export_types(repos[0], con, start=lambda: False)
                    fragments["export-types"] = {
                        "state": "missing" if stats.get("reason") else "present",
                        **stats,
                    }
            try:
                plan = plan_adoptions(con)
                adopted = apply_adoptions(con, plan.get("adopted") or [])
                fragments["propagate"] = {
                    "state": "present",
                    "adopted": adopted,
                    "stats": plan.get("stats") or {},
                }
            except Exception as exc:  # noqa: BLE001 — receipt must name the fragment
                errors.append(f"propagate:{exc}")
                fragments["propagate"] = {"state": "error", "error": str(exc)}

            row = con.execute("SELECT id FROM binary ORDER BY id LIMIT 1").fetchone()
            if row is None:
                types = "missing"
                gaps.append("types")
                fragments["build-types-header"] = {"state": "missing", "reason": "no-binary"}
            else:
                built = build_header(con, int(row["id"]), header)
                if built.get("types"):
                    types = {"state": "present", "path": str(header), **built}
                    fragments["build-types-header"] = {"state": "present", "path": str(header)}
                else:
                    types = "missing"
                    gaps.append("types")
                    fragments["build-types-header"] = {"state": "missing"}
        except Exception as exc:  # noqa: BLE001 — receipt must name the fragment
            errors.append(f"types:{exc}")
            types = {"state": "error", "error": str(exc)}
            fragments.setdefault("build-types-header", {"state": "error", "error": str(exc)})
    else:
        types = "missing"
        gaps.append("types")
        fragments["export-types"] = {"state": "missing", "reason": "no-db"}
        fragments["propagate"] = {"state": "missing", "reason": "no-db"}
        fragments["build-types-header"] = {"state": "missing", "reason": "no-db"}

    if errors:
        state = "error"
    elif gaps:
        state = "partial"
    else:
        state = "done"

    receipt: dict[str, Any] = {
        "state": state,
        "compiler": compiler,
        "types": types,
        "gaps": gaps,
        "errors": errors,
        "fragments": fragments,
        "wineStarted": False,
    }
    _write(dest, receipt)
    return receipt


def _compile_snapshot_c(
    functions: dict[str, list[dict[str, Any]]],
    *,
    donor,
    corpus: CorpusManifest,
    work_dir: Path,
    workspace: Path,
    cc: str | None,
    llm: bool,
    llm_model: str | None,
    llm_runner: Any,
    get_function_runner: Any,
) -> tuple[dict[str, Any], set[str]]:
    compiled_ids: set[str] = set()
    objects: list[Path] = []
    build_dir = work_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    compile_rows: list[dict[str, Any]] = []
    if not cc:
        return {"ok": False, "reason": "no C compiler on PATH", "completeExecutable": False}, compiled_ids
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
    return {
        "ok": bool(link.get("ok")),
        "units": compile_rows,
        "compiledCount": len(compiled_ids),
        "llmAttempted": sum(1 for u in compile_rows if u.get("llmAttempted")),
        "llmKept": sum(1 for u in compile_rows if u.get("llmCleanup") and u.get("ok")),
        "link": link,
        "completeExecutable": bool(link.get("ok")),
    }, compiled_ids


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
    db: Path | None = None,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    receipts: dict[str, Any] = {}
    planned = stages_through(resolve_stage(stop_after) if stop_after else None)
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
        write_json(work_dir / "extract.json", receipts["extract"])

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
        receipts["identify"] = {
            "bindings": len(bindings),
            "rows": bindings,
            "named": sum(1 for rows in functions.values() for r in rows if r.get("name")),
        }
        write_json(work_dir / "identify.json", receipts["identify"])

    if "calibrate-global" in planned:
        receipts["calibrate-global"] = write_calibrate_global_receipt(work_dir, db=db)
        write_json(work_dir / "calibrate-global.json", receipts["calibrate-global"])

    if "assembly-floor" in planned:
        donor_rows = functions.get(donor.id, []) if donor else []
        skeleton = write_skeleton(workspace, donor_rows)
        receipts["assembly-floor"] = skeleton
        write_json(work_dir / "assembly-floor.json", skeleton)

    compile_receipt: dict[str, Any] = {}
    if "recover-source" in planned:
        recovered = recover_units(functions)
        preparsed = preparse_units(functions, known_globals=corpus.known_globals)
        cc = compiler or find_c_compiler()
        compile_receipt, compiled_ids = _compile_snapshot_c(
            functions,
            donor=donor,
            corpus=corpus,
            work_dir=work_dir,
            workspace=workspace,
            cc=cc,
            llm=llm,
            llm_model=llm_model,
            llm_runner=llm_runner,
            get_function_runner=get_function_runner,
        )
        receipts["recover-source"] = {
            **recovered,
            "preparse": preparsed,
            "compile": {
                "compiledCount": compile_receipt.get("compiledCount", 0),
                "completeExecutable": compile_receipt.get("completeExecutable"),
                "link": compile_receipt.get("link"),
                "llmAttempted": compile_receipt.get("llmAttempted", 0),
                "llmKept": compile_receipt.get("llmKept", 0),
            },
        }
        write_json(work_dir / "recover-source.json", receipts["recover-source"])

    if "apply-cross-build" in planned:
        placements = propagate_compiling_source(functions, bindings, compiled_ids)
        receipts["apply-cross-build"] = {"placements": placements, "count": len(placements)}
        write_json(work_dir / "apply-cross-build.json", receipts["apply-cross-build"])

    if "leftover-recover" in planned:
        leftover = [
            {"binary": bid, "id": row.get("id"), "name": row.get("name")}
            for bid, rows in functions.items()
            for row in rows
            if row.get("source_claim") == "recovered" and str(row.get("id")) not in compiled_ids
        ]
        llm_ran = bool(llm) and bool(compiler or find_c_compiler()) and "recover-source" in planned
        receipts["leftover-recover"] = {
            "queued": leftover,
            "count": len(leftover),
            "ran": llm_ran,
            "attempted": compile_receipt.get("llmAttempted", 0),
            "kept": compile_receipt.get("llmKept", 0),
            "reason": (
                "LLM edited leftover Ghidra C after snapshot C compile failed. "
                "Edits are kept only if the compiler then accepts them."
                if llm_ran
                else "Pass --llm (and have a C compiler) to edit leftover Ghidra C with the local claude CLI."
            ),
        }
        write_json(work_dir / "leftover-recover.json", receipts["leftover-recover"])

    if "verify-byte-accuracy" in planned:
        receipts["verify-byte-accuracy"] = {
            "status": "not-run" if not compile_receipt.get("completeExecutable") else "pending-compare",
            "realC": receipts.get("recover-source", {}),
            "byteAccuracy": None,
            "claimBoundary": (
                "Byte-accuracy is independent of compile success. This receipt "
                "does not invent a match."
            ),
        }
        write_json(work_dir / "verify-byte-accuracy.json", receipts["verify-byte-accuracy"])

    graph = build_call_graph(functions, bindings)
    write_json(work_dir / "call-graph.json", graph)

    summary = {
        "schema": SCHEMA,
        "corpusId": corpus.id,
        "stagesRun": list(planned),
        "receipts": {key: _summarize(value) for key, value in receipts.items()},
        "completeExecutable": bool(compile_receipt.get("completeExecutable")),
        "ui": {key: val.get("ok") for key, val in ui.items() if isinstance(val, dict)},
        "claimBoundary": CLAIM_BOUNDARY,
        "priority": "compile-complete-executable",
    }
    write_json(work_dir / "corpus-run.json", summary)
    write_json(work_dir / "functions-state.json", functions)
    return summary


def _summarize(value: Any) -> Any:
    if isinstance(value, dict):
        skip = {"rows", "units", "placements", "queued"}
        return {k: (len(v) if k in skip and isinstance(v, list) else v) for k, v in value.items() if k not in skip}
    return value
