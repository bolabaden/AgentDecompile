"""CLI for the corpus-wide semantic decompilation pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .archive import check_extraction, list_archive, summarize_entries
from .contract import STAGE_ALIASES, stages_catalog, resolve_stage
from .pipeline import run_corpus_pipeline, write_calibrate_global_receipt
from .registry import add_binary, load_corpus, new_corpus, save_corpus


def run_list_archive_command(args: argparse.Namespace) -> int:
    archive: Path = args.archive
    if not archive.is_file():
        print(f"error: {archive} is not a file", file=sys.stderr)
        return 1

    entries = list(list_archive(archive))
    if getattr(args, "output_json", False):
        summary = summarize_entries(archive, entries)
        shown = [e.to_json() for e in entries if not (args.files_only and e.is_dir)]
        print(json.dumps({"summary": summary.to_json(), "entries": shown}, indent=2))
        return 0
    total_files = 0
    total_uncompressed = 0
    for entry in entries:
        if entry.is_dir and args.files_only:
            continue
        kind_tag = f"  [{entry.ghidra_kind}]" if entry.ghidra_kind else ""
        if entry.is_dir:
            print(f"         -  {entry.name.rstrip('/')}/{kind_tag}")
        else:
            print(f"  {entry.file_size:>12,}  {entry.name}{kind_tag}")
            total_files += 1
            total_uncompressed += entry.file_size
    print(f"\n  {total_uncompressed:>12,}  {total_files} files")
    return 0


def run_check_extraction_command(args: argparse.Namespace) -> int:
    archive: Path = args.archive
    directory: Path = args.directory
    if not archive.is_file():
        print(f"error: {archive} is not a file", file=sys.stderr)
        return 1
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 1

    report = check_extraction(archive, directory, check_extra=not args.no_extra)
    if getattr(args, "output_json", False):
        print(json.dumps(report.to_json(), indent=2))
    else:
        print(f"archive:   {archive}")
        print(f"directory: {directory}")
        print(f"status:    {report.status}")
        if report.missing:
            print(f"\nmissing ({len(report.missing)}):")
            for name in report.missing:
                print(f"  {name}")
        if report.size_mismatch:
            print(f"\nsize mismatch ({len(report.size_mismatch)}):")
            for item in report.size_mismatch:
                print(f"  {item['path']}  expected={item['expectedBytes']}  actual={item['actualBytes']}")
        if report.extra:
            print(f"\nextra ({len(report.extra)}):")
            for name in report.extra:
                print(f"  {name}")
        if report.is_complete:
            print("\nExtraction is complete.")
    return 0 if report.is_complete else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentdecompile-corpus",
        description=(
            "Corpus-wide semantic decompilation. First priority is linking one "
            "STABS/DWARF donor project to a complete executable. Adding a binary "
            "is a registry action, not a rewrite."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="Create an empty corpus file")
    init.add_argument("--id", required=True, dest="corpus_id")
    init.add_argument("--out", type=Path, required=True)

    add = sub.add_parser("add-binary", help="Register another binary in the corpus")
    add.add_argument("--corpus", type=Path, required=True)
    add.add_argument("--id", required=True, dest="binary_id")
    add.add_argument("--path", required=True)
    add.add_argument("--debug", choices=("stabs", "dwarf", "none"), default="none")
    add.add_argument("--donor", action="store_true", help="Use this binary for STABS/DWARF layout")
    add.add_argument("--label", default="")
    add.add_argument("--threshold-with", dest="threshold_with", help="Other binary id for a pair threshold")
    add.add_argument("--min-confidence", type=float, default=0.55)
    add.add_argument("--arch", default="")
    add.add_argument("--bits", type=int, default=0)
    add.add_argument("--format", dest="file_format", default="")
    add.add_argument("--game", default="")

    rmbin = sub.add_parser(
        "remove-binary",
        help="Delete one binary and its per-binary rows from a store",
    )
    rmbin.add_argument("--db", type=Path, required=True)
    rmbin.add_argument("--repo", dest="repo_path")
    rmbin.add_argument("--slug")

    stabs = sub.add_parser("extract-stabs", help="Read Mach-O STABS into a functions snapshot")
    stabs.add_argument("--binary", type=Path, required=True)
    stabs.add_argument("--id", required=True, dest="binary_id")
    stabs.add_argument("--out-dir", type=Path, required=True)

    run = sub.add_parser("run", help="Run pipeline stages in contract order")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    run.add_argument("--snapshot-dir", type=Path, required=True, help="Directory of {id}.functions.json extracts")
    run.add_argument(
        "--stop-after",
        default="compile",
        help=(
            "Last stage to run. Live names or aliases "
            f"({', '.join(f'{k}->{v}' for k, v in STAGE_ALIASES.items())}). "
            "Default compile aliases to recover-source."
        ),
    )
    run.add_argument("--compiler", default=None)
    run.add_argument(
        "--llm",
        action="store_true",
        help=(
            "After preparse+compile still fail, edit that Ghidra C with the local "
            "claude CLI and retry once. The model is given `agentdecompile-cli get-function` output."
        ),
    )
    run.add_argument("--llm-model", default=None, help="Optional claude --model for cleanup")

    sub.add_parser("stages", help="Print the contract stages and priorities")

    list_archive = sub.add_parser("list-archive", help="List a corpus ZIP without extracting it")
    list_archive.add_argument("archive", type=Path)
    list_archive.add_argument("--json", action="store_true", dest="output_json")
    list_archive.add_argument("--files-only", action="store_true")

    check_extraction = sub.add_parser(
        "check-extraction",
        help="Compare an extracted directory against its source archive",
    )
    check_extraction.add_argument("archive", type=Path)
    check_extraction.add_argument("directory", type=Path)
    check_extraction.add_argument("--no-extra", action="store_true")
    check_extraction.add_argument("--json", action="store_true", dest="output_json")

    init_store = sub.add_parser("init-store", help="Create an empty identity SQLite store")
    init_store.add_argument("--db", type=Path, required=True)

    write_snap = sub.add_parser("write-snapshot", help="Write {id}.functions.json from a JSON array")
    write_snap.add_argument("--id", required=True, dest="binary_id")
    write_snap.add_argument("--from-json", type=Path, required=True)
    write_snap.add_argument("--out-dir", type=Path, required=True)

    apply_stabs = sub.add_parser("apply-stabs", help="Apply a reviewed STABS manifest to a store")
    apply_stabs.add_argument("--db", type=Path, required=True)
    apply_stabs.add_argument("--binary-id", type=int, required=True)
    apply_stabs.add_argument("--manifest", type=Path, required=True)

    prop = sub.add_parser("propagate-source", help="Carry source_file across logical identities")
    prop.add_argument("--db", type=Path, required=True)

    ev = sub.add_parser("evaluate-pair", help="Measure matcher vs unique-name ground truth")
    ev.add_argument("--db", type=Path, required=True)
    ev.add_argument("--src", required=True)
    ev.add_argument("--dst", required=True)
    ev.add_argument("--mode", choices=("engine", "fid"), default="engine")

    sib = sub.add_parser("export-siblings", help="Export same-class method-name conflicts")
    sib.add_argument("--db", type=Path, required=True)
    sib.add_argument("--out", type=Path, required=True)

    hookpack = sub.add_parser(
        "export-hookpack",
        aliases=["export-hook-pack"],
        help="Write a Phasor-shaped hook pack from logical identities (VA is a cache)",
    )
    hookpack.add_argument("--db", type=Path, required=True)
    hookpack.add_argument("--out", type=Path, required=True)

    match_pair = sub.add_parser("match-pair", help="Run the store matcher on one directed pair")
    match_pair.add_argument("--db", type=Path, required=True)
    match_pair.add_argument("--src", required=True)
    match_pair.add_argument("--dst", required=True)
    match_pair.add_argument("--run", default="v1")
    match_pair.add_argument("--note", default="")

    logical_build = sub.add_parser("logical-build", help="Rebuild name-first logical identities")
    logical_build.add_argument("--db", type=Path, required=True)

    pkg = sub.add_parser("package", help="Copy a workspace tree to an output directory")
    pkg.add_argument("--workspace", type=Path, required=True)
    pkg.add_argument("--out", type=Path, required=True)

    cal = sub.add_parser("calibrate", help="Sweep score/margin from an evaluation JSON list")
    cal.add_argument("--from-json", type=Path, required=True)
    cal.add_argument("--out", type=Path, required=True)

    calg = sub.add_parser(
        "calibrate-global",
        help="Write compiler/ABI/types calibration receipt (not matcher score sweep)",
    )
    calg.add_argument("--work-dir", type=Path, required=True)
    calg.add_argument("--db", type=Path)
    calg.add_argument("--types-header", type=Path)
    calg.add_argument("--compiler-profile", type=Path)

    merge_parts = sub.add_parser("merge-parts", help="Merge per-program part databases into one store")
    merge_parts.add_argument("--parts-dir", type=Path, required=True)
    merge_parts.add_argument("--db", type=Path, required=True)

    stabs_rep = sub.add_parser("stabs-report", help="Write STABS JSON + markdown for one Mach-O")
    stabs_rep.add_argument("--binary", type=Path, required=True)
    stabs_rep.add_argument("--out", type=Path, required=True)

    genp = sub.add_parser("genproject", help="Write a prompt project from the logical-function queue")
    genp.add_argument("--queue", type=Path, required=True)
    genp.add_argument("--out", type=Path, required=True)
    genp.add_argument("--db", type=Path, required=True)
    genp.add_argument("--raw", type=Path, required=True)
    genp.add_argument("--repo-path", required=True)
    genp.add_argument("--limit", type=int, default=25)
    genp.add_argument("--max-size", type=int, default=256)
    genp.add_argument("--min-size", type=int, default=4)
    genp.add_argument("--base-project", type=Path)
    genp.add_argument("--mkobj", type=Path)
    genp.add_argument("--coverage-ledger", type=Path)
    genp.add_argument("--skip-manifests", nargs="*", action="extend", default=[], type=Path)
    genp.add_argument("--skip-recovered", action="store_true")
    genp.add_argument("--leftover-only", action="store_true", default=True)
    genp.add_argument("--all-queue", dest="leftover_only", action="store_false")

    ingest_rec = sub.add_parser("ingest-recovered", help="Bind recovered C to existing identities")
    ingest_rec.add_argument("--db", type=Path, required=True)
    ingest_rec.add_argument("--recovered-dir", type=Path, required=True)
    ingest_rec.add_argument("--coverage-dir", type=Path, required=True)
    ingest_rec.add_argument("--out-dir", type=Path, required=True)
    ingest_rec.add_argument("--seed-results", type=Path)
    ingest_rec.add_argument("--reuse-candidates", type=Path)
    ingest_rec.add_argument("--force", action="store_true")
    ingest_rec.add_argument("--report", action="store_true")

    export_rr = sub.add_parser("export-run-report", help="Write aggregated recovered_function run results")
    export_rr.add_argument("--db", type=Path, required=True)
    export_rr.add_argument("--out", type=Path, required=True)

    gurl = sub.add_parser("ghidra-url", help="Print the Ghidra URL for a repo path")
    gurl.add_argument("path")

    apply_ann = sub.add_parser("apply-annotations", help="Apply jsonl names to a Ghidra program (dry-run default)")
    apply_ann.add_argument("jsonl", type=Path)
    apply_ann.add_argument("--program", required=True)
    apply_ann.add_argument("--min-confidence", type=float, default=0.95)
    apply_ann.add_argument("--status", default="auto")
    apply_ann.add_argument("--apply", action="store_true")
    apply_ann.add_argument("--no-comments", action="store_true")

    bulk = sub.add_parser("ghidra-bulk", help="Normalize + compile Ghidra decompiled C")
    bulk.add_argument("--program", required=True)
    bulk.add_argument("--repo", required=True)
    bulk.add_argument("--db", type=Path, required=True)
    bulk.add_argument("--out-dir", type=Path, required=True)
    bulk.add_argument("--kb", type=Path, required=True)
    bulk.add_argument("--mode", choices=("compile-only", "semantic"), default="compile-only")
    bulk.add_argument("--compiler", type=Path)
    bulk.add_argument("--sample", type=int)
    bulk.add_argument("--workers", type=int, default=2)
    bulk.add_argument("--write", action="store_true", default=True)
    bulk.add_argument("--no-write", dest="write", action="store_false")
    bulk.add_argument("--skip-existing", action="store_true", default=True)
    bulk.add_argument("--force", dest="skip_existing", action="store_false")
    bulk.add_argument("--force-c-replace", action="store_true")
    bulk.add_argument("--llm-cleanup", action="store_true")
    bulk.add_argument("--llm-model")
    bulk.add_argument("--compile-complete", type=float, default=0.95)
    bulk.add_argument("--asm-fallback", action="store_true", default=True)
    bulk.add_argument("--no-asm-fallback", dest="asm_fallback", action="store_false")
    bulk.add_argument("--extract-raw", type=Path)

    workspace = sub.add_parser(
        "workspace",
        help="Write STABS folders and fill each compiling function as its own TU",
    )
    workspace.add_argument("--db", type=Path, required=True)
    workspace.add_argument("--donor-slug", required=True)
    workspace.add_argument("--out", type=Path, required=True)
    workspace.add_argument("--fill-from", help="program id or repo_path to read addresses from")
    workspace.add_argument("--src-dir", type=Path, help="ghidra-bulk recovered-source tree")

    clink = sub.add_parser(
        "compile-link",
        help="Compile workspace units and link one executable (not byte-accuracy)",
    )
    clink.add_argument("--src-dir", type=Path, required=True)
    clink.add_argument("--out", type=Path, required=True)
    clink.add_argument("--compiler", type=Path)
    clink.add_argument("--sample", type=int)
    clink.add_argument("--obj-dir", type=Path)
    clink.add_argument("--workers", type=int, default=2)
    clink.add_argument("--no-entrypoint", dest="entrypoint", action="store_false")

    xplace = sub.add_parser("cross-place", help="Copy compiling C onto bound sibling binaries")
    xplace.add_argument("--from", dest="program", required=True)
    xplace.add_argument("--db", type=Path, required=True)
    xplace.add_argument("--out-dir", type=Path, required=True)
    xplace.add_argument("--repo", required=True)
    xplace.add_argument("--watch", action="store_true")
    xplace.add_argument("--interval", type=float, default=8.0)

    from . import kx_cli

    kx_cli.register(sub)
    from . import mizuchi_tools_cli

    mizuchi_tools_cli.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "init":
        save_corpus(args.out, new_corpus(args.corpus_id))
        print(args.out)
        return 0
    if args.cmd == "remove-binary":
        from .store import connect, remove_binary

        if not args.repo_path and not args.slug:
            print("error: --repo or --slug is required", file=sys.stderr)
            return 2
        print(json.dumps(remove_binary(connect(args.db), repo_path=args.repo_path, slug=args.slug), indent=2))
        return 0
    if args.cmd == "add-binary":
        corpus = load_corpus(args.corpus)
        add_binary(
            corpus,
            binary_id=args.binary_id,
            path=args.path,
            debug=args.debug,
            donor=args.donor,
            label=args.label,
            arch=args.arch,
            bits=args.bits,
            format=args.file_format,
            game=args.game,
        )
        if args.threshold_with:
            from .registry import PairThreshold

            corpus.pair_thresholds.append(
                PairThreshold(left=args.binary_id, right=args.threshold_with, min_confidence=args.min_confidence)
            )
        save_corpus(args.corpus, corpus)
        print(json.dumps({"binaries": [b.id for b in corpus.binaries], "donorId": corpus.donor_id}))
        return 0
    if args.cmd == "extract-stabs":
        from .machostabs import analyze

        report = analyze(args.binary)
        functions = []
        for sl in report.get("slices") or []:
            stabs = sl.get("stabs") or {}
            for fn in stabs.get("functions") or []:
                functions.append(
                    {
                        "id": f"0x{fn.get('addr') or 0:x}",
                        "addr": fn.get("addr"),
                        "name": fn.get("name"),
                        "stabs_name": fn.get("name"),
                        "source_file": fn.get("source_file"),
                        "object_file": fn.get("object_file"),
                        "size": fn.get("size"),
                        "name_origin": "stabs",
                        "strings": [],
                        "consts": [],
                        "ext_calls": [],
                        "mnem": {},
                        "callees": [],
                    }
                )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        dest = args.out_dir / f"{args.binary_id}.functions.json"
        dest.write_text(json.dumps(functions, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"wrote": str(dest), "functions": len(functions), "slices": len(report.get("slices") or [])}))
        return 0
    if args.cmd == "run":
        try:
            stop_after = resolve_stage(args.stop_after)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        corpus = load_corpus(args.corpus)
        summary = run_corpus_pipeline(
            corpus,
            work_dir=args.work_dir,
            snapshot_dir=args.snapshot_dir,
            stop_after=stop_after,
            compiler=args.compiler,
            llm=bool(args.llm),
            llm_model=args.llm_model,
        )
        print(json.dumps(summary, indent=2))
        if stop_after == "recover-source" and not summary.get("completeExecutable"):
            return 2
        return 0
    if args.cmd == "stages":
        print(json.dumps(stages_catalog(), indent=2))
        return 0
    if args.cmd == "calibrate-global":
        if args.db is None and args.work_dir is None:
            print("error: --work-dir is required", file=sys.stderr)
            return 2
        receipt = write_calibrate_global_receipt(
            args.work_dir,
            db=args.db,
            types_header=args.types_header,
            compiler_profile=args.compiler_profile,
        )
        print(json.dumps(receipt, indent=2))
        return 0 if receipt.get("state") != "error" else 1
    if args.cmd == "list-archive":
        return run_list_archive_command(args)
    if args.cmd == "check-extraction":
        return run_check_extraction_command(args)
    if args.cmd == "init-store":
        from .store import connect

        connect(args.db).close()
        print(args.db)
        return 0
    if args.cmd == "write-snapshot":
        from .extract import write_snapshot
        from .io import read_json

        rows = read_json(args.from_json)
        functions = list(rows) if isinstance(rows, list) else list(rows.get("functions") or [])
        dest = write_snapshot(args.out_dir, args.binary_id, functions)
        print(json.dumps({"wrote": str(dest), "functions": len(functions)}))
        return 0
    if args.cmd == "apply-stabs":
        from .stabs_link import apply_manifest_records, ensure_columns
        from .store import connect

        records = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line]
        con = connect(args.db)
        ensure_columns(con)
        n = apply_manifest_records(con, args.binary_id, records)
        print(json.dumps({"applied": n}))
        return 0
    if args.cmd == "propagate-source":
        from .stabs_link import ensure_columns, propagate_source_files
        from .store import connect

        con = connect(args.db)
        ensure_columns(con)
        print(json.dumps({"pushed": propagate_source_files(con)}))
        return 0
    if args.cmd == "evaluate-pair":
        from .evaluate import evaluate
        from .store import connect

        print(json.dumps(evaluate(connect(args.db), args.src, args.dst, mode=args.mode), indent=2))
        return 0
    if args.cmd == "export-siblings":
        from .sibling_conflicts import export_sibling_conflicts
        from .store import connect

        print(json.dumps(export_sibling_conflicts(connect(args.db), args.out)))
        return 0
    if args.cmd in {"export-hookpack", "export-hook-pack"}:
        from .export_hookpack import export_hookpack
        from .store import connect

        print(json.dumps(export_hookpack(connect(args.db), args.out)))
        return 0
    if args.cmd == "match-pair":
        from .propagate import run_pair
        from .store import connect

        print(json.dumps(run_pair(connect(args.db), args.src, args.dst, args.note, args.run), indent=2))
        return 0
    if args.cmd == "logical-build":
        from .logical import build
        from .store import connect

        print(json.dumps(build(connect(args.db))))
        return 0
    if args.cmd == "package":
        from .package_project import package_project

        print(json.dumps(package_project(args.workspace, args.out)))
        return 0
    if args.cmd == "calibrate":
        from .calibrate import calibrate_evaluations
        from .io import read_json, write_json

        payload = read_json(args.from_json)
        write_json(args.out, calibrate_evaluations(list(payload)))
        print(args.out)
        return 0
    if args.cmd == "merge-parts":
        from .merge import merge_parts

        parts = sorted(
            p
            for p in args.parts_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".sqlite", ".db", ".sqlite3"}
        )
        print(json.dumps(merge_parts(parts, args.db), indent=2))
        return 0
    if args.cmd == "stabs-report":
        from .stabs_report import write_report

        print(json.dumps(write_report(args.binary, args.out), indent=2))
        return 0
    if args.cmd == "genproject":
        from .genproject import generate_project
        from .store import connect

        print(
            json.dumps(
                generate_project(
                    con=connect(args.db),
                    repo_path=args.repo_path,
                    out_dir=args.out,
                    queue_path=args.queue,
                    raw_path=args.raw,
                    limit=args.limit,
                    max_size=args.max_size,
                    min_size=args.min_size,
                    base_project=args.base_project,
                    mkobj=args.mkobj,
                    coverage_ledger=args.coverage_ledger,
                    skip_manifests=args.skip_manifests,
                    skip_recovered=args.skip_recovered,
                    leftover_only=args.leftover_only,
                ),
                indent=2,
            )
        )
        return 0
    if args.cmd == "ingest-recovered":
        from .ingest_recovered import ensure_recovered_schema, ingest, print_summary
        from .store import connect

        con = connect(args.db)
        ensure_recovered_schema(con)
        if args.report:
            print(json.dumps(print_summary(con, args.out_dir), indent=2))
            return 0
        print(
            json.dumps(
                ingest(
                    con,
                    recovered_dir=args.recovered_dir,
                    coverage_dir=args.coverage_dir,
                    out_dir=args.out_dir,
                    seed_results=args.seed_results,
                    reuse_candidates=args.reuse_candidates,
                    force=args.force,
                ),
                indent=2,
            )
        )
        return 0
    if args.cmd == "export-run-report":
        from .export_run_report import write_report

        report = write_report(args.db, args.out)
        print(json.dumps({"out": report["out"], "summary": report["summary"]}, indent=2))
        return 0
    if args.cmd == "ghidra-url":
        from .ghidra_url import ghidra_url

        print(ghidra_url(args.path))
        return 0
    if args.cmd == "apply-annotations":
        from .apply_annotations import apply_annotations

        print(
            json.dumps(
                apply_annotations(
                    args.jsonl,
                    args.program,
                    apply=args.apply,
                    min_confidence=args.min_confidence,
                    status=args.status,
                    comments=not args.no_comments,
                ),
                indent=2,
            )
        )
        return 0
    if args.cmd == "ghidra-bulk":
        from . import ghidra_bulk as gb

        bulk_argv = [
            "--program", args.program,
            "--repo", args.repo,
            "--db", str(args.db),
            "--out-dir", str(args.out_dir),
            "--kb", str(args.kb),
            "--mode", args.mode,
            "--compile-complete", str(args.compile_complete),
            "--workers", str(args.workers),
        ]
        if args.compiler:
            bulk_argv += ["--compiler", str(args.compiler)]
        if args.sample is not None:
            bulk_argv += ["--sample", str(args.sample)]
        if not args.write:
            bulk_argv.append("--no-write")
        if not args.skip_existing:
            bulk_argv.append("--force")
        if getattr(args, "force_c_replace", False):
            bulk_argv.append("--force-c-replace")
        if args.llm_cleanup:
            bulk_argv.append("--llm-cleanup")
        if args.llm_model:
            bulk_argv += ["--llm-model", args.llm_model]
        if not args.asm_fallback:
            bulk_argv.append("--no-asm-fallback")
        if args.extract_raw:
            bulk_argv += ["--extract-raw", str(args.extract_raw)]
        return gb.main(bulk_argv)
    if args.cmd == "workspace":
        from .store import connect
        from .workspace_skeleton import build_workspace

        if args.fill_from and args.src_dir is None:
            print("error: --src-dir is required with --fill-from", file=sys.stderr)
            return 2
        con = connect(args.db)
        stats = build_workspace(
            con,
            args.donor_slug,
            args.out,
            fill_from=args.fill_from,
            src_dir=args.src_dir,
        )
        print(json.dumps(stats, indent=2))
        return 0
    if args.cmd == "compile-link":
        from .compile_link import compile_and_link_tree

        result = compile_and_link_tree(
            args.src_dir,
            args.out,
            compiler=str(args.compiler) if args.compiler else None,
            sample=args.sample,
            obj_dir=args.obj_dir,
            workers=args.workers,
            entrypoint=getattr(args, "entrypoint", True),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    if args.cmd == "cross-place":
        from .cross_place import main as cross_main

        argv = [
            "--from", args.program,
            "--db", str(args.db),
            "--out-dir", str(args.out_dir),
            "--repo", args.repo,
        ]
        if args.watch:
            argv.append("--watch")
            argv += ["--interval", str(args.interval)]
        return cross_main(argv)
    from . import kx_cli

    code = kx_cli.dispatch(args)
    if code is not None:
        return code
    from . import mizuchi_tools_cli

    code = mizuchi_tools_cli.dispatch(args)
    if code is not None:
        return code
    return 2


if __name__ == "__main__":
    sys.exit(main())
