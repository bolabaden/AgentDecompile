"""Register and dispatch kx-derived corpus subcommands for AIO tooling.

Each entry mirrors a former ``kx/*.py`` script. Subparsers are registered on
``agentdecompile-corpus`` so the workbench action catalog can introspect them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KX_COMMANDS = frozenset({
    "export-atlas-db",
    "seed-validation",
    "harvest-shards",
    "verify-legacy-recovered",
    "permuter-harness",
    "recover-named-ghidra",
    "program-inventory",
    "work-queue",
    "report",
    "stabs-manifest",
    "export-bytes",
    "export-c",
    "export-types",
    "fix-func-counts",
    "bsim-eval",
    "bsim-createdatabase",
    "bsim-ingest",
    "bsim-report",
    "external-bridge",
    "build-project",
    "build-types-header",
    "propagate-corpus",
    "bind-identities",
    "reclassify-matches",
    "package-readable",
    "package-recovered",
    "package-readable-index",
})


def register(sub: argparse._SubParsersAction) -> None:
    """Add kx library subcommands to the corpus CLI parser."""

    atlas = sub.add_parser("export-atlas-db", help="Export identity store into an Atlas work tree")
    atlas.add_argument("--binary", required=True)
    atlas.add_argument("--db", type=Path, required=True)
    atlas.add_argument("--out-root", type=Path, required=True)
    atlas.add_argument("--knowledge-db", type=Path)
    atlas.add_argument("--max-functions", type=int)
    atlas.add_argument("--no-asm", action="store_true")
    atlas.add_argument("--no-c", action="store_true")

    seed = sub.add_parser("seed-validation", help="Audit seed recoveries against reuse candidates")
    seed.add_argument("--seeds-dir", type=Path, required=True)
    seed.add_argument("--candidates", type=Path, required=True)
    seed.add_argument("--reuse", type=Path, required=True)
    seed.add_argument("--results", type=Path, required=True)
    seed.add_argument("--summary", type=Path, required=True)
    seed.add_argument("--coverage-dir", type=Path)
    seed.add_argument("--compile", action="store_true")
    seed.add_argument("--retry-failed", action="store_true")

    harvest = sub.add_parser("harvest-shards", help="Collect permuter shard outputs into recovered tree")
    harvest.add_argument("patterns", nargs="+")
    harvest.add_argument("--program", required=True)
    harvest.add_argument("--recovered-dir", type=Path, required=True)
    harvest.add_argument("--coverage-dir", type=Path, required=True)
    harvest.add_argument("--attempts", type=Path, required=True)
    harvest.add_argument("--db", type=Path)
    harvest.add_argument("--binary-id", type=int)
    harvest.add_argument("--dry-run", action="store_true")

    legacy = sub.add_parser("verify-legacy-recovered", help="Verify legacy recovered projects byte-for-byte")
    legacy.add_argument("--recovered-dir", type=Path, required=True)
    legacy.add_argument("--projects-root", type=Path, required=True)
    legacy.add_argument("--projects-json", type=Path, required=True)
    legacy.add_argument("--results", type=Path, required=True)
    legacy.add_argument("--summary", type=Path, required=True)
    legacy.add_argument("--compiler", type=Path, required=True)
    legacy.add_argument("--raw-dir", type=Path, required=True)
    legacy.add_argument("--coverage-dir", type=Path)
    legacy.add_argument("--write-coverage", action="store_true")

    perm = sub.add_parser("permuter-harness", help="Sample permuter cases from the identity store")
    perm.add_argument("--per-band", type=int, default=3)
    perm.add_argument("--binaries", nargs="*")
    perm.add_argument("--compiler", default="vc71")
    perm.add_argument("--seconds", type=int, default=120)
    perm.add_argument("--db", type=Path, required=True)
    perm.add_argument("--out", type=Path, required=True)
    perm.add_argument("--work-dir", type=Path)
    perm.add_argument("--from-ghidra-bulk")
    perm.add_argument("--limit", type=int)

    rn = sub.add_parser("recover-named-ghidra", help="Recover named Ghidra C for unrecovered logicals")
    rn.add_argument("--limit", type=int, default=40)
    rn.add_argument("--min-size", type=int, default=16)
    rn.add_argument("--compiler", default="vc8")
    rn.add_argument("--permuter-seconds", type=int, default=0)
    rn.add_argument("--repo", required=True)
    rn.add_argument("--program")
    rn.add_argument("--db", type=Path, required=True)
    rn.add_argument("--out-dir", type=Path)
    rn.add_argument("--recovered-dir", type=Path)
    rn.add_argument("--results", default="")
    rn.add_argument("--replay-jsonl", default="")

    inv = sub.add_parser("program-inventory", help="Census Ghidra programs into inventory JSON")
    inv.add_argument("--out", type=Path, required=True)
    inv.add_argument("--programs-json", type=Path, help="JSON list of {path, version} records")

    wq = sub.add_parser("work-queue", help="Export logical-function work queue JSONL")
    wq.add_argument("--db", type=Path, required=True)
    wq.add_argument("--out-dir", type=Path, required=True)
    wq.add_argument("--arches", nargs="*", default=["x86"])

    rep = sub.add_parser("report", help="Regenerate markdown report fragments from the store")
    rep.add_argument("--db", type=Path, required=True)
    rep.add_argument("--out-dir", type=Path, required=True)
    rep.add_argument("--run", default="v1")

    sm = sub.add_parser("stabs-manifest", help="Dry-run STABS address manifest for one binary")
    sm.add_argument("repo_path")
    sm.add_argument("--db", type=Path, required=True)
    sm.add_argument("--raw-dir", type=Path, required=True)
    sm.add_argument("--out-dir", type=Path, required=True)

    eb = sub.add_parser("export-bytes", help="Recover on-disk FileBytes images via Ghidra")
    eb.add_argument("paths", nargs="+", help="repo paths to export")
    eb.add_argument("--out-dir", type=Path, required=True)

    ec = sub.add_parser("export-c", help="Export whole-program decompiled C via Ghidra")
    ec.add_argument("--repo-path", required=True)
    ec.add_argument("--out-dir", type=Path, required=True)
    ec.add_argument("--source-path")

    et = sub.add_parser("export-types", help="Export Ghidra struct/union/enum rows into the store")
    et.add_argument("--repo-path", required=True)
    et.add_argument("--db", type=Path, required=True)

    ffc = sub.add_parser("fix-func-counts", help="Audit code vs stub function counts")
    ffc.add_argument("--db", type=Path, required=True)
    ffc.add_argument("--out", type=Path, required=True)
    ffc.add_argument("--apply", action="store_true")

    bsim = sub.add_parser("bsim-eval", help="Measure Ghidra BSim against name ground truth")
    bsim.add_argument("--db", type=Path, required=True)
    bsim.add_argument("--bsim-url", required=True)
    bsim.add_argument("--out", type=Path, required=True)
    bsim.add_argument("--pairs-json", type=Path, help='JSON list of ["src","dst"] pairs')
    bsim.add_argument("--sample", type=int, default=400)

    bsim_create = sub.add_parser("bsim-createdatabase", help="Create a BSim database (bsim createdatabase)")
    bsim_create.add_argument("--bsim-url", help="postgresql://…/name or file:/dir/name")
    bsim_create.add_argument("--datadir", type=Path, help="BSimControl PostgreSQL data directory")
    bsim_create.add_argument("--name", default="bsim", help="Database name when URL is derived from --datadir")
    bsim_create.add_argument("--template", default="medium_nosize")
    bsim_create.add_argument("--owner", default="")
    bsim_create.add_argument("--description", default="")

    bsim_ing = sub.add_parser("bsim-ingest", help="Generate and commit BSim signatures for every program in a Ghidra repo")
    bsim_ing.add_argument("--repository", "--repo", dest="repository", required=True)
    bsim_ing.add_argument("--bsim-url")
    bsim_ing.add_argument("--datadir", type=Path)
    bsim_ing.add_argument("--name", default="bsim")
    bsim_ing.add_argument("--ghidra-url", default="", help="ghidra://host/repo or ghidra:/project prefix")
    bsim_ing.add_argument("--program", action="append", dest="programs", help="Limit to these program names (repeatable)")
    bsim_ing.add_argument("--receipt", type=Path)
    bsim_ing.add_argument("--force", action="store_true")

    bsim_rep = sub.add_parser("bsim-report", help="Report whether a BSim datadir/database is empty or holds executables")
    bsim_rep.add_argument("--datadir", type=Path)
    bsim_rep.add_argument("--bsim-url")
    bsim_rep.add_argument("--name", default="bsim")

    bridge = sub.add_parser("external-bridge", help="Emit enrichment/reuse/priority bridge artefacts")
    bridge.add_argument("--db", type=Path, required=True)
    bridge.add_argument("--out-dir", type=Path, required=True)
    bridge.add_argument("--program-map-json", type=Path, help="JSON map program_name -> repo_path")
    bridge.add_argument("--reuse-only", action="store_true")
    bridge.add_argument("--priority-only", action="store_true")
    bridge.add_argument("--priority-limit", type=int, default=4000)

    bp = sub.add_parser("build-project", help="Compile every .c under a packaged project")
    bp.add_argument("--project-dir", type=Path, required=True)
    bp.add_argument("--compiler")

    bth = sub.add_parser("build-types-header", help="Write ghidra_types.h from stored type rows")
    bth.add_argument("--db", type=Path, required=True)
    bth.add_argument("--repo-path", required=True)
    bth.add_argument("--out", type=Path, required=True)

    prop = sub.add_parser("propagate-corpus", help="Run matcher pairs from corpus config and bind identities")
    prop.add_argument("--db", type=Path, required=True)
    prop.add_argument("--run", default="v1")
    prop.add_argument("--report", type=Path, help="Write propagation summary JSON")
    prop.add_argument("--filter", nargs="*", help="Only pairs whose paths contain any token")

    bind = sub.add_parser("bind-identities", help="Bind match rows to logical identities for one run")
    bind.add_argument("--db", type=Path, required=True)
    bind.add_argument("--run", default="v1")

    recl = sub.add_parser("reclassify-matches", help="Downgrade conflicts and rebuild match identities")
    recl.add_argument("--db", type=Path, required=True)
    recl.add_argument("--run", default="v1")

    pr = sub.add_parser("package-readable", help="Package readable source tree for one binary")
    pr.add_argument("--db", type=Path, required=True)
    pr.add_argument("--repo-path", required=True)
    pr.add_argument("--out", type=Path, required=True)

    prec = sub.add_parser("package-recovered", help="Package recovered functions from the store")
    prec.add_argument("--db", type=Path, required=True)
    prec.add_argument("--out", type=Path, required=True)

    pri = sub.add_parser("package-readable-index", help="Write readable package index JSON")
    pri.add_argument("--root", type=Path, required=True)


def _argv_from_ns(args: argparse.Namespace, *, skip: frozenset[str] = frozenset({"cmd"})) -> list[str]:
    argv: list[str] = []
    for key, value in sorted(vars(args).items()):
        if key in skip or value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            if value:
                argv.append(flag)
            continue
        if isinstance(value, Path):
            argv.extend([flag, str(value)])
        elif isinstance(value, list):
            if key == "paths" or key == "patterns":
                argv.extend(str(item) for item in value)
            elif key == "filter" or key == "binaries" or key == "arches":
                if value:
                    argv.extend([flag, *value])
            else:
                argv.extend([flag, *[str(item) for item in value]])
        else:
            argv.extend([flag, str(value)])
    return argv


def dispatch(args: argparse.Namespace) -> int | None:
    """Run a kx subcommand. Returns None when *args.cmd* is not a kx command."""
    cmd = args.cmd
    if cmd not in KX_COMMANDS:
        return None

    if cmd == "export-atlas-db":
        from . import export_atlas_db as mod

        return mod.main(
            [
                "--binary", args.binary,
                "--db", str(args.db),
                "--out-root", str(args.out_root),
                *(["--knowledge-db", str(args.knowledge_db)] if args.knowledge_db else []),
                *(["--max-functions", str(args.max_functions)] if args.max_functions is not None else []),
                *(["--no-asm"] if args.no_asm else []),
                *(["--no-c"] if args.no_c else []),
            ]
        )

    if cmd == "seed-validation":
        from . import seed_validation as mod

        argv = _argv_from_ns(args)
        return mod.main(argv)

    if cmd == "harvest-shards":
        from . import harvest_shards as mod

        return mod.main([*args.patterns, *_argv_from_ns(args, skip=frozenset({"cmd", "patterns"}))])

    if cmd == "verify-legacy-recovered":
        from . import verify_legacy_recovered as mod

        return mod.main(_argv_from_ns(args))

    if cmd == "permuter-harness":
        from . import permuter_harness as mod

        return mod.main(_argv_from_ns(args)) or 0

    if cmd == "recover-named-ghidra":
        from . import recover_named_ghidra as mod

        return mod.main(_argv_from_ns(args)) or 0

    if cmd == "program-inventory":
        from . import ghidra_env as ge
        from . import program_inventory as inv

        records: list[dict] = []
        if args.programs_json:
            payload = json.loads(Path(args.programs_json).read_text(encoding="utf-8"))
            records = payload if isinstance(payload, list) else list(payload.get("programs") or [])
        else:
            records = [{"path": item["path"], "version": item.get("version")} for item in ge.list_files()]
        results = inv.inventory_programs(records, args.out, open_program=ge.open_program)
        print(json.dumps({"out": str(args.out), "programs": len(results)}, indent=2))
        return 0

    if cmd == "work-queue":
        from . import work_queue as wq
        from .store import connect

        con = connect(args.db)
        dest = wq.export_queue(con, args.out_dir, arches=tuple(args.arches) if args.arches else None)
        print(json.dumps({"wrote": str(dest)}, indent=2))
        return 0

    if cmd == "report":
        from . import report as rep
        from .store import connect

        con = connect(args.db)
        summary = rep.write_fragments(con, args.out_dir, run=args.run)
        print(json.dumps(summary, indent=2))
        return 0

    if cmd == "stabs-manifest":
        from . import stabs_manifest as sm
        from .store import connect

        con = connect(args.db)
        manifest, summary_path, summary = sm.generate(
            con, args.repo_path, raw_dir=args.raw_dir, out_dir=args.out_dir
        )
        print(json.dumps(summary, indent=2))
        print(f"wrote {manifest}")
        print(f"wrote {summary_path}")
        return 0

    if cmd == "export-bytes":
        from . import export_bytes as eb
        from . import ghidra_env as ge

        if ge.start() is False:
            print(json.dumps({"skipped": "no-program", "paths": args.paths}), indent=2)
            return 1
        args.out_dir.mkdir(parents=True, exist_ok=True)
        meta = []
        for repo_path in args.paths:
            slug = repo_path.strip("/").replace("/", "__")
            dest = args.out_dir / slug
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                with ge.open_program(repo_path) as program:
                    if program is None:
                        meta.append({"repo_path": repo_path, "skipped": "no-program"})
                        continue
                    meta.extend(eb.export(program, dest))
            except Exception as exc:
                meta.append({"repo_path": repo_path, "error": str(exc)})
        manifest = args.out_dir / "_manifest.json"
        manifest.write_text(json.dumps(meta, indent=1), encoding="utf-8")
        print(json.dumps({"manifest": str(manifest), "entries": len(meta)}, indent=2))
        return 0

    if cmd == "export-c":
        from . import export_c as ec

        result = ec.run(args.repo_path, args.out_dir, source_path=args.source_path)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok", result.get("skipped")) else 1

    if cmd == "export-types":
        from . import export_types as et
        from .store import connect

        con = connect(args.db)
        stats = et.export(args.repo_path, con)
        print(json.dumps(stats, indent=2))
        return 0 if stats.get("reason") != "no-program" else 1

    if cmd == "fix-func-counts":
        from . import fix_func_counts as ffc
        from .store import connect

        con = connect(args.db)
        result = ffc.audit(con, apply_counts=args.apply, report_path=args.out)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "bsim-eval":
        from . import bsim_eval as be
        from .store import connect

        con = connect(args.db)
        if args.pairs_json:
            raw = json.loads(Path(args.pairs_json).read_text(encoding="utf-8"))
            pairs = [(item[0], item[1]) for item in raw]
        else:
            from .corpus_config import load_match_pairs

            pairs = [(src, dst) for src, dst, _note in load_match_pairs()]
        results = be.evaluate_pairs(
            con, pairs, bsim_url=args.bsim_url, out_path=args.out, sample=args.sample
        )
        print(json.dumps({"pairs": len(results), "out": str(args.out)}, indent=2))
        return 0

    if cmd == "external-bridge":
        from . import external_bridge as bridge
        from .store import connect

        con = connect(args.db)
        if args.program_map_json:
            bridge.PROGRAM_MAP = json.loads(Path(args.program_map_json).read_text(encoding="utf-8"))
        out_dir = args.out_dir
        if args.priority_only:
            summary = bridge.emit_priority_targets(con, limit=args.priority_limit, out_dir=out_dir)
        elif args.reuse_only:
            summary = bridge.emit_reuse_candidates(con, out_dir=out_dir)
        else:
            bridge.emit_enrichment(con, out_dir=out_dir)
            summary = bridge.emit_reuse_candidates(con, out_dir=out_dir)
            bridge.emit_priority_targets(con, limit=args.priority_limit, out_dir=out_dir)
        print(json.dumps(summary, indent=2))
        return 0

    if cmd == "build-project":
        from . import build_project as bp

        result = bp.build_project(args.project_dir, compiler=args.compiler)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1

    if cmd == "build-types-header":
        from . import build_types_header as bth
        from .store import connect

        con = connect(args.db)
        row = con.execute("SELECT id FROM binary WHERE repo_path=?", (args.repo_path,)).fetchone()
        if row is None:
            print(f"error: not in database: {args.repo_path}", file=sys.stderr)
            return 2
        result = bth.build_header(con, int(row["id"]), args.out, program=args.repo_path)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "propagate-corpus":
        from . import propagate as prop
        from .corpus_config import load_match_pairs
        from .store import connect

        con = connect(args.db)
        pairs = load_match_pairs()
        if args.filter:
            tokens = args.filter
            pairs = [item for item in pairs if any(t in item[0] or t in item[1] for t in tokens)]
        if not pairs:
            print("error: no match pairs (set AGENT_DECOMPILE_CORPUS_CONFIG_DIR/pairs.json)", file=sys.stderr)
            return 2
        summary = prop.run_registry_pairs(con, pairs, run=args.run)
        dropped = prop.dedupe_identity_addrs(con)
        payload = {"run": args.run, "pairs": summary, "deduped": dropped}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(payload, indent=1), encoding="utf-8")
            payload["report"] = str(args.report)
        print(json.dumps(payload, indent=2))
        return 0

    if cmd == "bind-identities":
        from . import propagate as prop
        from .store import connect

        con = connect(args.db)
        bound = prop.bind_identities(con, args.run)
        print(json.dumps({"bound": bound, "run": args.run}, indent=2))
        return 0

    if cmd == "reclassify-matches":
        from . import propagate as prop
        from .store import connect

        con = connect(args.db)
        changed, bound, dropped = prop.reclassify_existing(con, args.run)
        print(json.dumps({"downgraded": changed, "bound": bound, "deduped": dropped}, indent=2))
        return 0

    if cmd == "package-readable":
        from . import package_readable as pr
        from .store import connect

        con = connect(args.db)
        result = pr.package_from_store(con, args.repo_path, args.out)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "package-recovered":
        from . import package_recovered as prec
        from .store import connect

        con = connect(args.db)
        result = prec.package_from_store(con, args.out)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "package-readable-index":
        from . import package_readable_index as pri

        result = pri.write_index(args.root)
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "bsim-createdatabase":
        from . import bsim_ops as bo

        url = args.bsim_url or bo.default_bsim_url(datadir=args.datadir, name=args.name)
        payload = bo.createdatabase(
            url,
            template=args.template,
            name=args.name,
            owner=args.owner,
            description=args.description,
        )
        print(json.dumps(payload, indent=2))
        return 0 if payload.get("ok") else 1

    if cmd == "bsim-ingest":
        from . import bsim_ops as bo

        payload = bo.ingest(
            args.repository,
            bsim_url=args.bsim_url or "",
            datadir=args.datadir,
            name=args.name,
            programs=args.programs,
            ghidra_url=args.ghidra_url,
            receipt=args.receipt,
            force=args.force,
        )
        print(json.dumps(payload, indent=2))
        return 0 if payload.get("ok") else 1

    if cmd == "bsim-report":
        from . import bsim_ops as bo

        payload = bo.report(datadir=args.datadir, bsim_url=args.bsim_url or "", name=args.name)
        print(json.dumps(payload, indent=2))
        return 0 if payload.get("ok") else 1

    return 2
