"""CLI for the corpus-wide semantic decompilation pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .archive import check_extraction, list_archive, summarize_entries
from .contract import PIPELINE_STAGES, PRIORITIES
from .pipeline import run_corpus_pipeline
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


def main(argv: list[str] | None = None) -> int:
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

    stabs = sub.add_parser("extract-stabs", help="Read Mach-O STABS into a functions snapshot")
    stabs.add_argument("--binary", type=Path, required=True)
    stabs.add_argument("--id", required=True, dest="binary_id")
    stabs.add_argument("--out-dir", type=Path, required=True)

    run = sub.add_parser("run", help="Run pipeline stages in contract order")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    run.add_argument("--snapshot-dir", type=Path, required=True, help="Directory of {id}.functions.json extracts")
    run.add_argument("--stop-after", default="compile", choices=PIPELINE_STAGES)
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

    args = parser.parse_args(argv)
    if args.cmd == "init":
        save_corpus(args.out, new_corpus(args.corpus_id))
        print(args.out)
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
                        "name": fn.get("name"),
                        "stabs_name": fn.get("name"),
                        "source_file": fn.get("source_file"),
                        "object_file": fn.get("object_file"),
                        "size": fn.get("size"),
                        "name_origin": "stabs",
                    }
                )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        dest = args.out_dir / f"{args.binary_id}.functions.json"
        dest.write_text(json.dumps(functions, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"wrote": str(dest), "functions": len(functions), "slices": len(report.get("slices") or [])}))
        return 0
    if args.cmd == "run":
        corpus = load_corpus(args.corpus)
        summary = run_corpus_pipeline(
            corpus,
            work_dir=args.work_dir,
            snapshot_dir=args.snapshot_dir,
            stop_after=args.stop_after,
            compiler=args.compiler,
            llm=bool(args.llm),
            llm_model=args.llm_model,
        )
        print(json.dumps(summary, indent=2))
        if args.stop_after == "compile" and not summary.get("completeExecutable"):
            return 2
        return 0
    if args.cmd == "stages":
        print(json.dumps({"stages": PIPELINE_STAGES, "priorities": PRIORITIES}, indent=2))
        return 0
    if args.cmd == "list-archive":
        return run_list_archive_command(args)
    if args.cmd == "check-extraction":
        return run_check_extraction_command(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
