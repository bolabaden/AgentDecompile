"""Register MizuchiRE ``tools/`` scripts on ``agentdecompile-corpus`` for AIO."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

MIZUCHI_COMMANDS = frozenset({
    "collect-source",
    "coverage-report",
    "rebuild-ledger",
    "mkobj",
    "objdiff-check",
    "compile-unit",
})

TOOLCHAIN_SCRIPTS = {
    "msvc-x86": "compile-msvc-x86.sh",
    "msvc-x86-modern": "compile-msvc-x86-modern.sh",
    "msvc-x64": "compile-msvc-x64.sh",
    "xbox-x86": "compile-xbox-x86.sh",
    "android-arm64": "compile-android-arm64.sh",
    "android-armv7": "compile-android-armv7.sh",
    "android-x86": "compile-android-x86.sh",
    "elf-x86": "compile-elf-x86.sh",
    "apple-x86": "compile-apple-x86.sh",
    "apple-arm64": "compile-apple-arm64.sh",
}


def _toolchains_dir() -> Path:
    env = os.environ.get("AGENT_DECOMPILE_TOOLCHAINS_DIR", "").strip()
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "scripts" / "recovery-toolchains"


def register(sub: argparse._SubParsersAction) -> None:
    cs = sub.add_parser("collect-source", help="Collect byte-exact C from Mizuchi run-results")
    cs.add_argument("--projects-dir", type=Path, required=True)
    cs.add_argument("--coverage-dir", type=Path, required=True)
    cs.add_argument("--out-dir", type=Path, required=True)
    cs.add_argument("--recovery-root", type=Path)

    cr = sub.add_parser("coverage-report", help="Summarize coverage ledgers")
    cr.add_argument("--coverage-dir", type=Path, required=True)
    cr.add_argument("--inventory", type=Path)
    cr.add_argument("--json", action="store_true", dest="output_json")

    rl = sub.add_parser("rebuild-ledger", help="Rebuild a program coverage ledger from run-results")
    rl.add_argument("program")
    rl.add_argument("--projects-dir", type=Path, required=True)
    rl.add_argument("--coverage-dir", type=Path, required=True)
    rl.add_argument("--gen-project-script", type=Path)
    rl.add_argument("--patterns", help="Comma-separated project globs")
    rl.add_argument("--recovery-root", type=Path)

    mo = sub.add_parser("mkobj", help="Wrap a binary slice in a minimal COFF object")
    mo.add_argument("--binary", type=Path, required=True)
    mo.add_argument("--offset", type=int, required=True)
    mo.add_argument("--size", type=int, required=True)
    mo.add_argument("--name", required=True)
    mo.add_argument("-o", "--output", type=Path, required=True)
    mo.add_argument("--symbol-prefix", default="_")
    mo.add_argument("--format", choices=("coff-i386", "coff-x86-64"), default="coff-i386")

    od = sub.add_parser("objdiff-check", help="Compare two COFF objects with objdiff-wasm")
    od.add_argument("base", type=Path)
    od.add_argument("target", type=Path)
    od.add_argument("symbol", nargs="?")
    od.add_argument("--script", type=Path)

    cu = sub.add_parser("compile-unit", help="Compile one C file with a recovery toolchain script")
    cu.add_argument("--family", required=True, choices=sorted(TOOLCHAIN_SCRIPTS))
    cu.add_argument("--source", type=Path, required=True)
    cu.add_argument("--object", type=Path, required=True)
    cu.add_argument("--function-name", default="")


def dispatch(args: argparse.Namespace) -> int | None:
    cmd = args.cmd
    if cmd not in MIZUCHI_COMMANDS:
        return None

    if cmd == "collect-source":
        from . import collect_source as cs

        result = cs.collect(
            projects_dir=args.projects_dir,
            coverage_dir=args.coverage_dir,
            out_dir=args.out_dir,
            recovery_root=args.recovery_root,
        )
        print(result["report"])
        print(json.dumps({k: v for k, v in result.items() if k != "report"}, indent=2))
        return 0

    if cmd == "coverage-report":
        from . import coverage_report as cr

        summary = cr.summarize(args.coverage_dir, inventory_path=args.inventory)
        if getattr(args, "output_json", False):
            print(json.dumps(summary, indent=2))
        else:
            print(cr.format_report(summary))
        return 0 if not summary.get("error") else 1

    if cmd == "rebuild-ledger":
        from . import rebuild_ledger as rl

        script = args.gen_project_script
        if script is None:
            env = os.environ.get("AGENT_DECOMPILE_GEN_PROJECT_SCRIPT", "").strip()
            script = Path(env) if env else None
        if script is None or not script.is_file():
            print(
                "error: --gen-project-script or AGENT_DECOMPILE_GEN_PROJECT_SCRIPT is required",
                file=sys.stderr,
            )
            return 2
        patterns = args.patterns.split(",") if args.patterns else None
        result = rl.rebuild(
            args.program,
            projects_dir=args.projects_dir,
            coverage_dir=args.coverage_dir,
            gen_project_script=script,
            patterns=patterns,
            recovery_root=args.recovery_root,
        )
        print(json.dumps(result, indent=2))
        return 0

    if cmd == "mkobj":
        from . import mkobj as mo

        argv = [
            "--binary", str(args.binary),
            "--offset", str(args.offset),
            "--size", str(args.size),
            "--name", args.name,
            "-o", str(args.output),
            "--symbol-prefix", args.symbol_prefix,
            "--format", args.format,
        ]
        return mo.main(argv)

    if cmd == "objdiff-check":
        from . import objdiff_check as od

        result = od.run_check(args.base, args.target, args.symbol, script_path=args.script)
        if result.get("stdout"):
            print(result["stdout"], end="" if result["stdout"].endswith("\n") else "\n")
        if result.get("stderr"):
            print(result["stderr"], file=sys.stderr, end="")
        if result.get("skipped"):
            print(json.dumps(result, indent=2))
            return 1
        return int(result.get("returncode", 1))

    if cmd == "compile-unit":
        script_name = TOOLCHAIN_SCRIPTS[args.family]
        script = _toolchains_dir() / script_name
        if not script.is_file():
            print(f"error: toolchain script not found: {script}", file=sys.stderr)
            return 2
        proc = subprocess.run(
            ["sh", str(script), str(args.source), str(args.object), args.function_name or ""],
            capture_output=False,
        )
        return proc.returncode

    return 2
