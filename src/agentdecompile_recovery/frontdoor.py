"""Installable reconstruction CLI front door.

This module keeps the full subcommand recovery CLI available while also
exposing a direct binary-or-folder entry shape:

    agentdecompile-reconstruct path/to/binary

The default path runs the generic recovery orchestrator with proof packaging
enabled and the plugin synthesis engine selected.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .acquire import acquire_context
from .autonomy_budget import budget_from_args
from .claim_report import write_claim_report
from .critical_path import write_critical_path
from .cli import main as legacy_main
from .pipeline import RecoveryConfig, RecoveryRunner
from .targets import identify_binary
from .tools import inspect_capabilities, resolve_script_asset


LEGACY_COMMANDS = {
    "inspect",
    "export-context",
    "export-context-batch",
    "recover",
    "recover-windows",
    "verify-package",
    "match-package",
    "sweep-package",
    "compiler-profile-corpus",
    "source-parity-synthesize",
    "source-plugin-pipeline",
}

UPSTREAM_COMMANDS = {"run", "atlas", "index-codebase"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def run_decomp_cli_bridge(args: list[str]) -> int:
    root = repo_root()
    decomp = root / "scripts" / "decomp-cli.sh"
    if not decomp.exists():
        print(f"agentdecompile-reconstruct: missing workspace bridge {decomp}", file=sys.stderr)
        return 1
    proc = subprocess.run([str(decomp), *args], cwd=root)
    return int(proc.returncode or 0)


def run_upstream_command(command: str, argv: list[str]) -> int:
    if command == "run":
        bridge_args = ["vacuum", "start", "--queue", "state/queue.json", "--max-functions", "1"]
        if argv:
            bridge_args = ["vacuum", "start", *argv]
        return run_decomp_cli_bridge(bridge_args)
    if command == "atlas":
        if not argv:
            print("Usage: agentdecompile-reconstruct atlas <prompt-name>", file=sys.stderr)
            return 2
        return run_decomp_cli_bridge(["decomp-atlas", argv[0], *argv[1:]])
    if command == "index-codebase":
        return run_decomp_cli_bridge(["source-parity-feature-index", *argv])
    return run_upstream_command_guard(command)


def default_work_dir(target_path: Path, preferred_name: str | None = None) -> Path:
    identity = identify_binary(target_path, preferred_name)
    return Path("target/agentdecompile-reconstruct") / identity.stable_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentdecompile-reconstruct",
        description="One-shot binary recovery packaging front door.",
        epilog=(
            "PE critical path (bounded checkpoints): "
            "prepare-analysis-image → inventory-binary → discover-functions → "
            "enrich-decompile → generate-source-candidates → synthesize-source-tasks. "
            "Example: reconstruct game.exe --stop-after discover-functions. "
            "Inspect readiness via critical-path.json or recovery status."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", type=Path, help="Binary, archive, installer, or app directory to recover.")
    parser.add_argument(
        "context_positional",
        nargs="*",
        type=Path,
        metavar="CONTEXT",
        help=(
            "Optional puzzle-piece paths after the target (notes, partial source dumps, JSON/JSONL, "
            "dirs, Ghidra .gzf). Same as repeatable --context; pieces are auto-sniffed."
        ),
    )
    parser.add_argument("--preferred-name", help="Preferred executable basename when input is a folder.")
    parser.add_argument("--work-dir", type=Path, help="Run/state directory. Defaults to target/agentdecompile-reconstruct/<stable-target-id>.")
    parser.add_argument(
        "--context",
        type=Path,
        action="append",
        default=[],
        help="Additional context file or directory (notes, partial source, Ghidra dumps, JSON facts). Repeatable.",
    )
    parser.add_argument(
        "--context-pack",
        type=Path,
        help="Previously generated context-pack or acquisition-bundle directory.",
    )
    parser.add_argument(
        "--acquisition-bundle",
        type=Path,
        help="Explicit acquisition-bundle directory (skips rediscovery from target fingerprint).",
    )
    parser.add_argument(
        "--autonomous",
        action="store_true",
        help="Enable bounded vacuum/repair autonomy after the core recovery stages (advanced).",
    )
    parser.add_argument(
        "--autonomous-max-functions",
        type=int,
        default=1,
        help="Autonomy budget: maximum functions for vacuum start (default: 1). Use 0 to skip vacuum.",
    )
    parser.add_argument(
        "--autonomous-max-attempts",
        type=int,
        default=3,
        help="Autonomy budget: maximum repair attempts per function (default: 3).",
    )
    parser.add_argument(
        "--autonomous-max-wall-seconds",
        type=int,
        default=None,
        help="Autonomy budget: optional wall-clock cap forwarded to vacuum when supported.",
    )
    parser.add_argument(
        "--autonomous-max-campaigns",
        type=int,
        default=1,
        help="Autonomy budget: maximum proof campaigns per --autonomous invocation (default: 1).",
    )
    parser.add_argument(
        "--autonomous-stop-on-accept",
        action="store_true",
        help="Stop the proof campaign loop after the first objdiff accept in the loop.",
    )
    parser.add_argument(
        "--skip-closure-executors",
        action="store_true",
        help="Skip context apply and symbol provenance stages before autonomous proof campaign.",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reuse complete stage receipts with matching config.",
    )
    parser.add_argument("--force", action="store_true", help="Rerun selected stages even when receipts exist.")
    parser.add_argument(
        "--stop-after",
        choices=[
            "discover",
            "inspect-capabilities",
            "prepare-analysis-image",
            "export-context",
            "inventory-binary",
            "discover-functions",
            "analyze-functions",
            "enrich-decompile",
            "generate-source-candidates",
            "synthesize-source-tasks",
            "plan-strategy",
            "byte-authority",
            "legacy-adapter",
            "snapshot-existing-recovery",
            "report",
        ],
        help="Stop after a named stage for bounded runs.",
    )
    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip PyGhidra enrich-decompile (typed names/modules before source generation).",
    )
    parser.add_argument("--json", action="store_true", help="Emit progress as JSON lines.")
    parser.add_argument("--stage-timeout", type=int, default=300, help="Timeout per orchestration stage.")
    parser.add_argument("--progress-width", type=int, default=24)
    parser.add_argument("--no-byte-authority", action="store_true", help="Disable byte-exact source authority package generation.")
    parser.add_argument("--function-analysis", choices=["auto", "none", "objdump"], default="auto")
    parser.add_argument("--source-task-limit", type=int, default=500, help="Maximum function candidates to queue.")
    parser.add_argument("--source-task-offset", type=int, default=0, help="Skip this many eligible candidates before queueing.")
    parser.add_argument(
        "--source-synthesis",
        choices=["none", "dry-run", "clang", "clang-cl", "msvc"],
        default="clang",
        help="Compiler lane used for bounded generated source verification.",
    )
    parser.add_argument(
        "--source-synthesis-engine",
        choices=["plugin", "legacy"],
        default="plugin",
        help="plugin uses the upstream-style setup/programmatic/retry lifecycle.",
    )
    parser.add_argument("--source-synthesis-limit", type=int, default=50, help="Maximum source tasks to inspect in this invocation.")
    parser.add_argument("--source-synthesis-max-variants", type=int, default=8)
    parser.add_argument("--source-synthesis-strategies", help="Comma-separated strategy/tag/rule filter.")
    parser.add_argument(
        "--source-synthesis-source-quality",
        action="append",
        default=[],
        help="Only verify generated candidates with this source quality. Repeat or comma-separate.",
    )
    parser.add_argument("--source-synthesis-vc-root", type=Path, help="MSVC/VC Toolkit root used by source synthesis.")
    parser.add_argument(
        "--vc-root",
        type=Path,
        help="Alias for --source-synthesis-vc-root (MSVC root for dump/match path).",
    )
    parser.add_argument("--source-synthesis-wine", default="wine", help="Wine executable used by MSVC source synthesis.")
    parser.add_argument("--source-synthesis-wineprefix", type=Path, help="Wine prefix used by MSVC source synthesis.")
    parser.add_argument("--steamless-cli", type=Path, help="Steamless CLI used to prepare PE analysis images when applicable.")
    parser.add_argument(
        "--dump-source",
        type=Path,
        help="Export reference-shaped dump (verified/ + advisory/ghidra/ + Port/CODE) to this directory after resume/export.",
    )
    parser.add_argument(
        "--dump-source-only",
        action="store_true",
        help="Skip recovery stages; only build --dump-source from existing receipts/summaries.",
    )
    parser.add_argument(
        "--dump-layers",
        default="verified,port",
        help="Comma-separated dump layers: verified,port,advisory (default: verified,port).",
    )
    parser.add_argument(
        "--dump-allow-leftovers",
        action="store_true",
        help="Allow undeclared sibling match JSONL / merged facts auto-load (operator resume only).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Parallel Wine/MSVC compile+objdiff workers (0 = auto 6–8).",
    )
    parser.add_argument(
        "--force-rematch",
        action="store_true",
        help="Rematch proven objdiff-0 functions (default: use match cache / skip).",
    )
    parser.add_argument(
        "--ghidra-facts",
        type=Path,
        help="Optional function-facts JSONL with decompiled text for advisory/ghidra dump layer.",
    )
    parser.add_argument("--context-format", choices=["json", "md"], default="json")
    parser.add_argument("--context-binary-analysis", choices=["light", "standard", "deep"], default="standard")
    parser.add_argument("--context-max-files", type=int, default=1000)
    parser.add_argument("--context-max-depth", type=int, default=4)
    parser.add_argument("--context-strings-limit", type=int, default=500)
    parser.add_argument("--context-max-index-text-chars", type=int, default=2000)
    parser.add_argument("--no-context-extract-containers", action="store_true")
    parser.add_argument("--context-include-low-signal-members", action="store_true")
    return parser


def build_self_check_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentdecompile-reconstruct self-check",
        description="Verify install-time Recovery assets and local recovery tool availability.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2], help="Checkout root used for script discovery.")
    return parser


def build_upstream_status_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentdecompile-reconstruct upstream-status",
        description="Report how this package maps the vendored reference implementation surfaces.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def merge_context_paths(*groups: list[Path] | tuple[Path, ...] | None) -> list[Path]:
    """Deduplicate context puzzle pieces while preserving first-seen order."""

    seen: set[str] = set()
    out: list[Path] = []
    for group in groups:
        if not group:
            continue
        for path in group:
            try:
                key = str(path.expanduser().resolve())
            except OSError:
                key = str(path)
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
    return out


def parse_csv_values(values: list[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                item.strip()
                for value in values
                for item in value.split(",")
                if item.strip()
            }
        )
    )


def parse_csv_string(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(sorted({item.strip() for item in value.split(",") if item.strip()}))


def run_one_shot(args: argparse.Namespace) -> int:
    if args.force:
        args.resume = False
    if getattr(args, "vc_root", None) and not getattr(args, "source_synthesis_vc_root", None):
        args.source_synthesis_vc_root = args.vc_root
    work_dir = args.work_dir or default_work_dir(args.input, args.preferred_name)
    work_dir.mkdir(parents=True, exist_ok=True)

    if getattr(args, "dump_source_only", False):
        if not getattr(args, "dump_source", None):
            print(
                "agentdecompile-reconstruct: --dump-source-only requires --dump-source DIR",
                file=sys.stderr,
            )
            return 2
        return run_dump_source(args, work_dir)

    context_paths = merge_context_paths(getattr(args, "context_positional", None), getattr(args, "context", None))
    args.context = context_paths

    acquisition_receipt = None
    if context_paths:
        from .context_pack import materialize_context_seeds, write_placement_summary

        acquisition_receipt = acquire_context(
            target_input=args.input,
            context_paths=list(context_paths),
            out_dir=work_dir / "acquisition",
            preferred_name=args.preferred_name,
            repo_root=repo_root(),
        )
        receipt_path = work_dir / "acquisition" / "acquire.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        placement = write_placement_summary(
            work_dir / "acquisition",
            pack_manifest=(acquisition_receipt or {}).get("contextPack") or {},
            bundle_dir=Path(str(acquisition_receipt.get("bundleDir"))) if acquisition_receipt and acquisition_receipt.get("bundleDir") else None,
            routing=(acquisition_receipt or {}).get("routing") or {},
        )
        seed_receipt = materialize_context_seeds(
            pack_manifest=(acquisition_receipt or {}).get("contextPack") or {},
            seed_dir=work_dir / "advisory" / "context-seeds",
            facts_path=(
                Path(str(acquisition_receipt.get("snapshotDir"))) / "context-pack" / "function-facts.jsonl"
                if acquisition_receipt and acquisition_receipt.get("snapshotDir")
                else None
            ),
        )
        from .context_propose import write_propose_labels

        propose_receipt = write_propose_labels(work_dir)
        acquisition_receipt["placement"] = placement
        acquisition_receipt["contextSeeds"] = seed_receipt
        acquisition_receipt["proposeLabels"] = {
            "status": propose_receipt.get("status"),
            "counts": propose_receipt.get("counts"),
            "claimBoundary": propose_receipt.get("claimBoundary"),
        }
        receipt_path.write_text(json.dumps(acquisition_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not args.json:
            print(
                json.dumps(
                    {
                        "status": "acquired",
                        "claimBoundary": acquisition_receipt.get("claimBoundary"),
                        "bundleDir": acquisition_receipt.get("bundleDir"),
                        "entityHint": (acquisition_receipt.get("contextPack") or {}).get("entityCount"),
                        "placement": placement.get("counts"),
                        "contextSeeds": seed_receipt.get("counts"),
                        "proposeLabels": propose_receipt.get("counts"),
                    },
                    indent=2,
                )
            )

    config = RecoveryConfig(
        input_path=args.input,
        work_dir=work_dir,
        preferred_name=args.preferred_name,
        resume=args.resume,
        force=args.force,
        stop_after=args.stop_after,
        json_output=args.json,
        progress_width=args.progress_width,
        stage_timeout=args.stage_timeout,
        enable_byte_authority=not args.no_byte_authority,
        enable_legacy_adapters=False,
        function_analysis=args.function_analysis,
        context_paths=tuple(context_paths),
        context_pack=args.context_pack,
        acquisition_bundle=args.acquisition_bundle
        or (Path(str(acquisition_receipt["bundleDir"])) if acquisition_receipt and acquisition_receipt.get("bundleDir") else None),
        source_task_limit=args.source_task_limit,
        source_task_offset=args.source_task_offset,
        source_synthesis_engine=args.source_synthesis_engine,
        source_synthesis_mode=args.source_synthesis,
        source_synthesis_limit=args.source_synthesis_limit,
        source_synthesis_max_variants=args.source_synthesis_max_variants,
        source_synthesis_strategies=parse_csv_string(args.source_synthesis_strategies),
        source_synthesis_source_qualities=parse_csv_values(args.source_synthesis_source_quality),
        source_synthesis_vc_root=args.source_synthesis_vc_root,
        source_synthesis_wine=args.source_synthesis_wine,
        source_synthesis_wineprefix=args.source_synthesis_wineprefix,
        steamless_cli=args.steamless_cli,
        verify_workers=int(getattr(args, "workers", 0) or 0),
        force_rematch=bool(getattr(args, "force_rematch", False)),
        context_format=args.context_format,
        context_binary_analysis=args.context_binary_analysis,
        context_max_files=args.context_max_files,
        context_max_depth=args.context_max_depth,
        context_strings_limit=args.context_strings_limit,
        context_max_index_text_chars=args.context_max_index_text_chars,
        context_extract_containers=not args.no_context_extract_containers,
        context_include_low_signal_members=args.context_include_low_signal_members,
        skip_enrichment=False,
    )
    rc = RecoveryRunner(config).run()
    write_critical_path(work_dir)
    report_path = work_dir / "report.json"
    analysis_path = work_dir / "analysis-target.json"
    terminal = "matched" if rc == 0 else "failed"
    if analysis_path.exists():
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            if str(analysis.get("terminalStatus") or "").startswith("blocked:toolchain"):
                terminal = "blocked:toolchain"
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            # Best-effort status enrichment; keep orchestration outcome if parse fails.
            pass
    state_path = work_dir / "state.json"
    if terminal != "blocked:toolchain" and state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("terminalStatus") == "blocked:toolchain" or state.get("status") == "blocked:toolchain":
                terminal = "blocked:toolchain"
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            # Best-effort status enrichment; keep orchestration outcome if parse fails.
            pass
    if report_path.exists() or terminal == "blocked:toolchain":
        if rc == 0 and (work_dir / "source-synthesis" / "summary.json").exists():
            try:
                synth = json.loads((work_dir / "source-synthesis" / "summary.json").read_text(encoding="utf-8"))
                accepted = int(synth.get("acceptedCandidates") or synth.get("accepted") or 0)
                if accepted == 0 and terminal == "matched":
                    terminal = "partial"
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                # Best-effort partial detection; keep matched/failed if summary is unreadable.
                pass
        claim_path = write_claim_report(work_dir, terminal_status=terminal)
        budget = budget_from_args(
            max_functions=getattr(args, "autonomous_max_functions", None),
            max_attempts_per_function=getattr(args, "autonomous_max_attempts", None),
            max_wall_seconds=getattr(args, "autonomous_max_wall_seconds", None),
            max_campaigns=getattr(args, "autonomous_max_campaigns", None),
            stop_on_accept=bool(getattr(args, "autonomous_stop_on_accept", False)),
        )
        if not args.json:
            print(
                json.dumps(
                    {
                        "status": terminal,
                        "workDir": str(work_dir),
                        "report": str(report_path),
                        "claimReport": str(claim_path),
                        "claimBoundary": "report status is orchestration outcome; semantic recovery requires objdiff-verified-semantic artifacts under verified/",
                        "autonomousRequested": bool(args.autonomous),
                        "autonomyBudget": budget.to_json(),
                    },
                    indent=2,
                )
            )
    if rc == 0 and args.autonomous:
        budget = budget_from_args(
            max_functions=getattr(args, "autonomous_max_functions", None),
            max_attempts_per_function=getattr(args, "autonomous_max_attempts", None),
            max_wall_seconds=getattr(args, "autonomous_max_wall_seconds", None),
            max_campaigns=getattr(args, "autonomous_max_campaigns", None),
            stop_on_accept=bool(getattr(args, "autonomous_stop_on_accept", False)),
        )
        if not getattr(args, "skip_closure_executors", False):
            from .agent_closure import run_agent_closure_stages

            run_agent_closure_stages(work_dir, budget)
        from .proof_campaign import run_proof_campaign_loop

        loop_result = run_proof_campaign_loop(
            work_dir,
            budget,
            run_decomp_cli_bridge=run_decomp_cli_bridge,
            vc_root=args.source_synthesis_vc_root,
            wineprefix=args.source_synthesis_wineprefix,
        )
        if int(loop_result.get("returncode") or 0) != 0:
            rc = int(loop_result["returncode"])
    if getattr(args, "dump_source", None):
        dump_rc = run_dump_source(args, work_dir)
        if dump_rc != 0:
            return dump_rc
    return rc


def _analysis_digest_for_work_dir(work_dir: Path) -> str:
    """Best-effort analysis-image digest for fresh-dump gating."""
    for rel in ("state.json", "analysis-target.json", "ghidra-analysis.json"):
        path = work_dir / rel
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        stages = data.get("stages") if isinstance(data.get("stages"), dict) else {}
        for stage_name in ("prepare", "inventory", "batch-decompile"):
            stage = stages.get(stage_name) if isinstance(stages.get(stage_name), dict) else {}
            for key in ("analysisBinarySha256", "targetSha256", "binarySha256"):
                value = str(stage.get(key) or "").strip()
                if value:
                    return value
        for key in ("analysisBinarySha256", "targetSha256", "binarySha256"):
            value = str(data.get(key) or "").strip()
            if value:
                return value
    return ""


def _jsonl_compatible_with_analysis(path: Path, expected_sha: str) -> bool:
    """Return True when *path* is safe to auto-load for the current analysis image.

    Fresh mode rejects unmarked leftovers when an analysis digest is known: every
    auto-discovered JSONL must carry at least one matching
    ``targetSha256`` / ``analysisBinarySha256`` / ``binarySha256``. Explicit
    operator paths (``export-summaries.txt``, ``--ghidra-facts``) bypass this.
    """
    if not expected_sha:
        return True
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines[:200]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        for key in ("targetSha256", "analysisBinarySha256", "binarySha256"):
            value = str(row.get(key) or "").strip()
            if value and value == expected_sha:
                return True
    # Known analysis digest + unmarked/mismatched rows = treat as stale leftover.
    return False


def run_dump_source(args: argparse.Namespace, work_dir: Path) -> int:
    """Export a layered source dump from proofs plus optional Ghidra advisory."""

    from .source_dump import dump_source_tree
    from .source_parity_one_shot import detect_profile
    from .stage_timings import load_stage_timings, record_stage, write_stage_timings

    dump_started = time.monotonic()
    out_dir = Path(args.dump_source)
    # Fresh mode (default): only this work_dir's declared receipts + explicit flags.
    # Leftover sibling JSONL / repo-root merged facts are operator-resume only.
    allow_leftovers = bool(
        getattr(args, "dump_allow_leftovers", False) or getattr(args, "dump_source_only", False)
    )
    expected_sha = "" if allow_leftovers else _analysis_digest_for_work_dir(work_dir)
    summaries: list[Path] = []
    # Proof receipts written by this run's synthesis / match stages.
    for rel in (
        "source-synthesis/accepted.jsonl",
        "source-synthesis/code-slice-matches.jsonl",
        "source-synthesis/source-shape-matches.jsonl",
        "trivial-matches/summary.jsonl",
        "reloc-wrapper-matches/summary.jsonl",
    ):
        path = work_dir / rel
        if path.exists() and (allow_leftovers or _jsonl_compatible_with_analysis(path, expected_sha)):
            summaries.append(path)

    if allow_leftovers:
        # Sibling match receipts under target/ (operator resume).
        target_root = (
            work_dir.parent.parent
            if work_dir.parent.name == "agentdecompile-reconstruct"
            else work_dir.parent
        )
        siblings = [
            *target_root.glob("*-trivial-matches/summary.jsonl"),
            *target_root.glob("*-reloc-wrapper-matches/summary.jsonl"),
            *work_dir.parent.glob("*-trivial-matches/summary.jsonl"),
            *work_dir.parent.glob("*-reloc-wrapper-matches/summary.jsonl"),
        ]
        for sibling in siblings:
            if sibling.exists():
                summaries.append(sibling)

    # Operator-authored explicit summary list (paths under the operator's control).
    list_file = work_dir / "export-summaries.txt"
    if list_file.exists():
        for line in list_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and Path(line).exists() and line.endswith(".jsonl"):
                summaries.append(Path(line))

    # Deduplicate
    seen: set[str] = set()
    unique: list[Path] = []
    for path in summaries:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    ghidra_facts = getattr(args, "ghidra_facts", None)
    if ghidra_facts is None:
        fresh_facts_candidates = (
            work_dir / "source-generation" / "function-facts.jsonl",
            work_dir / "acquisition" / "function-facts.jsonl",
            work_dir / "facts" / "function-facts.jsonl",
            work_dir / "unpack" / "facts" / "function-facts.jsonl",
            work_dir / "batch-decompile" / "function-facts.jsonl",
        )
        leftover_facts_candidates = tuple(Path("target").glob("*-ghidra-merged-decomp.jsonl"))
        for candidate in fresh_facts_candidates + (leftover_facts_candidates if allow_leftovers else ()):
            if not candidate.exists():
                continue
            if allow_leftovers or _jsonl_compatible_with_analysis(candidate, expected_sha):
                ghidra_facts = candidate
                break

    # Prefer facts JSONL. Only seed from a pre-materialized advisory dir when
    # no facts file was provided (avoids double banners / double filenames).
    advisory_seed = work_dir / "advisory" / "ghidra"
    use_advisory_seed = advisory_seed.is_dir() and ghidra_facts is None and allow_leftovers

    dump_layers = getattr(args, "dump_layers", None) or "verified,port"
    profile_slug = str(getattr(args, "profile", None) or detect_profile(Path(args.input)))
    module_hints: dict[str, dict] = {}
    module_map_path = work_dir / "unpack" / "facts" / "module-map.json"
    if not module_map_path.exists():
        module_map_path = work_dir / "facts" / "module-map.json"
    if module_map_path.exists():
        try:
            payload = json.loads(module_map_path.read_text(encoding="utf-8"))
            module_hints = dict(payload.get("entries") or {})
        except (OSError, json.JSONDecodeError, TypeError):
            module_hints = {}
    manifest = dump_source_tree(
        out_dir=out_dir,
        summaries=unique,
        ghidra_facts=Path(ghidra_facts) if ghidra_facts else None,
        advisory_dir=advisory_seed if use_advisory_seed else None,
        target_name=args.input.name if hasattr(args.input, "name") else "binary",
        clean=True,
        layers=dump_layers,
        profile=profile_slug,
        module_hints=module_hints,
    )
    receipt = {
        "schema": "agentdecompile.dump-source.v1",
        "status": manifest.get("status"),
        "outDir": str(out_dir),
        "workDir": str(work_dir),
        "summaries": [str(p) for p in unique],
        "ghidraFacts": str(ghidra_facts) if ghidra_facts else None,
        "dumpLayers": manifest.get("layers"),
        "freshMode": not allow_leftovers,
        "analysisBinarySha256": expected_sha or None,
        "matchedCount": manifest.get("matchedCount"),
        "codeSliceMatchedCount": manifest.get("codeSliceMatchedCount"),
        "ghidraCount": manifest.get("ghidraCount"),
        "claimBoundary": manifest.get("claimBoundary"),
    }
    (work_dir / "dump-source.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    timings = load_stage_timings(work_dir)
    record_stage(
        timings,
        "dump-source",
        started=dump_started,
        status=str(manifest.get("status") or "complete"),
        outDir=str(out_dir),
        freshMode=not allow_leftovers,
    )
    write_stage_timings(work_dir, timings)
    if not args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if manifest.get("status") == "complete" else 1


def build_reconstruct_namespace(
    input_path: Path,
    *,
    work_dir: Path | None = None,
    preferred_name: str | None = None,
    context: list[Path] | None = None,
    context_pack: Path | None = None,
    acquisition_bundle: Path | None = None,
    stop_after: str | None = None,
    autonomous: bool = False,
    autonomous_max_functions: int = 1,
    autonomous_max_attempts: int = 3,
    autonomous_max_wall_seconds: int | None = None,
    autonomous_max_campaigns: int = 1,
    autonomous_stop_on_accept: bool = False,
    force: bool = False,
    resume: bool = True,
) -> argparse.Namespace:
    """Build a reconstruct argparse namespace for MCP/programmatic callers."""

    argv: list[str] = [str(input_path), "--json"]
    if work_dir is not None:
        argv.extend(["--work-dir", str(work_dir)])
    if preferred_name:
        argv.extend(["--preferred-name", preferred_name])
    for path in context or []:
        argv.extend(["--context", str(path)])
    if context_pack is not None:
        argv.extend(["--context-pack", str(context_pack)])
    if acquisition_bundle is not None:
        argv.extend(["--acquisition-bundle", str(acquisition_bundle)])
    if stop_after:
        argv.extend(["--stop-after", stop_after])
    if autonomous:
        argv.append("--autonomous")
    argv.extend(["--autonomous-max-functions", str(autonomous_max_functions)])
    argv.extend(["--autonomous-max-attempts", str(autonomous_max_attempts)])
    if autonomous_max_wall_seconds is not None:
        argv.extend(["--autonomous-max-wall-seconds", str(autonomous_max_wall_seconds)])
    if autonomous_max_campaigns != 1:
        argv.extend(["--autonomous-max-campaigns", str(autonomous_max_campaigns)])
    if autonomous_stop_on_accept:
        argv.append("--autonomous-stop-on-accept")
    if force:
        argv.append("--force")
    if not resume:
        argv.append("--no-resume")
    return build_parser().parse_args(argv)


def run_reconstruct_job(
    input_path: Path,
    *,
    work_dir: Path | None = None,
    preferred_name: str | None = None,
    context: list[Path] | None = None,
    context_pack: Path | None = None,
    acquisition_bundle: Path | None = None,
    stop_after: str | None = None,
    autonomous: bool = False,
    autonomous_max_functions: int = 1,
    autonomous_max_attempts: int = 3,
    autonomous_max_wall_seconds: int | None = None,
    autonomous_max_campaigns: int = 1,
    autonomous_stop_on_accept: bool = False,
    force: bool = False,
    resume: bool = True,
) -> dict[str, Any]:
    """Run reconstruct and return an MCP-friendly status/claim payload."""

    from .claim_report import build_claim_report
    from .recovery_status import build_recovery_status

    args = build_reconstruct_namespace(
        input_path,
        work_dir=work_dir,
        preferred_name=preferred_name,
        context=context,
        context_pack=context_pack,
        acquisition_bundle=acquisition_bundle,
        stop_after=stop_after,
        autonomous=autonomous,
        autonomous_max_functions=autonomous_max_functions,
        autonomous_max_attempts=autonomous_max_attempts,
        autonomous_max_wall_seconds=autonomous_max_wall_seconds,
        autonomous_max_campaigns=autonomous_max_campaigns,
        autonomous_stop_on_accept=autonomous_stop_on_accept,
        force=force,
        resume=resume,
    )
    resolved_work = args.work_dir or default_work_dir(args.input, args.preferred_name)
    exit_code = run_one_shot(args)
    claim = build_claim_report(work_dir=resolved_work, terminal_status="unknown")
    # Prefer on-disk claim-report written by run_one_shot when present.
    claim_path = resolved_work / "claim-report.json"
    if claim_path.is_file():
        try:
            claim = json.loads(claim_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    status = build_recovery_status(resolved_work)
    terminal = str(claim.get("terminalStatus") or status.get("terminalStatus") or ("matched" if exit_code == 0 else "failed"))
    budget = budget_from_args(
        max_functions=autonomous_max_functions,
        max_attempts_per_function=autonomous_max_attempts,
        max_wall_seconds=autonomous_max_wall_seconds,
        max_campaigns=autonomous_max_campaigns,
        stop_on_accept=autonomous_stop_on_accept,
    )
    return {
        "tool": "reconstruct",
        "exitCode": exit_code,
        "terminalStatus": terminal,
        "workDir": str(resolved_work.resolve()),
        "status": status,
        "claimReport": claim,
        "claimBoundary": (
            "orchestration outcome only; semantic recovery requires receipt-backed "
            "objdiff-verified-semantic artifacts under verified/"
        ),
        "autonomousRequested": bool(autonomous),
        "autonomyBudget": budget.to_json(),
    }


def upstream_status() -> dict[str, Any]:
    return {
        "schema": "agentdecompile.recovery.upstream-status.v1",
        "upstream": {
            "repository": "vendored reference implementation",
            "vendoredCommit": "218ecfe220ec9559ec914657f882b4e617cffe43",
            "commands": ["run", "atlas", "index-codebase"],
        },
        "mappedSurfaces": [
            {
                "upstreamSurface": "plugin lifecycle",
                "localSurface": "agentdecompile_recovery.plugin_pipeline.PluginPipeline",
                "status": "ported",
            },
            {
                "upstreamSurface": "programmatic source/objdiff phase",
                "localSurface": "agentdecompile_recovery.source_plugin_runner.run_source_plugin_pipeline",
                "status": "ported-for-source-slices",
            },
            {
                "upstreamSurface": "installable CLI front door",
                "localSurface": "agentdecompile-reconstruct <binary-or-folder>",
                "status": "adapted-for-binary-recovery",
            },
            {
                "upstreamSurface": "JSON reports",
                "localSurface": "target/agentdecompile-reconstruct/<target-id>/report.json and stage receipts",
                "status": "ported-for-binary-recovery",
            },
            {
                "upstreamSurface": "run",
                "localSurface": "scripts/decomp-cli.sh vacuum start (prompt-folder matching loop)",
                "status": "bridged",
            },
            {
                "upstreamSurface": "atlas",
                "localSurface": "scripts/decomp-cli.sh decomp-atlas",
                "status": "bridged",
            },
            {
                "upstreamSurface": "index-codebase",
                "localSurface": "scripts/decomp-cli.sh source-parity-feature-index",
                "status": "bridged",
            },
        ],
        "unmappedSurfaces": [
            {
                "upstreamSurface": "Claude runner",
                "reason": "default installable path uses deterministic source generation plus compiler/object gates, not Claude SDK calls",
            },
        ],
        "claimBoundary": "This reports CLI/core surface coverage only. It is not a semantic source recovery claim.",
    }


def run_upstream_status(args: argparse.Namespace) -> int:
    status = upstream_status()
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0
    print("Upstream reference surface mapping")
    print(f"- Vendored commit: {status['upstream']['vendoredCommit']}")
    for row in status["mappedSurfaces"]:
        print(f"- mapped: {row['upstreamSurface']} -> {row['localSurface']} ({row['status']})")
    for row in status["unmappedSurfaces"]:
        print(f"- not packaged: {row['upstreamSurface']} - {row['reason']}")
    print(f"- boundary: {status['claimBoundary']}")
    return 0


def run_self_check(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    capabilities = inspect_capabilities(repo_root)
    required_scripts = [
        "one-shot-source.py",
        "binary-source-roundtrip.py",
        "source-authority-report.py",
        "one-shot-source-proof.py",
        "one-shot-source-archive-verify.py",
        "one-shot-source-deliverable-verify.py",
        "one-shot-source-claims.py",
        "one-shot-source-validate.py",
        "one-shot-source-verify.py",
    ]
    scripts = {
        name: {
            "available": (path := resolve_script_asset(repo_root, name)) is not None,
            "path": str(path) if path else None,
        }
        for name in required_scripts
    }
    ok = all(item["available"] for item in scripts.values())
    report = {
        "schema": "agentdecompile.recovery.install-self-check.v1",
        "status": "ok" if ok else "missing-assets",
        "repoRoot": str(repo_root),
        "scriptAssets": scripts,
        "capabilities": capabilities,
        "upstreamStatus": upstream_status(),
        "claimBoundary": "Self-check verifies packaging and local tool discovery only; it does not run source recovery.",
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Status: {report['status']}")
        print(f"Repo root: {repo_root}")
        for name, item in scripts.items():
            marker = "ok" if item["available"] else "missing"
            print(f"- {marker}: {name} {item['path'] or ''}".rstrip())
        print(f"Boundary: {report['claimBoundary']}")
    return 0 if ok else 1


def run_upstream_command_guard(command: str) -> int:
    print(
        "\n".join(
            [
                f"agentdecompile-reconstruct: upstream command '{command}' is not packaged in this Python front door.",
                "Use `agentdecompile-reconstruct upstream-status` for the exact surface mapping.",
                "For direct binary recovery use: `agentdecompile-reconstruct <path/to/binary-or-folder>`.",
                "The vendored upstream TypeScript implementation remains under the repo's vendor tree in this checkout.",
            ]
        ),
        file=sys.stderr,
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args and args[0] == "self-check":
        return run_self_check(build_self_check_parser().parse_args(args[1:]))
    if args and args[0] == "upstream-status":
        return run_upstream_status(build_upstream_status_parser().parse_args(args[1:]))
    if args and args[0] in UPSTREAM_COMMANDS:
        return run_upstream_command(args[0], args[1:])
    if args and args[0] in LEGACY_COMMANDS:
        return legacy_main(args)
    parser = build_parser()
    return run_one_shot(parser.parse_args(args))


if __name__ == "__main__":
    raise SystemExit(main())
