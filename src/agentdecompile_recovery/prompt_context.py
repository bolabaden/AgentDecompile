"""Project hash-pinned, advisory acquisition evidence into a prompt folder."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from . import acquisition_registry
from .acquisition_bundle import load_bundle, query_entities, write_json


def parse_simple_yaml(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line or raw_line[0].isspace() or ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            value = value[1:-1]
        values[key] = value
    return values


def infer_prompt_function(prompt_dir: Path) -> str | None:
    for name in ("case.yaml", "settings.yaml"):
        metadata = parse_simple_yaml(prompt_dir / name)
        function = metadata.get("functionName") or metadata.get("caseId")
        if function:
            return function
    return prompt_dir.name or None


def resolve_prompt_bundle(prompt_dir: Path, explicit: Path | None, repo_root: Path | None) -> Path | None:
    if explicit is not None:
        return acquisition_registry.resolve_bundle(explicit=explicit, repo_root=repo_root)
    metadata = parse_simple_yaml(prompt_dir / "case.yaml")
    binary_path = metadata.get("binaryPath")
    target: dict[str, Any] | None = None
    if binary_path:
        candidate = Path(binary_path)
        if candidate.exists():
            try:
                from .targets import identify_binary

                target = identify_binary(candidate).to_json()
            except (FileNotFoundError, OSError, ValueError):
                target = None
    return acquisition_registry.resolve_bundle(target=target, repo_root=repo_root, allow_latest=True)


def project_prompt_context(
    *,
    bundle_dir: Path,
    prompt_dir: Path,
    function: str,
    target_fingerprint: str | None = None,
) -> dict[str, Any]:
    manifest, entities, conflicts = load_bundle(bundle_dir)
    if target_fingerprint and manifest.get("targetFingerprint") != target_fingerprint:
        return {
            "schema": "agentdecompile.prompt-acquisition-context.v1",
            "status": "target-mismatch",
            "written": False,
            "expectedTargetFingerprint": target_fingerprint,
            "bundleTargetFingerprint": manifest.get("targetFingerprint"),
            "claimBoundary": "no prompt context was written because target binding did not match.",
        }
    address = parse_address(function)
    rows = query_entities(entities, kind="function", query=function, address=address, limit=5)
    if not rows and address is not None:
        rows = query_entities(entities, kind="function", address=address, limit=5)
    receipt = {
        "schema": "agentdecompile.prompt-acquisition-context.v1",
        "status": "complete" if rows else "not-found",
        "bundleTargetFingerprint": manifest.get("targetFingerprint"),
        "bundleTarget": manifest.get("target"),
        "bundleEntities": [row["id"] for row in rows],
        "function": function,
        "functionAddress": address,
        "functionEvidence": rows,
        "conflicts": [row for row in conflicts if any(entity_id in row.get("entityIds", []) for entity_id in [item["id"] for item in rows])],
        "claimBoundary": "prompt acquisition context is advisory evidence only; objdiff zero remains the acceptance gate.",
    }
    prompt_dir.mkdir(parents=True, exist_ok=True)
    output = prompt_dir / "acquisition-context.json"
    write_json(output, receipt)
    receipt["path"] = str(output)
    receipt["written"] = True
    return receipt


def parse_address(value: str) -> int | None:
    if value.lower().startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return None
    match = re.search(r"(?:FUN_|sub_|fcn[._])([0-9a-fA-F]{4,16})", value)
    return int(match.group(1), 16) if match else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Project advisory acquisition evidence into a prompt folder. Only the prompt dir is required; function and bundle are inferred.")
    parser.add_argument("prompt", type=Path, nargs="?", help="Prompt folder (positional). Same as --prompt-dir.")
    parser.add_argument("--prompt-dir", type=Path, help="Prompt folder.")
    parser.add_argument("--bundle", type=Path, help="Explicit bundle dir. Omit to auto-resolve from the prompt's case.yaml target or the latest registered bundle.")
    parser.add_argument("--function", help="Function name or address. Omit to infer from case.yaml/settings.yaml.")
    parser.add_argument("--target-fingerprint")
    parser.add_argument("--repo-root", type=Path, help="Registry lookup root. Defaults to the current directory.")
    args = parser.parse_args(argv)
    prompt_dir = args.prompt_dir or args.prompt
    if prompt_dir is None:
        parser.error("a prompt folder is required (positional or --prompt-dir)")
    function = args.function or infer_prompt_function(prompt_dir)
    if not function:
        parser.error("could not infer a function from the prompt folder; pass --function")
    bundle_dir = resolve_prompt_bundle(prompt_dir, args.bundle, args.repo_root)
    if bundle_dir is None:
        print(json.dumps({
            "schema": "agentdecompile.prompt-acquisition-context.v1",
            "status": "unavailable",
            "written": False,
            "reason": "no acquisition bundle found; run acquisition first or pass --bundle",
        }, indent=2, sort_keys=True))
        return 1
    receipt = project_prompt_context(
        bundle_dir=bundle_dir,
        prompt_dir=prompt_dir,
        function=function,
        target_fingerprint=args.target_fingerprint,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
