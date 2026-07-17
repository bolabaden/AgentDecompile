"""Read-only stdio query service for acquisition bundles.

The protocol is deliberately small JSONL so it can be used directly or wrapped
by an MCP transport.  It exposes evidence and provenance, never verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import acquisition_registry
from .acquisition_bundle import coerce_int, load_bundle, query_entities


def query_bundle(
    bundle_dir: Path,
    *,
    action: str,
    query: str | None = None,
    address: int | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    manifest, entities, conflicts = load_bundle(bundle_dir)
    kind = {
        "get-function": "function",
        "get-global": "global",
        "get-type": "type",
        "get-xrefs": "xref",
    }.get(action)
    if action == "inspect":
        results: list[dict[str, Any]] = []
    elif action == "search-everything":
        results = query_entities(entities, query=query, address=address, limit=limit)
    elif kind:
        results = query_entities(entities, kind=kind, query=query, address=address, limit=limit)
    else:
        raise ValueError(f"unsupported acquisition query action: {action}")
    return {
        "schema": "agentdecompile.acquisition-query.v1",
        "status": "complete" if action == "inspect" or results else "not-found",
        "action": action,
        "query": query,
        "address": address,
        "bundle": {
            "schema": manifest["schema"],
            "target": manifest["target"],
            "targetFingerprint": manifest["targetFingerprint"],
            "entityCount": manifest["entityCount"],
            "conflictCount": len(conflicts),
        },
        "resultCount": len(results),
        "results": results,
        "conflicts": conflicts if action == "inspect" else [],
        "claimBoundary": "query results are advisory acquisition evidence only; compile and objdiff gates remain required.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only JSONL acquisition-bundle query service.")
    parser.add_argument("--bundle", type=Path, help="Explicit bundle dir. Omit to auto-resolve the latest registered bundle.")
    parser.add_argument("--stdio", action="store_true", help="Read JSON request lines and write JSON response lines.")
    parser.add_argument("--action", default="inspect", choices=["inspect", "search-everything", "get-function", "get-global", "get-type", "get-xrefs"])
    parser.add_argument("--query")
    parser.add_argument("--address", type=lambda value: int(value, 0))
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args(argv)
    bundle = acquisition_registry.resolve_bundle(explicit=args.bundle, allow_latest=True)
    if bundle is None:
        print(json.dumps({"schema": "agentdecompile.acquisition-query.v1", "status": "unavailable", "reason": "no acquisition bundle found; run acquisition first or pass --bundle"}, sort_keys=True))
        return 1
    if not args.stdio:
        print(json.dumps(query_bundle(bundle, action=args.action, query=args.query, address=args.address, limit=args.limit), sort_keys=True))
        return 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request: dict[str, Any] = json.loads(line)
            raw_address = request.get("address")
            address = coerce_int(raw_address)
            if raw_address not in (None, "") and address is None:
                raise ValueError(f"invalid address: {raw_address!r}")
            response = query_bundle(
                bundle,
                action=str(request.get("action") or "inspect"),
                query=request.get("query"),
                address=address,
                limit=int(request.get("limit") or args.limit),
            )
        except Exception as exc:  # Keep stdio transport alive for independent requests.
            response = {"schema": "agentdecompile.acquisition-query.v1", "status": "error", "reason": str(exc)}
        print(json.dumps(response, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
