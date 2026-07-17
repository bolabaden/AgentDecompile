"""Target-bound, provenance-preserving acquisition context bundles.

Bundles contain reverse-engineering evidence only.  They never establish a
source-parity claim; compiler/objdiff verification remains the acceptance gate.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "agentdecompile.acquisition-bundle.v1"
CLAIM_BOUNDARY = "acquisition evidence only; compile and objdiff gates remain required."


def canonical_target(target: dict[str, Any] | None) -> dict[str, Any]:
    target = target or {}
    return {
        "stableId": target.get("stableId"),
        "sha256": target.get("sha256"),
        "analysisImageSha256": target.get("analysisImageSha256") or target.get("analysisSha256"),
        "format": target.get("format"),
        "architecture": target.get("architectureHint") or target.get("architecture"),
        "imageBase": target.get("imageBase"),
    }


def target_fingerprint(target: dict[str, Any] | None) -> str:
    encoded = json.dumps(canonical_target(target), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def content_sha256(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def source_record(
    *,
    path: str,
    source_id: str,
    kind: str,
    content_hash: str,
    extractor: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "agentdecompile.acquisition-source.v1",
        "id": source_id,
        "kind": kind,
        "path": path,
        "contentSha256": content_hash,
        "extractor": extractor,
        "metadata": metadata or {},
        "claimBoundary": CLAIM_BOUNDARY,
    }


def entity_from_fact(fact: dict[str, Any]) -> dict[str, Any]:
    entry = coerce_int(fact.get("entryOffset") or fact.get("entry") or fact.get("address") or fact.get("rva"))
    entity_type = classify_entity(fact)
    source_id = str(fact.get("sourceId") or fact.get("contextSource") or "unknown")
    address_space = str(fact.get("addressSpace") or "ram")
    entity_id = stable_entity_id(entity_type, address_space, entry, source_id, fact.get("name"))
    entity = {
        "schema": "agentdecompile.acquisition-entity.v1",
        "id": entity_id,
        "kind": entity_type,
        "name": fact.get("name") or fact.get("label"),
        "aliases": aliases_for(fact),
        "addressSpace": address_space,
        "address": entry,
        "range": normalized_range(fact, entry),
        "sourceId": source_id,
        "provider": fact.get("provider") or "context-pack",
        "tool": fact.get("tool") or "context-pack",
        "sourceKind": fact.get("sourceKind") or "context-fact",
        "confidence": fact.get("confidence") or "context-fact",
        "payload": fact,
        "claimBoundary": fact.get("claimBoundary") or CLAIM_BOUNDARY,
    }
    return entity


def classify_entity(fact: dict[str, Any]) -> str:
    explicit = fact.get("entityKind") or fact.get("kind")
    if explicit in {"function", "label", "global", "type", "xref", "note"}:
        return str(explicit)
    if fact.get("decompiled") or fact.get("decompiledCode") or fact.get("prototype") or fact.get("bodyBytes"):
        return "function"
    if fact.get("type") or fact.get("definition") or fact.get("dataType"):
        return "type"
    if fact.get("references") or fact.get("fromAddress") or fact.get("toAddress"):
        return "xref"
    if fact.get("globals") or fact.get("global"):
        return "global"
    return "note"


def aliases_for(fact: dict[str, Any]) -> list[str]:
    aliases = [value for value in [fact.get("name"), fact.get("label")] if isinstance(value, str) and value]
    for value in fact.get("aliases") or []:
        if isinstance(value, str) and value:
            aliases.append(value)
    return sorted(set(aliases))


def normalized_range(fact: dict[str, Any], entry: int | None) -> dict[str, int] | None:
    size = coerce_int(fact.get("bodyBytes") or fact.get("size"))
    if entry is None or size is None or size <= 0:
        return None
    return {"start": entry, "end": entry + size}


def stable_entity_id(kind: str, address_space: str, address: int | None, source_id: str, name: Any) -> str:
    canonical = f"{kind}\0{address_space}\0{address if address is not None else ''}\0{source_id}\0{name or ''}"
    return f"{kind}-{content_sha256(canonical)[:16]}"


def build_bundle(
    *,
    out_dir: Path,
    target: dict[str, Any] | None,
    sources: Iterable[dict[str, Any]],
    facts: Iterable[dict[str, Any]],
    items: Iterable[dict[str, Any]] = (),
    extractor_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write a deterministic bundle and its legacy function-facts projection."""

    out_dir.mkdir(parents=True, exist_ok=True)
    normalized_sources = sorted((dict(row) for row in sources), key=lambda row: str(row.get("id") or row.get("path")))
    entities = [entity_from_fact(dict(row)) for row in facts]
    entities.extend(entity_from_fact(dict(row)) for row in items)
    entities = sorted(entities, key=entity_sort_key)
    conflicts = detect_conflicts(entities)
    target_data = canonical_target(target)
    manifest = {
        "schema": SCHEMA,
        "status": "complete",
        "target": target_data,
        "targetFingerprint": target_fingerprint(target_data),
        "extractorConfig": extractor_config or {},
        "sourceCount": len(normalized_sources),
        "entityCount": len(entities),
        "conflictCount": len(conflicts),
        "sourcesJsonl": "sources.jsonl",
        "entitiesJsonl": "entities.jsonl",
        "conflictsJsonl": "conflicts.jsonl",
        "factsJsonl": "function-facts.jsonl",
        "claimBoundary": CLAIM_BOUNDARY,
    }
    write_jsonl(out_dir / "sources.jsonl", normalized_sources)
    write_jsonl(out_dir / "entities.jsonl", entities)
    write_jsonl(out_dir / "conflicts.jsonl", conflicts)
    write_jsonl(out_dir / "function-facts.jsonl", function_fact_projection(entities))
    write_json(out_dir / "manifest.json", manifest)
    return manifest


def entity_sort_key(entity: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(entity.get("kind") or ""),
        str(entity.get("addressSpace") or ""),
        entity.get("address") if entity.get("address") is not None else -1,
        str(entity.get("name") or ""),
        str(entity.get("id") or ""),
    )


def detect_conflicts(entities: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for entity in entities:
        address = entity.get("address")
        if address is None:
            continue
        key = (str(entity.get("kind")), str(entity.get("addressSpace")), int(address))
        grouped[key].append(entity)
    conflicts: list[dict[str, Any]] = []
    for (kind, address_space, address), rows in sorted(grouped.items()):
        names = sorted({str(row.get("name")) for row in rows if row.get("name")})
        if len(names) <= 1:
            continue
        conflicts.append(
            {
                "schema": "agentdecompile.acquisition-conflict.v1",
                "kind": kind,
                "addressSpace": address_space,
                "address": address,
                "entityIds": sorted(str(row["id"]) for row in rows),
                "names": names,
                "resolution": "unresolved",
                "claimBoundary": CLAIM_BOUNDARY,
            }
        )
    return conflicts


def function_fact_projection(entities: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for entity in entities:
        if entity.get("kind") != "function":
            continue
        fact = dict(entity.get("payload") or {})
        fact.setdefault("name", entity.get("name"))
        fact.setdefault("entryOffset", entity.get("address"))
        fact.setdefault("address", entity.get("address"))
        fact["acquisitionEntityId"] = entity["id"]
        fact["acquisitionSourceId"] = entity.get("sourceId")
        fact["claimBoundary"] = fact.get("claimBoundary") or CLAIM_BOUNDARY
        facts.append(fact)
    return sorted(facts, key=lambda row: (coerce_int(row.get("entryOffset")) or -1, str(row.get("name") or "")))


def load_bundle(bundle_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"acquisition bundle manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError(f"unsupported acquisition bundle schema: {manifest.get('schema')!r}")
    entities = load_jsonl(bundle_dir / str(manifest.get("entitiesJsonl") or "entities.jsonl"))
    conflicts = load_jsonl(bundle_dir / str(manifest.get("conflictsJsonl") or "conflicts.jsonl"))
    return manifest, entities, conflicts


def validate_bundle_target(
    manifest: dict[str, Any],
    target: dict[str, Any] | None,
    *,
    allow_mismatch: bool = False,
) -> dict[str, Any]:
    expected = str(manifest.get("targetFingerprint") or "")
    actual = target_fingerprint(target)
    if expected == actual:
        return {"status": "complete", "targetMatched": True, "override": False}
    result = {
        "status": "overridden" if allow_mismatch else "target-mismatch",
        "targetMatched": False,
        "override": allow_mismatch,
        "expectedTargetFingerprint": expected,
        "actualTargetFingerprint": actual,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    if not allow_mismatch:
        raise ValueError(json.dumps(result, sort_keys=True))
    return result


def query_entities(
    entities: Iterable[dict[str, Any]],
    *,
    kind: str | None = None,
    query: str | None = None,
    address: int | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    query_folded = (query or "").casefold()
    rows: list[dict[str, Any]] = []
    for entity in entities:
        if kind and entity.get("kind") != kind:
            continue
        if address is not None and entity.get("address") != address:
            continue
        names = [str(entity.get("name") or ""), *(str(value) for value in entity.get("aliases") or [])]
        if query_folded and not any(query_folded in name.casefold() for name in names):
            continue
        rows.append(entity)
    return sorted(rows, key=entity_sort_key)[: max(0, limit)]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        try:
            return int(str(value), 16)
        except (TypeError, ValueError):
            return None
