"""Context-pack ingestion for recovery runs.

This module turns mixed user-supplied context into AgentDecompile-compatible
acquisition facts.  Context is evidence, not proof: every derived row keeps
provenance and remains gated by compile/objdiff later in the pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .acquisition_bundle import build_bundle, content_sha256, source_record


TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".hxx",
    ".md",
    ".txt",
    ".log",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
}

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
NOTE_SUFFIXES = {".md", ".txt", ".log", ".yaml", ".yml"}

FUNCTION_HEADER_LINE_RE = re.compile(
    r"^\s*(?P<header>(?:[A-Za-z_][\w:*&<>~,]*\s+)+(?P<name>[A-Za-z_][\w$.@]*|sub_[0-9A-Fa-f]+|fcn[._][0-9A-Fa-f]+)\s*\([^;{}]*\)\s*)\{"
)
ADDRESS_RE = re.compile(r"(?:0x|RVA\s*[:=]\s*0x|VA\s*[:=]\s*0x)([0-9A-Fa-f]{4,16})", re.IGNORECASE)
NAME_ADDRESS_RE = re.compile(r"(?:sub_|fcn[._]|FUN_)([0-9A-Fa-f]{4,16})", re.IGNORECASE)


def receipt_path(path: Path, repo_root: Path | None) -> str:
    resolved = path.resolve()
    if repo_root:
        try:
            return str(resolved.relative_to(repo_root.resolve()))
        except ValueError:
            pass
    return str(resolved)


def build_context_pack(
    *,
    contexts: list[Path],
    out_dir: Path,
    target: dict[str, Any] | None = None,
    repo_root: Path | None = None,
    max_files: int = 500,
    max_text_bytes: int = 10_000_000,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = list(discover_context_files(contexts, max_files=max_files))
    facts: list[dict[str, Any]] = []
    context_items: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for path in files:
        if not path.exists():
            skipped.append({"path": str(path), "reason": "missing"})
            continue
        if path.is_dir():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            skipped.append({"path": receipt_path(path, repo_root), "reason": "unsupported-suffix"})
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:max_text_bytes]
        except OSError as exc:
            skipped.append({"path": receipt_path(path, repo_root), "reason": f"read-failed: {exc}"})
            continue
        source_id = stable_source_id(path, text)
        parsed_facts, parsed_items = parse_context_file(path, text, source_id=source_id, repo_root=repo_root)
        facts.extend(parsed_facts)
        context_items.extend(parsed_items)

    facts = dedupe_facts(facts)
    facts_path = out_dir / "function-facts.jsonl"
    facts_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in facts), encoding="utf-8")
    items_path = out_dir / "context-items.jsonl"
    items_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in context_items), encoding="utf-8")
    bundle_dir = out_dir / "acquisition-bundle"
    sources = []
    for item in context_items:
        source_id = str(item.get("sourceId") or item.get("path") or "unknown")
        sources.append(
            source_record(
                path=str(item.get("path") or ""),
                source_id=source_id,
                kind=str(item.get("kind") or "context-item"),
                content_hash=str(item.get("textSha256") or content_sha256(json.dumps(item, sort_keys=True))),
                extractor="context-pack",
            )
        )
    source_ids = {row["id"] for row in sources}
    for fact in facts:
        source_id = str(fact.get("sourceId") or fact.get("contextSource") or "unknown")
        if source_id in source_ids:
            continue
        sources.append(
            source_record(
                path=str(fact.get("contextSource") or ""),
                source_id=source_id,
                kind=str(fact.get("sourceKind") or "context-fact"),
                content_hash=str(fact.get("decompiledSha256") or content_sha256(json.dumps(fact, sort_keys=True))),
                extractor=str(fact.get("tool") or "context-pack"),
            )
        )
        source_ids.add(source_id)
    bundle_manifest = build_bundle(
        out_dir=bundle_dir,
        target=target,
        sources=sources,
        facts=facts,
        items=context_items,
        extractor_config={"maxFiles": max_files, "maxTextBytes": max_text_bytes},
    )
    unplaced = [
        {
            "sourceId": row.get("sourceId"),
            "name": row.get("name") or row.get("title"),
            "kind": row.get("sourceKind") or row.get("kind"),
            "reason": "no-canonical-address",
            "claimBoundary": "unplaced context is retained as acquisition evidence only.",
        }
        for row in [*facts, *context_items]
        if coerce_int(row.get("entryOffset") or row.get("address")) is None
    ]
    failed = [row for row in skipped if str(row.get("reason", "")).startswith("read-failed:")]
    manifest = {
        "schema": "agentdecompile.context-pack.v1",
        "status": "complete",
        "target": target or {},
        "inputs": [receipt_path(path, repo_root) for path in contexts],
        "filesVisited": len(files),
        "factsImported": len(facts),
        "contextItems": len(context_items),
        "skipped": skipped,
        "failed": failed,
        "unplaced": unplaced,
        "factsJsonl": receipt_path(facts_path, repo_root),
        "contextItemsJsonl": receipt_path(items_path, repo_root),
        "bundleDir": receipt_path(bundle_dir, repo_root),
        "bundleManifest": receipt_path(bundle_dir / "manifest.json", repo_root),
        "bundleTargetFingerprint": bundle_manifest["targetFingerprint"],
        "bundleConflictCount": bundle_manifest["conflictCount"],
        "claimBoundary": "context-pack rows are acquisition evidence only; compile and objdiff gates remain required.",
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def discover_context_files(paths: list[Path], *, max_files: int) -> Iterable[Path]:
    count = 0
    for root in paths:
        if count >= max_files:
            break
        if root.is_file():
            count += 1
            yield root
            continue
        if not root.is_dir():
            count += 1
            yield root
            continue
        for path in sorted(root.rglob("*")):
            if count >= max_files:
                break
            if path.is_file():
                count += 1
                yield path


def parse_context_file(path: Path, text: str, *, source_id: str, repo_root: Path | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        facts = [contextualize_fact(row, path, source_id, "jsonl-fact", repo_root) for row in load_jsonl_text(text)]
        return [row for row in facts if row], []
    if suffix == ".json":
        facts, items = parse_json_context(path, text, source_id=source_id, repo_root=repo_root)
        return facts, items
    if suffix in SOURCE_SUFFIXES:
        return parse_source_dump(path, text, source_id=source_id, repo_root=repo_root), []
    if suffix in NOTE_SUFFIXES:
        item = parse_note(path, text, source_id=source_id, repo_root=repo_root)
        fact = note_to_fact(item) if item.get("entryOffset") or item.get("name") else None
        return [fact] if fact else [], [item]
    return [], []


def parse_json_context(path: Path, text: str, *, source_id: str, repo_root: Path | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [], [{"schema": "agentdecompile.context-item.v1", "kind": "json-unparsed", "path": receipt_path(path, repo_root), "sourceId": source_id}]
    if isinstance(payload, dict) and payload.get("schema") == "agentdecompile.one-shot-source-function-reconstruction-tasks.v1":
        return parse_one_shot_reconstruction_tasks(path, payload, source_id=source_id, repo_root=repo_root), []
    rows: list[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("facts", "functions", "items", "rows"):
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
        else:
            rows = [payload]
    else:
        rows = []
    facts: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        fact = contextualize_fact(row, path, source_id, "json-fact", repo_root)
        if fact.get("name") or fact.get("entryOffset") or fact.get("decompiled"):
            facts.append(fact)
        else:
            items.append(
                {
                    "schema": "agentdecompile.context-item.v1",
                    "kind": "json-context",
                    "path": receipt_path(path, repo_root),
                    "sourceId": source_id,
                    "payload": row,
                    "claimBoundary": "unplaced JSON context is evidence only",
                }
            )
    return facts, items


def parse_one_shot_reconstruction_tasks(path: Path, payload: dict[str, Any], *, source_id: str, repo_root: Path | None) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    package_dir = path.parent
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        task_json = resolve_relative_path(package_dir, task.get("taskJson"))
        task_payload = read_json_file(task_json) if task_json else {}
        target = task_payload.get("target") if isinstance(task_payload.get("target"), dict) else {}
        address = coerce_hex_address(target.get("address")) or coerce_int(task.get("address") or task.get("entryOffset") or task.get("entry"))
        if address is None:
            address = extract_address(str(task.get("name") or ""))
        size = coerce_int(target.get("size") or task.get("targetSize") or task.get("bodyBytes"))
        name = str(task_payload.get("name") or task.get("name") or (f"sub_{address:x}" if address is not None else f"task_{index:04d}"))
        reference = task_payload.get("referenceByteEmitter") if isinstance(task_payload.get("referenceByteEmitter"), dict) else {}
        fact = {
            "schema": "agentdecompile.context-function-fact.v1",
            "provider": "agentdecompile",
            "tool": "context-pack-one-shot-reconstruction-tasks",
            "sourceKind": "one-shot-reconstruction-task",
            "name": normalize_function_name(name),
            "entryOffset": address,
            "address": address,
            "bodyBytes": size,
            "section": target.get("sectionName") or task.get("sectionName"),
            "targetFileOffset": coerce_int(target.get("fileOffset") or task.get("targetFileOffset")),
            "targetBytes": task.get("targetBytes") or target.get("path"),
            "targetBytesSha256": target.get("sha256") or task.get("targetBytesSha256"),
            "referenceByteEmitter": reference.get("path") or task.get("referenceByteEmitter"),
            "referenceByteEmitterSha256": reference.get("sha256"),
            "semanticDecompilation": False,
            "confidence": "one-shot-byte-slice-task",
            "contextSource": receipt_path(path, repo_root),
            "sourceId": source_id,
            "taskIndex": index,
            "taskJson": receipt_path(task_json, repo_root) if task_json else None,
            "claimBoundary": "one-shot reconstruction task is byte-slice acquisition evidence only; semantic source still requires compiler and objdiff gates.",
        }
        if address is not None and size is not None and size > 0:
            facts.append(fact)
    return facts


def resolve_relative_path(base: Path, value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value))
    if path.is_absolute():
        return path
    return base / path


def read_json_file(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def coerce_hex_address(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return coerce_int(text)
    if re.fullmatch(r"[0-9A-Fa-f]{4,16}", text):
        return int(text, 16)
    return coerce_int(text)


def parse_source_dump(path: Path, text: str, *, source_id: str, repo_root: Path | None) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    offsets = line_start_offsets(text)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = FUNCTION_HEADER_LINE_RE.match(line)
        if not match:
            continue
        source_start = offsets[index]
        brace_index = text.find("{", source_start)
        if brace_index < 0:
            continue
        body_end = find_matching_brace(text, brace_index)
        if body_end is None:
            continue
        source = text[source_start : body_end + 1].strip()
        name = normalize_function_name(match.group("name"))
        prelude_start = offsets[max(0, index - 5)]
        prelude = text[prelude_start:source_start]
        entry = extract_address(prelude) or extract_address(match.group("header")) or extract_address(name)
        facts.append(
            {
                "schema": "agentdecompile.context-function-fact.v1",
                "provider": "agentdecompile",
                "tool": "context-pack-source-dump",
                "sourceKind": "context-pack-source-dump",
                "name": name,
                "entryOffset": entry,
                "address": entry,
                "decompiled": source + "\n",
                "language": "c" if path.suffix.lower() in {".c", ".h"} else "c++",
                "confidence": "context-source-dump",
                "contextSource": receipt_path(path, repo_root),
                "sourceId": source_id,
                "decompiledSha256": hashlib.sha256((source + "\n").encode("utf-8")).hexdigest(),
                "claimBoundary": "source dump text is unverified acquisition context; compile and objdiff gates remain required.",
            }
        )
    return facts


def line_start_offsets(text: str) -> list[int]:
    offsets = []
    offset = 0
    for line in text.splitlines(True):
        offsets.append(offset)
        offset += len(line)
    if not offsets:
        offsets.append(0)
    return offsets


def parse_note(path: Path, text: str, *, source_id: str, repo_root: Path | None) -> dict[str, Any]:
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    entry = extract_address(text[:1000])
    name_match = re.search(r"\b(?:function|func|name)\s*[:=]\s*([A-Za-z_][\w$.@]*)", text, re.IGNORECASE)
    return {
        "schema": "agentdecompile.context-item.v1",
        "kind": "note",
        "path": receipt_path(path, repo_root),
        "sourceId": source_id,
        "title": first_line[:160],
        "name": name_match.group(1) if name_match else None,
        "entryOffset": entry,
        "textSha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "textPreview": text[:1000],
        "claimBoundary": "note context is unverified evidence and cannot promote source parity.",
    }


def note_to_fact(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "agentdecompile.context-function-fact.v1",
        "provider": "agentdecompile",
        "tool": "context-pack-note",
        "sourceKind": "context-pack-note",
        "name": item.get("name") or (f"note_{int(item['entryOffset']):x}" if item.get("entryOffset") else None),
        "entryOffset": item.get("entryOffset"),
        "address": item.get("entryOffset"),
        "notes": item.get("textPreview"),
        "confidence": "context-note",
        "contextSource": item.get("path"),
        "sourceId": item.get("sourceId"),
        "claimBoundary": "note-derived function fact is acquisition context only; compile and objdiff gates remain required.",
    }


def contextualize_fact(row: dict[str, Any], path: Path, source_id: str, source_kind: str, repo_root: Path | None) -> dict[str, Any]:
    fact = dict(row)
    if "decompiled" not in fact and fact.get("decompiledCode"):
        fact["decompiled"] = fact.get("decompiledCode")
    entry = coerce_int(fact.get("entryOffset") or fact.get("entry") or fact.get("address") or fact.get("rva"))
    if entry is None and fact.get("name"):
        entry = extract_address(str(fact.get("name")))
    fact["entryOffset"] = entry
    if entry is not None:
        fact.setdefault("address", entry)
    fact.setdefault("provider", "agentdecompile")
    fact.setdefault("tool", "context-pack")
    fact.setdefault("sourceKind", source_kind)
    fact.setdefault("confidence", "context-fact")
    fact["contextSource"] = receipt_path(path, repo_root)
    fact["sourceId"] = source_id
    fact.setdefault("claimBoundary", "context fact is acquisition evidence only; compile and objdiff gates remain required.")
    return fact


def load_jsonl_text(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def find_matching_brace(text: str, open_index: int) -> int | None:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_index, len(text)):
        ch = text[index]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {'"', "'"}:
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def extract_address(text: str) -> int | None:
    match = ADDRESS_RE.search(text)
    if match:
        return int(match.group(1), 16)
    match = NAME_ADDRESS_RE.search(text)
    if match:
        return int(match.group(1), 16)
    return None


def normalize_function_name(name: str) -> str:
    return name.replace(".", "_")


def stable_source_id(path: Path, text: str) -> str:
    digest = hashlib.sha256()
    digest.update(str(path).encode("utf-8", errors="replace"))
    digest.update(b"\0")
    digest.update(text.encode("utf-8", errors="replace"))
    return digest.hexdigest()


def dedupe_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, Any, Any]] = set()
    output: list[dict[str, Any]] = []
    for fact in facts:
        key = (fact.get("entryOffset"), fact.get("name"), fact.get("decompiledSha256") or fact.get("sourceId"))
        if key in seen:
            continue
        seen.add(key)
        output.append(fact)
    return output


def coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return int(stripped, 0)
        except ValueError:
            if re.fullmatch(r"[0-9A-Fa-f]{4,16}", stripped):
                return int(stripped, 16)
            return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, action="append", required=True, help="Context file or directory. Repeat for multiple inputs.")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target-json", type=Path, help="Optional target.json to embed in the manifest.")
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--max-text-bytes", type=int, default=10_000_000)
    args = parser.parse_args(argv)
    target = {}
    if args.target_json and args.target_json.exists():
        target = json.loads(args.target_json.read_text(encoding="utf-8"))
    repo_root = Path(__file__).resolve().parents[2]
    manifest = build_context_pack(
        contexts=args.context,
        out_dir=args.out_dir,
        target=target,
        repo_root=repo_root,
        max_files=args.max_files,
        max_text_bytes=args.max_text_bytes,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
