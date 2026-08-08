"""Local Decomp Atlas-style retrieval over workspace feature indexes."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .decomp_function_corpus import DecompFunctionCorpus
    from .semantic_embedder import SemanticEmbedder


def run_decomp_atlas(
    *,
    prompt_name: str | None,
    query: str | None,
    prompts_dir: Path,
    index_root: Path,
    top_k: int,
    write_prompt: bool = False,
    corpus: "DecompFunctionCorpus | None" = None,
    embedder: "SemanticEmbedder | None" = None,
    min_match_percent: float | None = None,
) -> dict[str, Any]:
    prompt_dir = resolve_prompt_dir(prompt_name, prompts_dir)
    query_text = build_query_text(prompt_name, query, prompt_dir)
    retrieval_rows = load_index_rows(index_root, "retrieval.jsonl")
    matched_rows = load_index_rows(index_root, "matched-examples.jsonl")
    prompt_rows = load_matched_prompt_rows(prompts_dir)
    matched_rows.extend(prompt_rows)
    results = search_retrieval_rows(query_text, retrieval_rows, matched_rows, top_k)
    receipt = {
        "schema": "reconkit.decomp-atlas.local-search.v1",
        "status": "complete" if results else "no-local-examples",
        "prompt": str(prompt_dir) if prompt_dir else None,
        "query": query_text,
        "indexes": [str(path) for path in sorted(index_root.glob("*/retrieval.jsonl"))],
        "promptExampleCount": len(prompt_rows),
        "resultCount": len(results),
        "results": results,
        "claimBoundary": "Atlas retrieval is advisory prompt context only; objdiff zero remains the acceptance gate.",
    }
    # Optional embedding-based retrieval (see decomp_indexer.py / semantic_embedder.py):
    # purely additive so the token-overlap path above -- the tested, dependency-free
    # default -- is unaffected whether or not a corpus/embedder is supplied.
    if corpus is not None and embedder is not None and query_text.strip():
        receipt["semanticResults"] = semantic_search(
            query_text, corpus, embedder, top_k, min_match_percent=min_match_percent
        )
    if write_prompt and prompt_dir:
        receipt["promptUpdate"] = write_prompt_similar_examples(prompt_dir, receipt)
    return receipt


def semantic_search(
    query_text: str,
    corpus: "DecompFunctionCorpus",
    embedder: "SemanticEmbedder",
    top_k: int,
    *,
    min_match_percent: float | None = None,
) -> list[dict[str, Any]]:
    """Embedding-based nearest-neighbor search over a DecompFunctionCorpus.

    Complements search_retrieval_rows' token overlap: embeds the query text
    and ranks corpus functions by cosine similarity against their (already
    unit-normalized) vectors. Functions with no embedding are silently
    excluded rather than treated as a zero-similarity match.

    Results carry each function's objdiff outcome, and `min_match_percent`
    drops those that never reached it. A neighbour whose C is known to
    compile to its own target is worth more as prompt context than an equally
    close one nobody verified, and the caller cannot tell them apart unless
    this says so.
    """
    vectors = corpus.vectors
    if not vectors:
        return []

    embeddings = embedder.embed_batch([query_text])
    if not embeddings:
        return []
    query_vector = embeddings[0]
    norm = math.sqrt(sum(value * value for value in query_vector))
    if norm <= 0:
        return []
    normalized_query = [value / norm for value in query_vector]

    scored: list[tuple[float, str]] = []
    for function_id, vector in vectors.items():
        if len(vector) != len(normalized_query):
            continue
        similarity = sum(a * b for a, b in zip(normalized_query, vector))
        scored.append((similarity, function_id))
    scored.sort(key=lambda item: item[0], reverse=True)

    results: list[dict[str, Any]] = []
    for similarity, function_id in scored:
        if len(results) >= max(1, top_k):
            break
        fn = corpus.get_function_by_id(function_id)
        if fn is None:
            continue
        if min_match_percent is not None and (fn.match_percent is None or fn.match_percent < min_match_percent):
            continue
        results.append(
            {
                "index": "semantic-atlas",
                "name": fn.name,
                "entry": function_id,
                "similarity": round(similarity, 6),
                "candidateSource": fn.c_module_path,
                "matchPercent": fn.match_percent,
            }
        )
    return results


def resolve_prompt_dir(prompt_name: str | None, prompts_dir: Path) -> Path | None:
    if not prompt_name:
        return None
    path = Path(prompt_name)
    if path.exists():
        return path
    candidate = prompts_dir / prompt_name
    if candidate.exists():
        return candidate
    return None


def build_query_text(prompt_name: str | None, query: str | None, prompt_dir: Path | None) -> str:
    parts: list[str] = []
    if prompt_name:
        parts.append(prompt_name)
    if query:
        parts.append(query)
    if prompt_dir:
        for name in ["case.yaml", "settings.yaml", "prompt.md", "notes.md", "acquisition-context.json"]:
            path = prompt_dir / name
            if path.exists():
                parts.append(path.read_text(encoding="utf-8", errors="replace")[:20_000])
    return "\n".join(parts)


def load_index_rows(index_root: Path, filename: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(index_root.glob(f"*/{filename}")):
        for row in load_jsonl(path):
            row = dict(row)
            row["_index"] = str(path.parent.name)
            rows.append(row)
    return rows


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def load_matched_prompt_rows(prompts_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not prompts_dir.exists():
        return rows
    for case_path in sorted(prompts_dir.glob("*/case.yaml")):
        metadata = parse_simple_case_yaml(case_path)
        if str(metadata.get("status") or "").lower() != "matched":
            continue
        prompt_dir = case_path.parent
        name = str(metadata.get("functionName") or metadata.get("caseId") or prompt_dir.name)
        row = {
            "_index": "prompt-folder",
            "name": name,
            "entry": infer_entry(name, metadata),
            "kind": metadata.get("proof") or metadata.get("targetFamily") or "matched-prompt",
            "strategyClass": metadata.get("targetFamily") or "matched-prompt",
            "tags": prompt_tags(metadata),
            "candidateSource": str(resolve_prompt_relative(prompt_dir, str(metadata.get("candidateSourcePath") or "candidate.c"))),
            "differences": 0,
            "sourcePreview": prompt_preview(prompt_dir, metadata),
        }
        rows.append(row)
    return rows


def parse_simple_case_yaml(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
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


def resolve_prompt_relative(prompt_dir: Path, value: str) -> Path:
    if value.startswith("prompt:/"):
        return prompt_dir / value.removeprefix("prompt:/")
    path = Path(value)
    if path.is_absolute():
        return path
    return path


def infer_entry(name: str, metadata: dict[str, str]) -> str | None:
    if address := metadata.get("binaryFunctionAddress"):
        return address.removeprefix("0x").removeprefix("0X")
    for pattern in (r"FUN_([0-9a-fA-F]+)", r"fcn\.([0-9a-fA-F]+)", r"\b([0-9a-fA-F]{8})\b"):
        match = re.search(pattern, name)
        if match:
            return match.group(1).lower()
    return None


def prompt_tags(metadata: dict[str, str]) -> list[str]:
    tags = ["matched", "prompt-folder"]
    for key in ("targetFamily", "proof"):
        value = metadata.get(key)
        if value:
            tags.append(value)
    return tags


def prompt_preview(prompt_dir: Path, metadata: dict[str, str]) -> str:
    parts = [f"{key}: {value}" for key, value in sorted(metadata.items()) if key in {"caseId", "functionName", "targetFamily", "proof", "claimBoundary"}]
    for name in ("prompt.md", "candidate.c"):
        path = prompt_dir / name
        if path.exists():
            parts.append(path.read_text(encoding="utf-8", errors="replace")[:4000])
    return "\n".join(parts)


def search_retrieval_rows(
    query_text: str,
    retrieval_rows: list[dict[str, Any]],
    matched_rows: list[dict[str, Any]],
    top_k: int,
) -> list[dict[str, Any]]:
    query = normalize_query(query_text)
    exact_keys = query_keys(query_text)
    scored: list[tuple[float, dict[str, Any]]] = []
    for row in retrieval_rows:
        score = retrieval_score(row, query, exact_keys)
        if score <= 0:
            continue
        scored.append((score, row))
    scored.sort(key=lambda item: item[0], reverse=True)
    results = [format_retrieval_result(row, score, top_k) for score, row in scored[: max(1, top_k)]]
    if results:
        return results

    matched_scored: list[tuple[float, dict[str, Any]]] = []
    for row in matched_rows:
        score = matched_score(row, query, exact_keys)
        if score > 0:
            matched_scored.append((score, row))
    matched_scored.sort(key=lambda item: item[0], reverse=True)
    return [format_matched_result(row, score) for score, row in matched_scored[: max(1, top_k)]]


def query_keys(text: str) -> set[str]:
    keys = {item.lower() for item in re.findall(r"FUN_[0-9a-fA-F]+", text)}
    keys.update(match.lower() for match in re.findall(r"\bfcn\.([0-9a-fA-F]{6,8})\b", text, flags=re.IGNORECASE))
    keys.update(match.lower() for match in re.findall(r"\b[0-9a-fA-F]{8}\b", text))
    keys.update(f"fun_{key}" for key in list(keys) if re.fullmatch(r"[0-9a-f]{6,8}", key))
    return keys


def normalize_query(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_@.$+-]+", text)
        if len(token) >= 3
    }


def retrieval_score(row: dict[str, Any], query: set[str], exact_keys: set[str]) -> float:
    name = str(row.get("name") or "").lower()
    entry = str(row.get("entry") or "").lower()
    row_keys = {name, entry, f"fun_{entry}" if entry else ""}
    if exact_keys & row_keys:
        return 100.0
    haystack = row_text(row)
    overlap = len(query & haystack)
    if overlap == 0:
        return 0.0
    best_example = max((float(item.get("score") or 0.0) for item in row.get("nearestMatchedExamples") or []), default=0.0)
    return overlap + best_example


def matched_score(row: dict[str, Any], query: set[str], exact_keys: set[str]) -> float:
    name = str(row.get("name") or "").lower()
    entry = str(row.get("entry") or "").lower()
    row_keys = {name, entry, f"fun_{entry}" if entry else ""}
    if exact_keys & row_keys:
        return 50.0
    overlap = len(query & row_text(row))
    return float(overlap)


def row_text(row: dict[str, Any]) -> set[str]:
    fields = [
        row.get("name"),
        row.get("entry"),
        row.get("strategyClass"),
        row.get("kind"),
        row.get("symbol"),
        " ".join(str(item) for item in row.get("tags") or []),
        row.get("sourcePreview"),
    ]
    for example in row.get("nearestMatchedExamples") or []:
        fields.extend([example.get("name"), example.get("entry"), example.get("kind"), " ".join(example.get("tags") or [])])
    return normalize_query("\n".join(str(field) for field in fields if field))


def format_retrieval_result(row: dict[str, Any], score: float, top_k: int) -> dict[str, Any]:
    examples = []
    for example in (row.get("nearestMatchedExamples") or [])[: max(1, top_k)]:
        examples.append(
            {
                "name": example.get("name"),
                "entry": example.get("entry"),
                "kind": example.get("kind"),
                "score": example.get("score"),
                "tags": example.get("tags") or [],
                "candidateSource": example.get("candidateSource"),
                "whySimilar": why_similar(row, example),
            }
        )
    return {
        "index": row.get("_index"),
        "name": row.get("name"),
        "entry": row.get("entry"),
        "score": round(score, 6),
        "strategyClass": row.get("strategyClass"),
        "tags": row.get("tags") or [],
        "nextAction": row.get("nextAction"),
        "nearestMatchedExamples": examples,
    }


def format_matched_result(row: dict[str, Any], score: float) -> dict[str, Any]:
    return {
        "index": row.get("_index"),
        "name": row.get("name"),
        "entry": row.get("entry"),
        "score": round(score, 6),
        "strategyClass": row.get("strategyClass"),
        "tags": row.get("tags") or [],
        "nearestMatchedExamples": [
            {
                "name": row.get("name"),
                "entry": row.get("entry"),
                "kind": row.get("kind"),
                "score": row.get("differences"),
                "tags": row.get("tags") or [],
                "candidateSource": row.get("candidateSource"),
                "whySimilar": "Exact or text-matched verified local example.",
            }
        ],
    }


def why_similar(row: dict[str, Any], example: dict[str, Any]) -> str:
    shared = sorted(set(row.get("tags") or []) & set(example.get("tags") or []))
    if shared:
        return "Shared tags: " + ", ".join(shared[:6])
    if row.get("strategyClass"):
        return f"Same retrieval class context: {row.get('strategyClass')}"
    return "Nearest local feature-index match."


def write_prompt_similar_examples(prompt_dir: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    prompt_path = prompt_dir / "prompt.md"
    if not prompt_path.exists():
        return {"status": "skipped", "reason": "prompt.md not found"}
    text = prompt_path.read_text(encoding="utf-8", errors="replace")
    block = atlas_markdown(receipt)
    marker = "## Similar Examples"
    if marker in text:
        updated = re.sub(r"## Similar Examples\n.*?(?=\n## |\Z)", block.rstrip() + "\n", text, flags=re.S)
    else:
        updated = text.rstrip() + "\n\n" + block
    prompt_path.write_text(updated, encoding="utf-8")
    return {"status": "updated", "prompt": str(prompt_path)}


def atlas_markdown(receipt: dict[str, Any]) -> str:
    lines = ["## Similar Examples", ""]
    if not receipt.get("results"):
        lines.append("No high-quality local examples were found. Proceed without fabricated analogies.")
        return "\n".join(lines) + "\n"
    for result in receipt["results"]:
        lines.append(f"- Target `{result.get('name')}` / `{result.get('entry')}`: {result.get('strategyClass') or 'unknown'}")
        for example in result.get("nearestMatchedExamples") or []:
            lines.append(
                f"  - `{example.get('name')}` / `{example.get('entry')}` "
                f"score={example.get('score')}: {example.get('whySimilar')}"
            )
            if example.get("candidateSource"):
                lines.append(f"    source: `{example.get('candidateSource')}`")
        if result.get("nextAction"):
            lines.append(f"  - next: {result.get('nextAction')}")
    lines.append("")
    lines.append("Boundary: Atlas examples are prompt context only; accept only objdiff-zero matches.")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="decomp-atlas", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("prompt", nargs="?", help="Prompt name/path or search text.")
    parser.add_argument("--query", help="Additional search text.")
    parser.add_argument("--prompts-dir", type=Path, default=Path("prompts"))
    parser.add_argument("--index-root", type=Path, default=Path("target/source-parity-index"))
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--write-prompt", action="store_true", help="Update prompts/<name>/prompt.md with a Similar Examples section.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    receipt = run_decomp_atlas(
        prompt_name=args.prompt,
        query=args.query,
        prompts_dir=args.prompts_dir,
        index_root=args.index_root,
        top_k=args.top_k,
        write_prompt=args.write_prompt,
    )
    if args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(atlas_markdown(receipt), end="")
    return 0 if receipt.get("status") in {"complete", "no-local-examples"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
