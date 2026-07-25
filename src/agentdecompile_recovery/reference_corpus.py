"""Parse a reference C/C++ tree into a recovery corpus (classes, methods, paths)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "agentdecompile.reference-corpus.v1"

_CLASS_RE = re.compile(
    r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^{;]+))?\s*\{",
    re.MULTILINE,
)
_METHOD_RE = re.compile(
    r"(?:^|\n)\s*(?:virtual\s+|static\s+|inline\s+|explicit\s+)*"
    r"(?:[~]?[A-Za-z_][A-Za-z0-9_:<>,\s\*\&]+)\s+"
    r"(?P<name>[A-Za-z_~][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:override\s*)?(?:;|=|{)",
    re.MULTILINE,
)
_FIELD_RE = re.compile(
    r"(?:^|\n)\s*(?P<type>[A-Za-z_][A-Za-z0-9_:<>,\s\*\&]+?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*[^;]+)?\s*;",
    re.MULTILINE,
)
_SKIP_METHODS = frozenset({"if", "for", "while", "switch", "return", "sizeof", "typeof"})


@dataclass
class CorpusField:
    name: str
    type: str


@dataclass
class CorpusClass:
    name: str
    path: str
    base_classes: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    fields: list[CorpusField] = field(default_factory=list)
    source_file: str = ""


@dataclass
class ReferenceCorpus:
    reference_root: str
    classes: dict[str, CorpusClass] = field(default_factory=dict)
    module_files: dict[str, str] = field(default_factory=dict)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    content_digest: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "referenceRoot": self.reference_root,
            "contentDigest": self.content_digest,
            "classCount": len(self.classes),
            "moduleFileCount": len(self.module_files),
            "parseErrorCount": len(self.parse_errors),
            "classes": {name: _class_to_json(cls) for name, cls in sorted(self.classes.items())},
            "moduleFiles": dict(sorted(self.module_files.items())),
            "parseErrors": self.parse_errors,
        }


# Back-compat alias for any leftover imports during transition.
ReferenceCorpus = ReferenceCorpus


def _class_to_json(cls: CorpusClass) -> dict[str, Any]:
    return {
        "name": cls.name,
        "path": cls.path,
        "sourceFile": cls.source_file,
        "baseClasses": cls.base_classes,
        "methods": cls.methods,
        "fields": [asdict(f) for f in cls.fields],
    }


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*?$", "", text, flags=re.M)
    return text


def _parse_bases(raw: str | None) -> list[str]:
    if not raw:
        return []
    bases: list[str] = []
    for part in raw.split(","):
        tokens = (
            part.replace("public", " ")
            .replace("protected", " ")
            .replace("private", " ")
            .replace("virtual", " ")
        )
        name = tokens.strip().split()[-1] if tokens.strip() else ""
        name = name.strip(": ")
        if name and re.match(r"^[A-Za-z_]", name):
            bases.append(name)
    return bases


def _extract_body(text: str, brace_start: int) -> str:
    depth = 0
    for index in range(brace_start, len(text)):
        ch = text[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start + 1 : index]
    return ""


def parse_header_text(text: str, *, relative_path: str) -> tuple[list[CorpusClass], str | None]:
    """Parse class declarations from a header. Returns (classes, error)."""
    try:
        cleaned = _strip_comments(text)
        classes: list[CorpusClass] = []
        for match in _CLASS_RE.finditer(cleaned):
            name = match.group(1)
            bases = _parse_bases(match.group(2))
            brace = cleaned.find("{", match.end() - 1)
            if brace < 0:
                continue
            body = _extract_body(cleaned, brace)
            methods: list[str] = []
            for mm in _METHOD_RE.finditer(body):
                mname = mm.group("name")
                if mname in _SKIP_METHODS and mname != name and mname != f"~{name}":
                    continue
                if mname.startswith("~"):
                    methods.append(mname)
                elif mname not in methods and mname not in _SKIP_METHODS:
                    methods.append(mname)
            fields: list[CorpusField] = []
            for fm in _FIELD_RE.finditer(body):
                fname = fm.group("name")
                ftype = re.sub(r"\s+", " ", fm.group("type")).strip()
                if fname in methods or fname in _SKIP_METHODS:
                    continue
                if "(" in ftype or ")" in ftype:
                    continue
                fields.append(CorpusField(name=fname, type=ftype))
            classes.append(
                CorpusClass(
                    name=name,
                    path=str(Path(relative_path).parent).replace("\\", "/"),
                    base_classes=bases,
                    methods=methods,
                    fields=fields,
                    source_file=relative_path.replace("\\", "/"),
                )
            )
        return classes, None
    except Exception as exc:  # noqa: BLE001 — per-file isolation
        return [], str(exc)


def _code_root(root: Path) -> Path:
    """Prefer ``<root>/CODE`` or ``Port/CODE`` if present; else ``root`` itself."""
    for candidate in (root / "CODE", root / "Port" / "CODE", root):
        if candidate.is_dir() and (
            any(candidate.glob("**/*.h"))
            or any(candidate.glob("**/*.hpp"))
            or any(candidate.glob("**/*.cpp"))
            or any(candidate.glob("**/*.c"))
            or candidate == root
        ):
            if candidate == root or any(candidate.rglob("*.[ch]*")):
                return candidate
    return root


def iter_reference_code_files(root: Path) -> Iterable[Path]:
    code = _code_root(root.expanduser().resolve())
    if not code.is_dir():
        return []
    files: list[Path] = []
    for pattern in ("**/*.h", "**/*.hpp", "**/*.hh", "**/*.cpp", "**/*.c", "**/*.cc"):
        files.extend(code.glob(pattern))
    return sorted(set(files))


def build_corpus(reference_root: Path) -> ReferenceCorpus:
    root = reference_root.expanduser().resolve()
    corpus = ReferenceCorpus(reference_root=str(root))
    digest = hashlib.sha256()
    code_root = _code_root(root)

    for path in iter_reference_code_files(root):
        try:
            relative = path.relative_to(code_root).as_posix()
        except ValueError:
            relative = path.name
        raw = path.read_bytes()
        digest.update(raw)
        digest.update(relative.encode())
        if path.suffix.lower() in {".h", ".hpp", ".hh"}:
            text = raw.decode("utf-8", errors="replace")
            classes, err = parse_header_text(text, relative_path=relative)
            if err:
                corpus.parse_errors.append({"path": relative, "error": err})
                continue
            for cls in classes:
                existing = corpus.classes.get(cls.name)
                if existing is None or len(cls.methods) > len(existing.methods):
                    corpus.classes[cls.name] = cls
        stem = path.stem
        corpus.module_files.setdefault(stem, relative)

    corpus.content_digest = digest.hexdigest()
    return corpus


def write_corpus(corpus: ReferenceCorpus, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "reference-corpus.json"
    path.write_text(json.dumps(corpus.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt = {
        "schema": "agentdecompile.reference-corpus-receipt.v1",
        "corpusPath": str(path),
        "referenceRoot": corpus.reference_root,
        "contentDigest": corpus.content_digest,
        "classCount": len(corpus.classes),
        "moduleFileCount": len(corpus.module_files),
        "parseErrorCount": len(corpus.parse_errors),
    }
    (out_dir / "reference-corpus-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def load_corpus(path: Path) -> ReferenceCorpus:
    data = json.loads(path.read_text(encoding="utf-8"))
    classes: dict[str, CorpusClass] = {}
    for name, raw in (data.get("classes") or {}).items():
        fields = [CorpusField(**f) for f in raw.get("fields") or []]
        classes[name] = CorpusClass(
            name=raw.get("name") or name,
            path=raw.get("path") or "",
            base_classes=list(raw.get("baseClasses") or []),
            methods=list(raw.get("methods") or []),
            fields=fields,
            source_file=raw.get("sourceFile") or "",
        )
    return ReferenceCorpus(
        reference_root=str(data.get("referenceRoot") or ""),
        classes=classes,
        module_files=dict(data.get("moduleFiles") or {}),
        parse_errors=list(data.get("parseErrors") or []),
        content_digest=str(data.get("contentDigest") or ""),
    )


def unmatched_rtti_classes(corpus: ReferenceCorpus, rtti_names: Iterable[str]) -> list[str]:
    return sorted({name for name in rtti_names if name not in corpus.classes})
