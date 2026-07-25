"""Pure-Python Itanium + MSVC RTTI helpers for enrich naming."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

# Itanium ABI length-prefixed name: 11CExampleApp
_TYPEINFO_NAME_RE = re.compile(r"^(\d+)([A-Za-z_][A-Za-z0-9_]*)$")
_NESTED_RE = re.compile(r"^N(?:\d+[A-Za-z_][A-Za-z0-9_]*)+E$")
# MSVC type descriptor: .?AVClass@Namespace@@  /  .?AUStruct@@
_MSVC_TYPE_RE = re.compile(r"^\.\?A[VU](.+)@@$")
_MSVC_TYPE_BYTES = re.compile(rb"\.\?A[VU][A-Za-z_][A-Za-z0-9_@]*@@")


@dataclass
class RttiClass:
    mangled: str
    name: str
    provenance: str = "rtti-typeinfo"


@dataclass
class VtableInfo:
    class_name: str
    address: int | None = None
    slot_count: int | None = None
    methods: list[str] = field(default_factory=list)
    provenance: str = "rtti-vtable"


def demangle_typeinfo_name(raw: str) -> str | None:
    """Decode an Itanium typeinfo string name into a C++ class identifier.

    Accepts forms like ``13CClientExoApp`` or nested ``N…E`` (returns None for
    complex nested forms we do not fully expand yet).
    """
    text = raw.strip().lstrip("*")
    if not text or text.startswith("_Z"):
        return None
    # Strip leading "typeinfo name for " style prefixes if present
    if " " in text and not text[0].isdigit():
        return None
    match = _TYPEINFO_NAME_RE.match(text)
    if match:
        length = int(match.group(1))
        name = match.group(2)
        if len(name) != length:
            # Allow trailing garbage after exact length
            if len(name) < length:
                return None
            name = name[:length]
        if not re.match(r"^[A-Za-z_]", name):
            return None
        return name
    if _NESTED_RE.match(text):
        return None
    return None


def demangle_msvc_type_descriptor(raw: str) -> str | None:
    """Decode MSVC RTTI type descriptor strings like ``.?AVFoo@Bar@@`` → ``Bar::Foo``."""
    text = str(raw or "").strip()
    match = _MSVC_TYPE_RE.match(text)
    if not match:
        return None
    body = match.group(1)
    parts = [part for part in body.split("@") if part]
    if not parts:
        return None
    for part in parts:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", part):
            return None
    return "::".join(reversed(parts))


def scan_typeinfo_strings(path: Path, *, limit: int = 0) -> list[RttiClass]:
    """Scan ELF string table / rodata-ish printable runs for Itanium typeinfo names."""
    data = path.read_bytes()
    found: dict[str, RttiClass] = {}
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= 4:
            text = current.decode("ascii", errors="ignore")
            name = demangle_typeinfo_name(text)
            if name and name not in found:
                found[name] = RttiClass(mangled=text, name=name)
                if limit and len(found) >= limit:
                    break
        current.clear()
    if current and (not limit or len(found) < limit):
        text = current.decode("ascii", errors="ignore")
        name = demangle_typeinfo_name(text)
        if name and name not in found:
            found[name] = RttiClass(mangled=text, name=name)
    return sorted(found.values(), key=lambda item: item.name)


def scan_msvc_rtti_strings(path: Path, *, limit: int = 0) -> list[RttiClass]:
    """Scan a PE (or any blob) for MSVC ``.?AV`` / ``.?AU`` type descriptors."""
    data = path.read_bytes()
    found: dict[str, RttiClass] = {}
    for match in _MSVC_TYPE_BYTES.finditer(data):
        mangled = match.group(0).decode("ascii", errors="ignore")
        name = demangle_msvc_type_descriptor(mangled)
        if not name or name in found:
            continue
        found[name] = RttiClass(mangled=mangled, name=name, provenance="msvc-rtti-string")
        if limit and len(found) >= limit:
            break
    return sorted(found.values(), key=lambda item: item.name)


def extract_ghidra_rtti_classes(program: Any) -> list[RttiClass]:
    """Collect class names from a live Ghidra program (symbols, data, ClassDataTypes).

    Soft-degrades to an empty list when APIs are missing or raise.
    Prefers already-recovered Ghidra RTTI surfaces over inventing a second parser.
    """
    found: dict[str, RttiClass] = {}

    def _ingest(raw: str | None, *, provenance: str) -> None:
        text = str(raw or "").strip()
        if not text:
            return
        name = demangle_msvc_type_descriptor(text) or demangle_typeinfo_name(text)
        if name is None:
            if text.startswith("RTTI_") or text.endswith("_vftable") or "FUN_" in text:
                return
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_:]{1,120}$", text):
                return
            name = text
        if name in found:
            return
        found[name] = RttiClass(mangled=text, name=name, provenance=provenance)

    try:
        symbol_table = program.getSymbolTable()
        for symbol in symbol_table.getAllSymbols(True):
            try:
                _ingest(str(symbol.getName()), provenance="ghidra-rtti-symbol")
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass

    try:
        listing = program.getListing()
        for data in listing.getDefinedData(True):
            try:
                value = data.getValue()
                _ingest(str(value) if value is not None else None, provenance="ghidra-rtti-data")
                label = data.getLabel() if hasattr(data, "getLabel") else None
                _ingest(str(label) if label else None, provenance="ghidra-rtti-data")
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass

    try:
        dtm = program.getDataTypeManager()
        category_path = None
        try:
            from ghidra.program.model.data import CategoryPath

            category_path = CategoryPath("/ClassDataTypes")
        except Exception:  # noqa: BLE001
            category_path = "/ClassDataTypes"
        category = dtm.getCategory(category_path)
        if category is not None:
            for data_type in category.getDataTypes():
                try:
                    _ingest(str(data_type.getName()), provenance="ghidra-class-datatype")
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        pass

    return sorted(found.values(), key=lambda item: item.name)


def merge_rtti_classes(*groups: list[RttiClass]) -> list[RttiClass]:
    """Union class lists; first provenance for a name wins."""
    found: dict[str, RttiClass] = {}
    for group in groups:
        for cls in group:
            found.setdefault(cls.name, cls)
    return sorted(found.values(), key=lambda item: item.name)


def align_vtable_methods(
    class_name: str,
    corpus_methods: list[str],
    slot_count: int | None,
) -> VtableInfo:
    """Join vtable slots to corpus method order; partial on mismatch."""
    info = VtableInfo(class_name=class_name, slot_count=slot_count)
    if slot_count is None:
        info.methods = list(corpus_methods)
        info.provenance = "rtti-vtable"
        return info
    # Skip RTTI/offset-to-top slots heuristically: first two often meta
    usable = max(0, slot_count - 2)
    if usable == len(corpus_methods):
        info.methods = list(corpus_methods)
        info.provenance = "rtti-vtable"
        return info
    if usable <= 0:
        info.methods = [f"{class_name}_slot_{i}" for i in range(slot_count)]
        info.provenance = "rtti-vtable-partial"
        return info
    methods: list[str] = []
    for index in range(usable):
        if index < len(corpus_methods):
            methods.append(corpus_methods[index])
        else:
            methods.append(f"{class_name}_slot_{index}")
    info.methods = methods
    info.provenance = "rtti-vtable-partial" if usable != len(corpus_methods) else "rtti-vtable"
    return info


_SOURCE_FILE_RE = re.compile(
    r"(?:(?:\.\./)?(?:CODE|src|source|Source)/[A-Za-z0-9_./+\-]+\.(?:cpp|c|cc|cxx|h|hpp))"
    r"|(?:[A-Za-z_][A-Za-z0-9_]{2,}\.(?:cpp|c|cc|cxx|h|hpp))",
    re.IGNORECASE,
)


def extract_assert_code_paths(path: Path) -> list[str]:
    """Return embedded source-path strings (``../CODE/...`` or bare ``foo.cpp``)."""
    data = path.read_bytes()
    text_chunks: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= 6:
                text_chunks.append(current.decode("ascii", "ignore"))
            current.clear()
    if current:
        text_chunks.append(current.decode("ascii", "ignore"))
    paths: list[str] = []
    seen: set[str] = set()
    for chunk in text_chunks:
        for match in _SOURCE_FILE_RE.finditer(chunk):
            rel = match.group(0)
            if rel.startswith("CODE/") or rel.startswith("src/") or rel.startswith("source/"):
                rel = "../" + rel
            # Skip obvious false positives from binary noise.
            if rel.lower() in {"this.cpp", "file.cpp", "main.c"}:
                continue
            # Bare short lowercase names are usually shaders/noise, not translation units.
            if "/" not in rel and "\\" not in rel:
                stem = Path(rel).stem
                if len(stem) < 8 and not any(ch.isupper() for ch in stem):
                    continue
                if len(stem) < 12 and stem.islower() and "internal" not in stem.lower():
                    continue
            if rel not in seen:
                seen.add(rel)
                paths.append(rel)
    return paths


def dynsym_imports(path: Path) -> list[dict[str, Any]]:
    """List dynamic symbol imports from an ELF."""
    rows: list[dict[str, Any]] = []
    try:
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            for section in elf.iter_sections():
                if section.name != ".dynsym":
                    continue
                for sym in section.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    rows.append(
                        {
                            "name": name,
                            "bind": sym.entry["st_info"]["bind"],
                            "type": sym.entry["st_info"]["type"],
                            "shndx": sym.entry["st_shndx"],
                        }
                    )
    except (OSError, ValueError, TypeError, KeyError):
        return []
    return rows


def _binary_kind(path: Path) -> str:
    try:
        header = path.read_bytes()[:4]
    except OSError:
        return "unknown"
    if header[:2] == b"MZ":
        return "pe"
    if header[:4] == b"\x7fELF":
        return "elf"
    return "unknown"


def rtti_scan_receipt(path: Path) -> dict[str, Any]:
    kind = _binary_kind(path)
    if kind == "pe":
        classes = scan_msvc_rtti_strings(path)
        abi = "msvc"
    elif kind == "elf":
        classes = scan_typeinfo_strings(path)
        abi = "itanium"
    else:
        # Unknown blobs: try both scanners; first provenance wins on name clash.
        classes = merge_rtti_classes(scan_msvc_rtti_strings(path), scan_typeinfo_strings(path))
        abi = "unknown"
    return {
        "schema": "agentdecompile.rtti-scan.v1",
        "binaryPath": str(path),
        "abi": abi,
        "classCount": len(classes),
        "classes": [{"name": c.name, "mangled": c.mangled, "provenance": c.provenance} for c in classes],
        "assertCodePaths": extract_assert_code_paths(path),
        "dynsymImports": dynsym_imports(path)[:200] if kind == "elf" else [],
        "claimBoundary": "RTTI class names are advisory enrichment evidence, not verified source identity",
    }
