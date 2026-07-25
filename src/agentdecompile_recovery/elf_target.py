"""ELF target helpers for format-aware recovery (sections, machine type)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

MIN_GAME_ELF_BYTES = 50_000
ELF_MACHINE_I386 = 3


def is_elf_binary(path: Path, *, min_bytes: int = MIN_GAME_ELF_BYTES) -> bool:
    """True when path is a real ELF image of at least min_bytes."""
    try:
        if path.stat().st_size < min_bytes:
            return False
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def elf_machine(path: Path) -> int | str | None:
    """Return e_machine (int or enum name), or None if not a readable ELF."""
    try:
        with path.open("rb") as fh:
            if fh.read(4) != b"\x7fELF":
                return None
            fh.seek(0)
            value = ELFFile(fh).header["e_machine"]
            if isinstance(value, int):
                return value
            return str(value)
    except (OSError, ValueError, TypeError):
        return None


def is_elf_i386(path: Path, *, min_bytes: int = MIN_GAME_ELF_BYTES) -> bool:
    """True for i386 ELF binaries (>= min_bytes)."""
    if not is_elf_binary(path, min_bytes=min_bytes):
        return False
    machine = elf_machine(path)
    return machine in {ELF_MACHINE_I386, "EM_386", 3}


def elf_section_rows(path: Path) -> list[dict[str, Any]]:
    """Return ELF section metadata compatible with PE section row shape."""
    rows: list[dict[str, Any]] = []
    try:
        with path.open("rb") as fh:
            if fh.read(4) != b"\x7fELF":
                return []
            fh.seek(0)
            elf = ELFFile(fh)
            for section in elf.iter_sections():
                name = section.name or ""
                if not name:
                    continue
                flags = int(section["sh_flags"])
                executable = bool(flags & 0x4)  # SHF_EXECINSTR
                size = int(section["sh_size"])
                rows.append(
                    {
                        "name": name,
                        "vsize": size,
                        "size": size,
                        "executable": executable,
                        "addr": int(section["sh_addr"]),
                        "offset": int(section["sh_offset"]),
                    }
                )
    except (OSError, ValueError, TypeError, KeyError):
        return []
    return rows


def detect_primary_text_section_elf(path: Path) -> str | None:
    """Prefer `.text`, then largest executable section."""
    rows = [row for row in elf_section_rows(path) if row.get("executable")]
    if not rows:
        return None
    by_name = {str(row["name"]): row for row in rows}
    if ".text" in by_name:
        return ".text"
    textish = [row for row in rows if str(row["name"]).startswith(".text")]
    if textish:
        return str(max(textish, key=lambda row: int(row.get("size") or 0))["name"])
    return str(max(rows, key=lambda row: int(row.get("size") or 0))["name"])


def resolve_elf_binary(input_path: Path) -> Path:
    """Resolve a file or directory to the largest qualifying i386 ELF beneath it."""
    path = input_path.expanduser().resolve()
    if path.is_file():
        return path
    if not path.is_dir():
        raise FileNotFoundError(f"ELF target does not exist: {path}")
    candidates = [item for item in path.iterdir() if item.is_file() and is_elf_i386(item)]
    if not candidates:
        # One level deeper (common install layout: GameData/, bin/, …)
        for child in path.iterdir():
            if not child.is_dir():
                continue
            for item in child.iterdir():
                if item.is_file() and is_elf_i386(item):
                    candidates.append(item)
    if not candidates:
        raise FileNotFoundError(f"no i386 ELF binary under {path}")
    return sorted(candidates, key=lambda item: item.stat().st_size, reverse=True)[0]


def format_profile_slug(path: Path) -> str:
    """Derive a work-dir profile slug from binary format + sanitized stem."""
    stem = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in path.stem).strip("-_") or "binary"
    stem = stem.lower()[:48]
    if is_elf_i386(path, min_bytes=0):
        return f"elf-i386-{stem}"
    if is_elf_binary(path, min_bytes=0):
        return f"elf-{stem}"
    from .targets import is_pe_binary

    if is_pe_binary(path, min_bytes=0):
        return f"pe-{stem}"
    return stem
