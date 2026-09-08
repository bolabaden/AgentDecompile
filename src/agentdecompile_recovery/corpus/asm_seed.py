"""STABS → original-byte assembly. C replacement is a later pass.

Every function gets a compiling `__declspec(naked)` + `_emit` body from the
shipped image. That is the default substrate, not recovered source. The C
pass overwrites these files when Ghidra C compiles.
"""

from __future__ import annotations

import re
from pathlib import Path

ASM_MARK = "compile-only-asm"
TRIED_MARK = "c-replace-tried"
# Prior leftover writes used this instead of TRIED_MARK.
TRIED_ALIASES = (TRIED_MARK, "asm-fallback")


def _banner_head(path: Path) -> str:
    try:
        return path.read_text(errors="replace")[:800]
    except OSError:
        return ""


def is_compile_only_asm(path: Path) -> bool:
    if not path or not path.is_file():
        return False
    return ASM_MARK in _banner_head(path)


def is_c_replace_tried(path: Path) -> bool:
    """True after a C-replace attempt kept this asm file.

    Seeded substrate is compile-only-asm without this mark, so the next
    ghidra-bulk pass still tries C once. Already-tried leftovers are not
    sent through Wine again unless ``--force-c-replace``.
    """
    head = _banner_head(path)
    return any(mark in head for mark in TRIED_ALIASES)


def mark_c_replace_tried(path: Path) -> None:
    """Stamp a seed-asm file so skip-existing will not requeue it."""
    if not path.is_file() or is_c_replace_tried(path):
        return
    text = path.read_text(errors="replace")
    note = f" * {TRIED_MARK}: C failed; kept asm substrate.\n"
    closer = text.find("*/")
    if closer != -1 and closer < 800:
        path.write_text(text[:closer] + note + text[closer:])
        return
    path.write_text(f"/* {TRIED_MARK} */\n" + text)


def emit_naked_asm(name: str, blob: bytes) -> str:
    ident = re.sub(r"[^A-Za-z_0-9]", "_", name) or "FUN"
    lines = "\n".join(f"        _emit 0x{b:02X}" for b in blob)
    return (
        f"/* {ASM_MARK}: {len(blob)} original file bytes, not recovered C */\n"
        f"__declspec(naked) void {ident}(void)\n"
        "{\n"
        "    __asm {\n"
        f"{lines}\n"
        "    }\n"
        "}\n"
    )


def asm_banner(fname: str, entry_hex: str) -> str:
    return (
        f"/*\n * {fname}  --  {ASM_MARK} (original file bytes)\n"
        f" * address: 0x{entry_hex}\n"
        f" * STABS/layout substrate. Replace with compiling Ghidra C.\n"
        f" * NOT recovered source. NOT a byte-verified recompile.\n */\n"
    )


def slice_image(image: bytes, offset: int, size: int) -> bytes | None:
    if size <= 0 or offset < 0 or offset + size > len(image):
        return None
    return image[offset : offset + size]
