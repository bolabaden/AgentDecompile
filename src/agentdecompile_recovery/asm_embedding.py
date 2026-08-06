"""Assembly text normalization for embedding-based similarity search.

Ports the upstream indexer's text-preprocessing half of embedder.ts: pure text
transforms with no model/subprocess dependency. Strips comments, isolates the
function body, and normalizes format differences between objdiff-extracted
assembly (matched functions) and raw .s files (unmatched) so semantically
identical code clusters together regardless of source format. See
semantic_atlas.py for the (optional-dependency) vector-index layer this feeds.
"""

from __future__ import annotations

import re

from .asm_utils import ArmOrMips, extract_asm_function_body, strip_commentaries


def preprocess_for_embedding(platform: ArmOrMips, asm_code: str) -> str:
    stripped = strip_commentaries(asm_code)
    body = extract_asm_function_body(platform, stripped)
    return _normalize_asm_for_embedding(body)


_THUMB_S_MNEMONICS = frozenset(
    {
        "adds", "subs", "movs", "lsls", "lsrs", "asrs", "ands", "orrs", "eors",
        "negs", "muls", "bics", "mvns", "rsbs", "sbcs", "adcs", "rors",
    }
)

_HEX_PREFIX_RE = re.compile(r"^[0-9a-f]+:\s*")
_REFERENCE_RE = re.compile(r"\s*#\s*REFERENCE_\S*")
_LINE_NUMBER_RE = re.compile(r"^\d+([\w.])")
_FOUR_BYTE_RE = re.compile(r"\.4byte\b")
_POOL_LABEL_LOAD_RE = re.compile(r"^(ldr\w*\s+r\d+),\s*_[0-9a-fA-F]{7,8}\b")
_POOL_PC_LOAD_RE = re.compile(r"^(ldr\w*\s+r\d+),\s*\[pc,\s*#0x[0-9a-fA-F]+\]")
_POOL_LABEL_DEF_RE = re.compile(r"^_[0-9a-fA-F]{7,8}:\s*")
_NONMATCHING_RE = re.compile(r"^nonmatching\s")
_MIPS_REG_RE = re.compile(r"\$(zero|at|v[01]|a[0-3]|t[0-9]|s[0-7]|k[01]|gp|sp|fp|ra|f[vtsa]\d|f\d{1,2}|\d{1,2})\b")
_DOT_L_LABEL_RE = re.compile(r"\.L[0-9a-fA-F]+\b")
_HI_RE = re.compile(r"%hi\([^)]+\)")
_LO_RE = re.compile(r"%lo\([^)]+\)")
_HI_SHIFT_RE = re.compile(r"\(0x[0-9a-fA-F]+ >> 16\)")
_LO_MASK_RE = re.compile(r"\(0x[0-9a-fA-F]+ & 0xFFFF\)")


def _normalize_asm_for_embedding(asm: str) -> str:
    result_lines: list[str] = []

    for line in asm.split("\n"):
        normalized = line

        normalized = _HEX_PREFIX_RE.sub("", normalized)
        normalized = _REFERENCE_RE.sub("", normalized)
        normalized = _LINE_NUMBER_RE.sub(r"\1", normalized)
        normalized = _FOUR_BYTE_RE.sub(".word", normalized)
        normalized = _POOL_LABEL_LOAD_RE.sub(r"\1, [pool]", normalized)
        normalized = _POOL_PC_LOAD_RE.sub(r"\1, [pool]", normalized)
        normalized = _POOL_LABEL_DEF_RE.sub("", normalized)

        space_idx = normalized.find(" ")
        mnemonic = normalized[:space_idx] if space_idx != -1 else normalized
        if mnemonic in _THUMB_S_MNEMONICS:
            normalized = mnemonic[:-1] + normalized[space_idx:]

        if _NONMATCHING_RE.match(normalized):
            continue

        normalized = _MIPS_REG_RE.sub(r"\1", normalized)
        normalized = _DOT_L_LABEL_RE.sub(".Lx", normalized)
        normalized = _HI_RE.sub("%hi(x)", normalized)
        normalized = _LO_RE.sub("%lo(x)", normalized)
        normalized = _HI_SHIFT_RE.sub("%hi(x)", normalized)
        normalized = _LO_MASK_RE.sub("%lo(x)", normalized)

        result_lines.append(normalized)

    return "\n".join(result_lines)
