"""Assembly text normalization for embedding-based similarity search.

Ports the upstream indexer's text-preprocessing half of embedder.ts: pure text
transforms with no model/subprocess dependency. Strips comments, isolates the
function body, and normalizes format differences between objdiff-extracted
assembly (matched functions) and raw .s files (unmatched) so semantically
identical code clusters together regardless of source format. See
semantic_atlas.py for the (optional-dependency) vector-index layer this feeds.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Callable

from .asm_utils import X86_PLATFORMS, AsmPlatform, extract_asm_function_body, strip_commentaries


def preprocess_for_embedding(platform: AsmPlatform, asm_code: str) -> str:
    stripped = strip_commentaries(asm_code, platform)
    body = extract_asm_function_body(platform, stripped)
    if platform in X86_PLATFORMS:
        return _normalize_x86_for_embedding(body)
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


# x86 normalization. Two jobs, both in service of "structurally similar
# functions must land near each other in the vector space":
#
#   1. Fold the objdiff and MASM dialects together, so the same function
#      compiled by MSVC and disassembled by objdiff clusters with its own
#      `cl /FAs` listing. Case, tabs, `DWORD PTR` vs `dword ptr`, and
#      `OFFSET FLAT:` vs a bare symbol are pure dialect.
#   2. Erase address noise. In this corpus a call target is an intra-object
#      offset (`call 0x223d30`) and a symbol name embeds its own address
#      (`sub_1e5c20`, `_DAT_007a6990`). Two structurally identical functions
#      calling different callees must not be pushed apart by that, so
#      branch/call targets and the address tails of generated names are
#      replaced by placeholders. Displacements inside memory operands are
#      NOT erased -- `[esi+0x10]` is real structure, not noise.
_X86_MASM_SIZE_RE = re.compile(r"\b(BYTE|WORD|DWORD|QWORD|TBYTE|XMMWORD|YMMWORD)\s+PTR\b")
_X86_OFFSET_FLAT_RE = re.compile(r"\bOFFSET\s+(?:FLAT\s*:\s*)?", re.IGNORECASE)
_X86_SHORT_RE = re.compile(r"\bSHORT\b", re.IGNORECASE)
_X86_BRANCH_TARGET_RE = re.compile(
    r"^((?:rep|repe|repz|repne|repnz|lock)\s+)?(call|jmp|j[a-z]{1,4}|loop(?:n?[ez])?)\s+(?:short\s+)?\S.*$",
    re.IGNORECASE,
)
_X86_GENERATED_NAME_RE = re.compile(r"\b((?:_+)?(?:sub|DAT|UNK|PTR|LAB|FUN|stack|s|u)_[A-Za-z0-9_]*?)([0-9a-fA-F]{6,8})\b")
_X86_LOCAL_LABEL_OPERAND_RE = re.compile(r"\$L[A-Za-z0-9]*")
_X86_REAL_POOL_RE = re.compile(r"__real@[0-9a-fA-F]+")
# MASM listings write displacements in decimal (`[esi+16]`), objdiff in hex
# (`[esi+0x10]`). Same operand, different radix: canonicalize to hex. The
# lookarounds keep digits that are part of an identifier (`sub_12620`, `st(0)`)
# out of it.
_X86_INTEGER_RE = re.compile(r"(?<![A-Za-z0-9_?$@.(])(0[xX][0-9a-fA-F]+|\d+)(?![A-Za-z0-9_?$@)])")


def _canonical_integer(match: re.Match[str]) -> str:
    text = match.group(1)
    value = int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
    return f"0x{value:x}"


def _normalize_x86_for_embedding(asm: str) -> str:
    result_lines: list[str] = []

    for line in asm.split("\n"):
        normalized = _X86_MASM_SIZE_RE.sub(lambda m: m.group(1).lower() + " ptr", line)
        normalized = _X86_OFFSET_FLAT_RE.sub("offset ", normalized)
        normalized = _X86_SHORT_RE.sub("short", normalized)
        normalized = _X86_LOCAL_LABEL_OPERAND_RE.sub("$Lx", normalized)
        normalized = _X86_REAL_POOL_RE.sub("__real@x", normalized)
        normalized = _X86_GENERATED_NAME_RE.sub(r"\1x", normalized)

        branch_match = _X86_BRANCH_TARGET_RE.match(normalized)
        if branch_match:
            prefix = branch_match.group(1) or ""
            normalized = f"{prefix}{branch_match.group(2).lower()} <target>"
        else:
            normalized = _X86_INTEGER_RE.sub(_canonical_integer, normalized)

        result_lines.append(normalized)

    return "\n".join(result_lines)


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


# --- Dependency-free structural backend ---------------------------------------

STRUCTURAL_EMBEDDING_DIMENSIONS = 512


def _shingles(text: str) -> list[str]:
    """Instruction unigrams and bigrams over normalized assembly.

    The unit is one normalized instruction, not one word: `mov eax, [esi+0x4]`
    is a single token. Bigrams carry the ordering that distinguishes, say, a
    compare-then-branch from a branch-then-compare.
    """
    lines = [line for line in text.split("\n") if line.strip()]
    grams = list(lines)
    grams.extend(f"{first}|{second}" for first, second in zip(lines, lines[1:]))
    return grams


def structural_embedding_backend(
    platform: AsmPlatform,
    dimensions: int = STRUCTURAL_EMBEDDING_DIMENSIONS,
) -> Callable[[list[str]], list[list[float]]]:
    """A SemanticEmbedder backend that needs no model and no dependencies.

    Hashes instruction shingles into a fixed-width vector, weights each by
    sqrt(count), and L2-normalizes. Cosine similarity over these is a
    plain-text structural similarity: two functions score high when they share
    instruction sequences, which for assembly is closer to what the retrieval
    layer actually wants than a natural-language sentence embedder is.

    The default backend (`semantic_embedder.default_embedding_backend`) needs
    `agentdecompile[semantic]`, which pulls chromadb, onnxruntime, and
    tokenizers. This exists so retrieval works, and stays measurable, without
    that stack. It is deterministic, so an index built with it is reproducible.

    Input texts are expected to be raw assembly; the backend runs them through
    `preprocess_for_embedding` itself.
    """
    if dimensions <= 0:
        raise ValueError("dimensions must be positive")

    def backend(texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            counts: dict[int, float] = {}
            for gram in _shingles(preprocess_for_embedding(platform, text)):
                digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
                bucket = int.from_bytes(digest, "big") % dimensions
                counts[bucket] = counts.get(bucket, 0.0) + 1.0
            vector = [0.0] * dimensions
            for bucket, count in counts.items():
                vector[bucket] = math.sqrt(count)
            norm = math.sqrt(sum(value * value for value in vector))
            if norm > 0:
                vector = [value / norm for value in vector]
            vectors.append(vector)
        return vectors

    return backend
