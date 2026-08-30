"""Mnemonic-class features from kotorxid `kx/features.py`."""

from __future__ import annotations

from collections import Counter

_CLASSES = {
    "mov": "MOV", "movl": "MOV", "movq": "MOV", "movw": "MOV", "movb": "MOV",
    "movzx": "MOV", "movsx": "MOV", "movsxd": "MOV", "lea": "LEA",
    "ldr": "MOV", "str": "STORE", "push": "PUSH", "pop": "POP",
    "add": "ARITH", "sub": "ARITH", "and": "LOGIC", "or": "LOGIC", "xor": "LOGIC",
    "shl": "SHIFT", "shr": "SHIFT", "sar": "SHIFT",
    "cmp": "CMP", "test": "CMP",
    "call": "CALL", "bl": "CALL",
    "ret": "RET", "retn": "RET",
    "jmp": "JMP", "b": "JMP",
    "nop": "NOP",
}


def mnemonic_class(m: str) -> str:
    key = m.lower()
    if key in _CLASSES:
        return _CLASSES[key]
    if key.startswith(("j", "b.")) and key not in ("jmp",):
        return "CBRANCH"
    if key.startswith(("cb", "tb")):
        return "CBRANCH"
    if key.startswith("set") or key.startswith("cmov"):
        return "COND"
    if key.startswith("f"):
        return "FLOAT"
    if key.startswith("rep"):
        return "STRINGOP"
    return "OTHER"


def mnemonic_profile(mnemonics: list[str]) -> dict[str, int]:
    counts: Counter[str] = Counter(mnemonic_class(m) for m in mnemonics)
    return dict(counts)
