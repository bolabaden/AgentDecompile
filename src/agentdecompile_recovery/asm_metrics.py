"""ARM/Thumb, MIPS, and x86 assembly instruction/branch/label counting.

Ports the upstream reference asm-metrics module for ARM/MIPS. Feeds the
difficulty classifier in logistic_regression.py.

The x86 counter is an addition, not a port -- see asm_utils for why, and for
the two Intel-syntax dialects it accepts. It shares asm_utils' mnemonic
tables so a mnemonic classified as a branch there is one here too. `call` is
counted as an instruction but not a branch, matching the ARM path's treatment
of `bl`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .asm_utils import (
    X86_PLATFORMS,
    AsmPlatform,
    is_x86_branch_mnemonic,
    is_x86_local_label,
    iter_x86_instructions,
    x86_label_name,
)

ArmOrMips = AsmPlatform  # Back-compat alias from the ARM/MIPS-only port.


@dataclass
class AsmMetrics:
    instruction_count: int
    branch_count: int
    label_count: int
    arm_encoding: str | None = None  # "thumb" | "arm32" | None


_ARM_DIRECTIVE_RE = re.compile(r"^\.")
_ARM_THUMB_FUNC_RE = re.compile(r"thumb_func_start")
_ARM_ARM_FUNC_RE = re.compile(r"arm_func_start")
_ARM_LABEL_FORMAT_A_RE = re.compile(r"^\.L\w+:$")
_ARM_LABEL_FORMAT_B_RE = re.compile(r"^_[0-9A-Fa-f]+:")
_ARM_FUNC_ENTRY_LABEL_RE = re.compile(r"^[\w]+:\s*@\s*0x")
_ARM_BRANCH_MNEMONICS = frozenset(
    {"beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs", "blo", "bls", "bcc", "bcs", "bmi", "bpl"}
)
_ARM_COMMENT_RE = re.compile(r"\s*@.*$")
_ARM32_ONLY_MNEMONICS = frozenset({"msr", "mrs", "mcr", "mrc", "stmfd", "ldmfd", "stmia", "ldmia", "stmdb", "ldmdb"})


def _count_arm_metrics(asm_code: str) -> AsmMetrics:
    instruction_count = 0
    branch_count = 0
    label_count = 0
    has_arm32_only_instr = False
    marker_encoding: str | None
    if _ARM_THUMB_FUNC_RE.search(asm_code):
        marker_encoding = "thumb"
    elif _ARM_ARM_FUNC_RE.search(asm_code):
        marker_encoding = "arm32"
    else:
        marker_encoding = None

    for raw_line in asm_code.split("\n"):
        line = _ARM_COMMENT_RE.sub("", raw_line.strip())
        if line == "":
            continue

        if _ARM_DIRECTIVE_RE.match(line) and not _ARM_LABEL_FORMAT_A_RE.match(line):
            continue
        if _ARM_THUMB_FUNC_RE.search(line) or _ARM_ARM_FUNC_RE.search(line):
            continue

        if _ARM_LABEL_FORMAT_A_RE.match(line) or _ARM_LABEL_FORMAT_B_RE.match(line):
            label_count += 1
            continue

        if _ARM_FUNC_ENTRY_LABEL_RE.match(raw_line.strip()):
            continue

        mnemonic = re.split(r"\s", line, maxsplit=1)[0].lower()

        if mnemonic == "bl":
            instruction_count += 1
            continue

        if mnemonic in ("bx", "bic", "bics"):
            instruction_count += 1
            continue

        if mnemonic in _ARM_BRANCH_MNEMONICS:
            branch_count += 1
            instruction_count += 1
            continue

        if mnemonic == "b":
            branch_count += 1
            instruction_count += 1
            continue

        if mnemonic in _ARM32_ONLY_MNEMONICS:
            has_arm32_only_instr = True

        instruction_count += 1

    arm_encoding = marker_encoding if marker_encoding is not None else ("arm32" if has_arm32_only_instr else None)
    return AsmMetrics(instruction_count, branch_count, label_count, arm_encoding)


_MIPS_INSTRUCTION_RE = re.compile(r"/\*\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s*\*/")
_MIPS_BRANCH_RE = re.compile(r"\b(beq|bne|bnez|beqz|blez|bgtz|bltz|bgez|blt|bgt|ble|bge|bltzal|bgezal)\b")
_MIPS_LABEL_RE = re.compile(r"^\s*\.L[\w]+:")


def _count_mips_metrics(asm_code: str) -> AsmMetrics:
    instruction_count = 0
    branch_count = 0
    label_count = 0

    for line in asm_code.split("\n"):
        if _MIPS_LABEL_RE.match(line):
            label_count += 1

        if not _MIPS_INSTRUCTION_RE.search(line):
            continue

        instruction_count += 1

        if _MIPS_BRANCH_RE.search(line):
            branch_count += 1

    return AsmMetrics(instruction_count, branch_count, label_count)


def _count_x86_metrics(asm_code: str) -> AsmMetrics:
    instruction_count = 0
    branch_count = 0
    for _line, mnemonic in iter_x86_instructions(asm_code):
        instruction_count += 1
        if is_x86_branch_mnemonic(mnemonic):
            branch_count += 1

    # Labels are counted over the raw text: iter_x86_instructions drops them
    # precisely because they are not instructions.
    label_count = 0
    for raw_line in asm_code.split("\n"):
        name = x86_label_name(raw_line)
        if name is not None and is_x86_local_label(name):
            label_count += 1

    return AsmMetrics(instruction_count, branch_count, label_count)


def count_asm_metrics(asm_code: str, platform: AsmPlatform) -> AsmMetrics:
    if platform == "arm":
        return _count_arm_metrics(asm_code)
    if platform == "mips":
        return _count_mips_metrics(asm_code)
    if platform in X86_PLATFORMS:
        return _count_x86_metrics(asm_code)
    return AsmMetrics(0, 0, 0)
