"""Regression tests for packaged-source candidates getting the Ghidra type shim."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.package_verify import TYPE_SHIM
from agentdecompile_recovery.source_parity_synthesize import packaged_source_candidate

pytestmark = pytest.mark.unit

RAW_DECOMPILER_SOURCE = (
    "void sub_1130(undefined4 param_1,undefined4 param_2,int param_3,code *param_4)\n"
    "\n"
    "{\n"
    "  if (-1 < param_3 + -1) {\n"
    "    do {\n"
    "      (*param_4)();\n"
    "      param_3 = param_3 + -1;\n"
    "    } while (param_3 != 0);\n"
    "  }\n"
    "  return;\n"
    "}\n"
)


def test_packaged_c_source_gets_type_shim_prepended(tmp_path: Path) -> None:
    """Raw Ghidra decompiler output uses undefined4/code pseudo-types that MSVC
    cannot parse without a typedef prelude -- without this, every packaged-source
    candidate fails to compile before objdiff is ever reached."""
    source_path = tmp_path / "candidate.c"
    source_path.write_text(RAW_DECOMPILER_SOURCE, encoding="utf-8")
    row = {
        "sourceTask": True,
        "source": str(source_path),
        "name": "sub_1130",
        "sourceQuality": "high-level-c",
        "sourceOrigin": "external decompiler output; automatically exported, not manually authored",
    }

    candidate = packaged_source_candidate(row)

    assert candidate is not None
    assert candidate.variant == "packaged-source"
    assert TYPE_SHIM in candidate.source
    assert "typedef unsigned int undefined4;" in candidate.source
    assert RAW_DECOMPILER_SOURCE.strip() in candidate.source
    # The shim must come before the raw source so declarations are in scope.
    assert candidate.source.index(TYPE_SHIM) < candidate.source.index(RAW_DECOMPILER_SOURCE.strip())


def test_packaged_asm_source_is_not_shimmed(tmp_path: Path) -> None:
    """The C typedef shim is meaningless (and unsafe to inject) for .asm/.s sources."""
    source_path = tmp_path / "candidate.asm"
    asm_source = "mov eax, 1\nret\n"
    source_path.write_text(asm_source, encoding="utf-8")
    row = {
        "sourceTask": True,
        "source": str(source_path),
        "name": "sub_2000",
        "sourceQuality": "asm",
    }

    candidate = packaged_source_candidate(row)

    assert candidate is not None
    assert candidate.source == asm_source
    assert TYPE_SHIM not in candidate.source
