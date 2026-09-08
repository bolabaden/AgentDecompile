from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from agentdecompile_recovery.corpus import genproject

pytestmark = pytest.mark.unit


def test_popped_bytes_reads_real_epilogue() -> None:
    assert genproject.popped_bytes(b"\x90\xc2\x0c\x00") == 12
    assert genproject.popped_bytes(b"\x90\xc3\xcc\xcc") == 0
    assert genproject.popped_bytes(b"\x90\xe9\x00\x00\x00\x00") is None


def test_symbol_shapes() -> None:
    base = {"addr": 0x401000, "stack_param_size": 99}
    assert genproject.symbol_for({**base, "calling_convention": "__cdecl", "ret_imm": 0}) == (
        "F_00401000", "_F_00401000",
    )
    assert genproject.symbol_for({**base, "calling_convention": "__stdcall", "ret_imm": 12}) == (
        "F_00401000", "_F_00401000@12",
    )
    assert genproject.symbol_for({**base, "calling_convention": "__thiscall", "ret_imm": 4}) == (
        "F_00401000", "@F_00401000@12",
    )
    assert genproject.symbol_for({**base, "calling_convention": "__fastcall", "ret_imm": 4}) == (
        "F_00401000", "@F_00401000@12",
    )
    assert genproject.symbol_for({**base, "calling_convention": "unknown", "ret_imm": 4}) == (
        "F_00401000", "_F_00401000",
    )


def test_build_target_preserves_complete_decorated_symbol() -> None:
    fn = {"addr": 0x401000, "size": 1, "calling_convention": "__stdcall", "ret_imm": 8}
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        raw = out / "raw.bin"
        raw.write_bytes(b"\xc3")
        with mock.patch("agentdecompile_recovery.corpus.genproject.subprocess.run") as run:
            def create_obj(argv, **kwargs):
                Path(argv[argv.index("-o") + 1]).write_bytes(b"obj")
                return mock.Mock(returncode=0)
            run.side_effect = create_obj
            genproject.build_target(fn, raw, 0, out, 32)
        argv = run.call_args.args[0]
        assert argv[argv.index("--name") + 1] == "F_00401000@8"
        assert argv[argv.index("--symbol-prefix") + 1] == "_"


def _prompt(fn):
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        obj = out / "target.o"
        obj.write_bytes(b"obj")
        genproject.write_prompt(fn, out, obj, "disassembly", None)
        return (out / "prompts" / "F_00401000" / "prompt.md").read_text()


def test_zero_argument_stdcall_does_not_claim_ret_zero_instruction() -> None:
    text = _prompt({
        "addr": 0x401000, "canonical_name": "KnownName", "calling_convention": "__stdcall",
        "ret_imm": 0, "n_instances": 1, "confidence": 1.0,
    })
    assert "plain `ret`" in text
    assert "_F_00401000@0" in text
    assert "ends in `ret 0`" not in text
