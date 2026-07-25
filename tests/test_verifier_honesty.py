"""Regression tests for fail-closed recovery verification."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from agentdecompile_recovery import package_verify
from agentdecompile_recovery.artifact_layout import is_objdiff_zero_accept
from agentdecompile_recovery.match_cache import is_proven_zero
from agentdecompile_recovery.objdiff_verification import parse_objdiff_report
from agentdecompile_recovery.proof_ladder import build_proof_ladder
from agentdecompile_recovery.source_dump import looks_like_byte_emitter


def test_empty_objdiff_output_is_error() -> None:
    report = parse_objdiff_report(0, "")

    assert report["status"] == "error"
    assert report["differences"] == -1


def test_unparseable_objdiff_output_is_error() -> None:
    report = parse_objdiff_report(0, "not json")

    assert report["status"] == "error"
    assert report["differences"] == -1


def test_objdump_fallback_is_not_proven_zero() -> None:
    assert not is_proven_zero(
        {
            "status": "matched",
            "differences": 0,
            "fallback": "objdump-disassembly-byte-compare",
        }
    )


def test_real_objdiff_zero_is_proven() -> None:
    assert is_proven_zero({"status": "matched", "differences": 0})


def test_asm_emitter_shapes_rejected() -> None:
    assert looks_like_byte_emitter("void f(void){ _asm { mov eax, 1 } }\n")
    assert looks_like_byte_emitter("payload db 90h, 90h\n")


def test_msvc_compile_does_not_reuse_stale_object(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vc_root = tmp_path / "vc"
    (vc_root / "bin").mkdir(parents=True)
    (vc_root / "bin" / "cl.exe").write_bytes(b"fixture")
    source = tmp_path / "candidate.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")
    object_path = tmp_path / "candidate.obj"
    object_path.write_bytes(b"stale-object")

    monkeypatch.setattr(
        package_verify,
        "run_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    result = package_verify.compile_with_msvc(
        source=source,
        object_path=object_path,
        out_dir=tmp_path,
        stem="candidate",
        args=[],
        timeout=5,
        msvc_root=vc_root,
        wine="wine",
        wineprefix=None,
    )

    assert result["status"] == "failed"
    assert not object_path.exists()


def test_mismatch_class_does_not_promote_without_objdiff_zero() -> None:
    assert not is_objdiff_zero_accept(
        {
            "status": "mismatched",
            "differences": 3,
            "mismatchClass": "operand",
        }
    )


def test_proof_ladder_requires_function_candidate_inventory(tmp_path: Path) -> None:
    (tmp_path / "binary-inventory.json").write_text(
        json.dumps(
            {
                "symbols": [
                    {"name": "exported", "type": "function"},
                ]
            }
        ),
        encoding="utf-8",
    )

    ladder = build_proof_ladder(tmp_path)

    assert ladder["status"] == "no-inventory"
    assert ladder["denominator"] == 0
    assert ladder["denominatorSource"] is None
