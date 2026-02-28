from __future__ import annotations

import subprocess
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "helper_scripts" / "generate_tools_list.py"
TOOLS_LIST = ROOT / "TOOLS_LIST.md"
TOOLS_LIST_GENERATED = ROOT / "TOOLS_LIST_GENERATED.md"
DIFF_OUT = ROOT / "tmp" / "TOOLS_LIST_GENERATED.diff"


def test_generated_tools_list_matches_source_of_truth() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert TOOLS_LIST.exists(), "TOOLS_LIST.md is missing"
    assert TOOLS_LIST_GENERATED.exists(), "TOOLS_LIST_GENERATED.md was not generated"
    assert "MATCH_EXACT True" in result.stdout, result.stdout + "\n" + result.stderr

    source = TOOLS_LIST.read_text(encoding="utf-8")
    generated = TOOLS_LIST_GENERATED.read_text(encoding="utf-8")
    assert generated == source, "TOOLS_LIST_GENERATED.md does not match TOOLS_LIST.md"

    if DIFF_OUT.exists():
        assert DIFF_OUT.read_text(encoding="utf-8").strip() == "", "tmp/TOOLS_LIST_GENERATED.diff is non-empty"
