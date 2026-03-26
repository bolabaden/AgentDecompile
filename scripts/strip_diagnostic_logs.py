"""Remove lines injected by inject_diagnostic_logs.py (diag.enter / diag.except)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "agentdecompile_cli"
MARKERS = ("diag.enter", "diag.except")


def main() -> int:
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        new = [ln for ln in lines if not any(m in ln for m in MARKERS)]
        out = "".join(new)
        # Drop orphan blank line blocks from removed inject-only prepend (best-effort)
        out = re.sub(r"(\nimport logging\n)\n+(logger = logging\.getLogger\(__name__\)\n)", r"\1\2", out)
        if out != text:
            path.write_text(out, encoding="utf-8")
            print("cleaned", path.relative_to(ROOT.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
