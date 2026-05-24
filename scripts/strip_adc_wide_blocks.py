"""Remove trailing _adc_wide_log_sites() blocks from package modules (one-shot cleanup)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src"
NEEDLE = "\ndef _adc_wide_log_sites()"


def main() -> None:
    for path in sorted(ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if NEEDLE not in text:
            continue
        idx = text.index(NEEDLE)
        path.write_text(text[:idx].rstrip() + "\n", encoding="utf-8")
        print("stripped", path.relative_to(ROOT.parent))


if __name__ == "__main__":
    main()
