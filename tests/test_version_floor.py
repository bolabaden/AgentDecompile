from __future__ import annotations

from pathlib import Path
import re

from packaging.version import Version

from agentdecompile_cli import __version__


def test_package_version_stays_on_configured_fallback_line_or_newer() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    match = re.search(r'^fallback_version\s*=\s*"([^"]+)"\s*$', pyproject.read_text(), re.MULTILINE)
    assert match is not None
    fallback_version = match.group(1)
    assert Version(__version__.split("+", 1)[0]) >= Version(fallback_version)
