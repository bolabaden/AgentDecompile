"""Unit tests for the named MSVC compiler-profile registry.

swkotor.exe's Rich header identifies cl 13.00.9466 (MSVC 7.0) as the original
compiler. The pipeline had been compiling with MSVC 8 (cl 14.00.50727.42), two
generations off. vc71 (VC++ Toolkit 2003) is the closest freely-obtainable
toolchain, so a run must be able to select it by name rather than by pasting a
long path; vc80 stays the default so the two can be A/B'd.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentdecompile_recovery.package_verify import (
    COMPILER_PROFILES,
    DEFAULT_COMPILER_PROFILE,
    REPO_ROOT,
    resolve_msvc_root,
    resolve_vc_root_option,
)

pytestmark = pytest.mark.unit


def test_profile_name_resolves_to_toolchain_root() -> None:
    assert resolve_vc_root_option(Path("vc71")) == COMPILER_PROFILES["vc71"]
    assert resolve_vc_root_option("vc80") == COMPILER_PROFILES["vc80"]


def test_profile_name_is_case_insensitive() -> None:
    assert resolve_vc_root_option("VC71") == COMPILER_PROFILES["vc71"]


def test_profile_roots_are_absolute() -> None:
    """compile_with_msvc runs cl.exe with cwd set to a temp dir, so a relative
    root would resolve against that temp dir and fail."""
    for name, root in COMPILER_PROFILES.items():
        assert root.is_absolute(), f"{name} root must be absolute: {root}"


def test_non_profile_value_passes_through_as_a_path() -> None:
    assert resolve_vc_root_option("/opt/some/msvc") == Path("/opt/some/msvc")
    assert resolve_vc_root_option(None) is None


def test_default_stays_vc80() -> None:
    """vc80 is the experimental control for A/B against vc71 -- registering
    vc71 must not silently move existing runs onto a different compiler."""
    assert DEFAULT_COMPILER_PROFILE == "vc80"
    assert resolve_msvc_root(None) == COMPILER_PROFILES["vc80"]


def test_vc_root_env_accepts_a_profile_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VC_ROOT", "vc71")
    assert resolve_msvc_root(None) == COMPILER_PROFILES["vc71"]


def test_registry_matches_compiler_profile_script() -> None:
    """scripts/compiler-profile.sh sweeps the same toolchains from bash. The two
    declarations must not drift, or a sweep and a pipeline run silently compare
    objects built by different compilers."""
    script = (REPO_ROOT / "scripts" / "compiler-profile.sh").read_text(encoding="utf-8")
    declared = dict(re.findall(r'^(VC\d\d)_ROOT="\$\{VC\d\d_ROOT:-(.+?)\}"$', script, re.MULTILINE))
    assert declared, "compiler-profile.sh no longer declares VC71_ROOT/VC80_ROOT"
    for var, raw in declared.items():
        expected = COMPILER_PROFILES[var.lower()]
        resolved = Path(raw.replace("$ROOT/", f"{REPO_ROOT}/"))
        assert resolved == expected, f"{var} drifted: {resolved} != {expected}"
