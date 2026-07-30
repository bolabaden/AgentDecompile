"""Unit tests for package_verify.build_shim()'s global-variable typing.

Regression coverage for the still-open invalid-C-generation bug documented in
docs/solutions/workflow-learnings/2026-07-25-proof-scale-smoke-swkotor.md:
packaged-source (raw decompiler output) candidates failed to compile with
MSVC C2146-class errors. The bulk of that bug (no typedefs at all for Ghidra
pseudo-types like undefined4/code) was already fixed by prepending TYPE_SHIM
in packaged_source_candidate(). This file covers the residual piece: when a
matched global (DAT_*/PTR_*/etc.) is actually dereferenced or is a Ghidra
PTR_-prefixed name, declaring it as `extern int <name>;` produces a real type
error ("indirection requires pointer operand") -- confirmed against an
archived pre-fix MSVC failure for FUN_00423f10
(target/agentdecompile-reconstruct/swkotor-parity-inv/source-synthesis/cases/
0x423f10_.../candidate.c: `(**(code **)(*DAT_007a68a4 + 8))(...)`) and
independently reproduced today via `clang -fsyntax-only`.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.package_verify import TYPE_SHIM, build_shim

pytestmark = pytest.mark.unit


def test_type_shim_defines_bool() -> None:
    """MSVC8 in C mode has no native bool -- Ghidra's decompiler emits `bool`
    return types routinely (e.g. `bool __fastcall FUN_00406030(char *param_1)`),
    which previously produced C2143 ("missing '{' before '__fastcall'") since
    `bool` was an undeclared identifier being parsed as part of the type.
    Confirmed against the real archived FUN_00406030 failure and re-verified
    with a real wine+MSVC8 compile after this fix (not just clang)."""
    assert "typedef" in TYPE_SHIM
    assert " bool;" in TYPE_SHIM or "\nbool" in TYPE_SHIM


def test_type_shim_defines_ushort() -> None:
    """Ghidra emits `ushort` directly (not just the undefined2 pseudo-type)
    for some decompiled parameter/return types -- confirmed against the real
    archived FUN_0043e340 failure (`uint __fastcall FUN_0043e340(ushort
    *param_1)`, C2143 "missing ')' before '*'")."""
    assert " ushort;" in TYPE_SHIM or "\nushort" in TYPE_SHIM


def test_dereferenced_global_is_declared_as_pointer() -> None:
    source = "void f(void) { (**(code **)(*DAT_007a68a4 + 8))(1); }\n"
    shim = build_shim(source)
    assert "extern char *DAT_007a68a4;" in shim
    assert "extern int DAT_007a68a4;" not in shim


def test_ptr_prefixed_global_is_always_declared_as_pointer() -> None:
    """PTR_ is Ghidra's own naming convention for pointer-typed globals --
    declare it as a pointer unconditionally, not only when a dereference is
    textually adjacent."""
    source = "void f(void) { g_thing(PTR_00500000); }\n"
    shim = build_shim(source)
    assert "extern char *PTR_00500000;" in shim


def test_non_dereferenced_scalar_global_stays_int() -> None:
    source = "void f(void) { if (DAT_00600000 == 5) { return; } }\n"
    shim = build_shim(source)
    assert "extern int DAT_00600000;" in shim
    assert "extern char *DAT_00600000;" not in shim


def test_dereferenced_global_with_intervening_whitespace() -> None:
    source = "void f(void) { int x = *   DAT_00700000; }\n"
    shim = build_shim(source)
    assert "extern char *DAT_00700000;" in shim


def test_multiple_globals_typed_independently() -> None:
    source = "void f(void) { *DAT_00800000 = PTR_00900000; if (DAT_00a00000) {} }\n"
    shim = build_shim(source)
    assert "extern char *DAT_00800000;" in shim
    assert "extern char *PTR_00900000;" in shim
    assert "extern int DAT_00a00000;" in shim
