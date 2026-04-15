from __future__ import annotations

from dataclasses import dataclass
import sys
import types

import pytest

import agentdecompile_cli.mcp_utils.decompiler_util as decompiler_util


@dataclass
class FakeDomainFile:
    path: str

    def getPathname(self) -> str:
        return self.path


@dataclass(eq=False)
class FakeProgram:
    path: str

    def getDomainFile(self) -> FakeDomainFile:
        return FakeDomainFile(self.path)


class FakeDecompiler:
    def __init__(self, program: FakeProgram | None = None) -> None:
        self._program = program
        self.disposed = 0
        self.options_set = 0
        self.c_code_toggles: list[bool] = []
        self.syntax_tree_toggles: list[bool] = []
        self.simplification_styles: list[str] = []
        self.open_program_calls = 0
        self.last_message = ""

    def getProgram(self) -> FakeProgram | None:
        return self._program

    def setOptions(self, options: object) -> None:
        self.options_set += 1

    def toggleCCode(self, value: bool) -> None:
        self.c_code_toggles.append(value)

    def toggleSyntaxTree(self, value: bool) -> None:
        self.syntax_tree_toggles.append(value)

    def setSimplificationStyle(self, value: str) -> None:
        self.simplification_styles.append(value)

    def openProgram(self, program: FakeProgram) -> None:
        self._program = program
        self.open_program_calls += 1

    def getLastMessage(self) -> str:
        return self.last_message

    def dispose(self) -> None:
        self.disposed += 1


class FakeOpenFailureDecompiler(FakeDecompiler):
    def openProgram(self, program: FakeProgram) -> bool:
        self._program = program
        self.open_program_calls += 1
        self.last_message = "Decompiler process failed to launch"
        return False


class FakeDecompileOptions:
    def __init__(self) -> None:
        self.grabbed_program: FakeProgram | None = None
        self.max_payload_mb: int | None = None

    def grabFromProgram(self, program: FakeProgram) -> None:
        self.grabbed_program = program

    def setMaxPayloadMBytes(self, value: int) -> None:
        self.max_payload_mb = value


def test_programs_same_decompiler_context_requires_same_program_object() -> None:
    program_a = FakeProgram("/same/path")
    program_b = FakeProgram("/same/path")

    assert decompiler_util.programs_same_decompiler_context(program_a, program_a)
    assert not decompiler_util.programs_same_decompiler_context(program_a, program_b)


def test_resolve_decompiler_for_program_opens_fresh_interface_for_reloaded_program(monkeypatch) -> None:
    program_a = FakeProgram("/same/path")
    program_b = FakeProgram("/same/path")
    session_decompiler = FakeDecompiler(program_a)
    fresh_decompiler = FakeDecompiler(program_b)

    monkeypatch.setattr(decompiler_util, "_configure_decompiler_for_program", lambda decompiler, program: None)
    monkeypatch.setattr(decompiler_util, "open_decompiler_for_program", lambda program: fresh_decompiler)

    resolved, owns_dispose = decompiler_util.resolve_decompiler_for_program(session_decompiler, program_b)

    assert resolved is fresh_decompiler
    assert owns_dispose is True


def test_acquire_decompiler_for_program_reuses_session_with_reentrant_lock(monkeypatch) -> None:
    program = FakeProgram("/same/path")
    session_decompiler = FakeDecompiler(program)

    monkeypatch.setattr(decompiler_util, "_configure_decompiler_for_program", lambda decompiler, current_program: None)

    with decompiler_util.acquire_decompiler_for_program(session_decompiler, program) as first_lease:
        assert first_lease.decompiler is session_decompiler
        assert first_lease.owns_dispose is False
        assert first_lease.reused_session is True

        with decompiler_util.acquire_decompiler_for_program(session_decompiler, program) as second_lease:
            assert second_lease.decompiler is session_decompiler
            assert second_lease.owns_dispose is False
            assert second_lease.reused_session is True

    assert session_decompiler.disposed == 0


def test_acquire_decompiler_for_program_uses_ephemeral_interface_for_different_program(monkeypatch) -> None:
    program_a = FakeProgram("/same/path")
    program_b = FakeProgram("/same/path")
    session_decompiler = FakeDecompiler(program_a)
    fresh_decompiler = FakeDecompiler(program_b)

    monkeypatch.setattr(decompiler_util, "open_decompiler_for_program", lambda program: fresh_decompiler)

    with decompiler_util.acquire_decompiler_for_program(session_decompiler, program_b) as lease:
        assert lease.decompiler is fresh_decompiler
        assert lease.owns_dispose is True
        assert lease.reused_session is False

    assert fresh_decompiler.disposed == 1


def test_open_decompiler_for_program_accepts_none_return_from_open_program(monkeypatch) -> None:
    fake_decompiler = FakeDecompiler()

    fake_module = types.ModuleType("ghidra.app.decompiler")
    fake_module.DecompInterface = lambda: fake_decompiler
    fake_module.DecompileOptions = FakeDecompileOptions
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", fake_module)

    program = FakeProgram("/program/path")
    result = decompiler_util.open_decompiler_for_program(program)

    assert result is fake_decompiler
    assert fake_decompiler.open_program_calls == 1
    assert fake_decompiler.getProgram() is program
    assert fake_decompiler.c_code_toggles == [True]
    assert fake_decompiler.syntax_tree_toggles == [False]
    assert fake_decompiler.simplification_styles == ["decompile"]


def test_open_decompiler_for_program_raises_when_open_program_returns_false(monkeypatch) -> None:
    fake_decompiler = FakeOpenFailureDecompiler()

    fake_module = types.ModuleType("ghidra.app.decompiler")
    fake_module.DecompInterface = lambda: fake_decompiler
    fake_module.DecompileOptions = FakeDecompileOptions
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", fake_module)

    with pytest.raises(RuntimeError, match="Decompiler process failed to launch"):
        decompiler_util.open_decompiler_for_program(FakeProgram("/program/path"))

    assert fake_decompiler.disposed == 1