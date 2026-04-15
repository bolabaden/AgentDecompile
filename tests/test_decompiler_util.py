from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
import sys

import agentdecompile_cli.mcp_utils.decompiler_util as decompiler_util
from agentdecompile_cli.context import ProgramInfo, PyGhidraContext


@dataclass
class FakeDomainFile:
    path: str

    def getPathname(self) -> str:
        return self.path


@dataclass(eq=False)
class FakeProgram:
    path: str

    name: str | None = None

    def getDomainFile(self) -> FakeDomainFile:
        return FakeDomainFile(self.path)

    def getName(self) -> str:
        return self.name or self.path.rsplit("/", 1)[-1]


class FakeDecompiler:
    def __init__(self, program: FakeProgram | None = None) -> None:
        self._program = program
        self.disposed = 0
        self.options_set = 0

    def getProgram(self) -> FakeProgram | None:
        return self._program

    def setOptions(self, options: object) -> None:
        self.options_set += 1

    def dispose(self) -> None:
        self.disposed += 1


class FakeOptions:
    def __init__(self) -> None:
        self.grabbed_program: FakeProgram | None = None
        self.max_payload: int | None = None

    def grabFromProgram(self, program: FakeProgram) -> None:
        self.grabbed_program = program

    def setMaxPayloadMBytes(self, value: int) -> None:
        self.max_payload = value


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


def test_open_decompiler_for_program_retries_after_initial_launch_failure(monkeypatch) -> None:
    program = FakeProgram("/same/path")
    first = FakeDecompiler(program)
    second = FakeDecompiler(program)
    attempts = [False, True]

    def open_program(_program: FakeProgram) -> bool:
        return attempts.pop(0)

    first.openProgram = open_program  # type: ignore[attr-defined]
    first.getLastMessage = lambda: "Decompiler process failed to launch"  # type: ignore[attr-defined]
    second.openProgram = lambda _program: True  # type: ignore[attr-defined]
    second.getLastMessage = lambda: ""  # type: ignore[attr-defined]

    decompilers = [first, second]

    fake_ghidra = ModuleType("ghidra")
    fake_ghidra_app = ModuleType("ghidra.app")
    fake_ghidra_decompiler = ModuleType("ghidra.app.decompiler")
    setattr(fake_ghidra_decompiler, "DecompInterface", lambda: decompilers.pop(0))
    setattr(fake_ghidra_decompiler, "DecompileOptions", FakeOptions)

    monkeypatch.setitem(sys.modules, "ghidra", fake_ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.app", fake_ghidra_app)
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", fake_ghidra_decompiler)

    result = decompiler_util.open_decompiler_for_program(program)

    assert result is second
    assert first.disposed == 1
    assert second.disposed == 0


def test_setup_decompiler_returns_none_when_open_fails(monkeypatch) -> None:
    context = object.__new__(PyGhidraContext)
    program = FakeProgram("/same/path", name="demo")

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.open_decompiler_for_program",
        lambda _program: (_ for _ in ()).throw(RuntimeError("launch failed")),
    )

    result = PyGhidraContext.setup_decompiler(context, program)  # type: ignore[misc]

    assert result is None


def test_program_info_get_decompiler_caches_successful_lazy_init(monkeypatch) -> None:
    program = FakeProgram("/same/path", name="demo")
    opened = FakeDecompiler(program)
    info = ProgramInfo(
        name="demo",
        program=program,
        flat_api=None,
        decompiler=None,
        metadata={},
        ghidra_analysis_complete=False,
    )

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.open_decompiler_for_program",
        lambda _program: opened,
    )

    assert info.get_decompiler() is opened
    assert info.get_decompiler() is opened