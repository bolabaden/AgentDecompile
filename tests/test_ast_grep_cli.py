"""Tests for ast_grep_cli.resolve_ast_grep_binary."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import ast_grep_cli

pytestmark = pytest.mark.unit


def test_rejects_linux_setgid_sg_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sg = tmp_path / "sg"
    fake_sg.write_text("#!/bin/sh\necho 'Usage: sg [-] group [[-c] command]'\n", encoding="utf-8")
    fake_sg.chmod(0o755)
    monkeypatch.setattr(ast_grep_cli.shutil, "which", lambda name: str(fake_sg) if name == "sg" else None)

    assert ast_grep_cli.resolve_ast_grep_binary() is None


def test_accepts_ast_grep_named_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "ast-grep"
    fake.write_text("#!/bin/sh\necho 'ast-grep 0.0.0'\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(ast_grep_cli.shutil, "which", lambda name: str(fake) if name == "ast-grep" else None)

    assert ast_grep_cli.resolve_ast_grep_binary() == str(fake)
