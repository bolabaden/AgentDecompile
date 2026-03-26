"""Regression tests for Ghidra RepositoryAdapter root-folder aliasing (``/`` vs ``""``)."""

from __future__ import annotations

import logging

import pytest

from agentdecompile_cli.mcp_server.repository_adapter_listing import (
    list_repository_adapter_items,
    repository_adapter_folder_candidates,
)


class _StubRepoRootBlank:
    """Some Ghidra Server/JPype setups list root programs only under ``""``, not ``"/"``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def getSubfolderList(self, folder_path: str) -> list[str]:
        self.calls.append(("sub", folder_path))
        return []

    def getItemList(self, folder_path: str) -> list[object]:
        self.calls.append(("items", folder_path))
        if folder_path == "/":
            return []
        if folder_path == "":
            return [_StubItem("foo.exe", "Program")]
        return []


class _StubItem:
    def __init__(self, name: str, content_type: str) -> None:
        self._name = name
        self._ct = content_type

    def getName(self) -> str:
        return self._name

    def getContentType(self) -> str:
        return self._ct


@pytest.mark.unit
def test_list_repository_adapter_items_finds_items_under_blank_root() -> None:
    stub = _StubRepoRootBlank()
    items = list_repository_adapter_items(stub, log=logging.getLogger("test_repo_list"))
    assert len(items) == 1
    assert items[0]["name"] == "foo.exe"
    assert items[0]["path"] == "/foo.exe"
    assert ("items", "") in stub.calls


@pytest.mark.unit
def test_repository_adapter_folder_candidates_includes_slash_and_blank() -> None:
    out = repository_adapter_folder_candidates("/")
    assert "/" in out
    assert "" in out
