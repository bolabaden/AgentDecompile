"""Unit tests for domain_folder_listing (local Ghidra project tree merge)."""

from __future__ import annotations

from typing import Any

from agentdecompile_cli.mcp_server.domain_folder_listing import (
    list_project_tree_from_ghidra,
    walk_domain_folder_tree,
)


class _FakeDomainFile:
    def __init__(self, name: str, pathname: str, content_type: str) -> None:
        self._name = name
        self._pathname = pathname
        self._content_type = content_type

    def getName(self) -> str:
        return self._name

    def getPathname(self) -> str:
        return self._pathname

    def getContentType(self) -> str:
        return self._content_type


class _FakeFolder:
    def __init__(self, name: str, pathname: str, files: list[Any] | None = None, subfolders: list[Any] | None = None) -> None:
        self._name = name
        self._pathname = pathname
        self._files = files or []
        self._subfolders = subfolders or []

    def getName(self) -> str:
        return self._name

    def getPathname(self) -> str:
        return self._pathname

    def getFolders(self) -> list[Any]:
        return list(self._subfolders)

    def getFiles(self) -> list[Any]:
        return list(self._files)

    def getFolder(self, path: str) -> Any | None:
        if path == "/":
            return self
        return None


def test_walk_domain_folder_tree_collects_files() -> None:
    root = _FakeFolder(
        "/",
        "/",
        files=[_FakeDomainFile("a.exe", "/a.exe", "Program")],
    )
    items = walk_domain_folder_tree(root, 50)
    assert len(items) == 1
    assert items[0]["name"] == "a.exe"
    assert items[0]["type"] == "Program"


def test_list_project_tree_from_ghidra_merges_two_roots() -> None:
    root_a = _FakeFolder("/", "/", files=[])
    root_b = _FakeFolder(
        "/",
        "/",
        files=[
            _FakeDomainFile("tool.exe", "/tool.exe", "Program"),
        ],
    )

    class _FakeProjectData:
        def getRootFolder(self) -> Any:
            return root_b

    class _FakeProject:
        def getProjectData(self) -> Any:
            return _FakeProjectData()

    class _FakeGhidraProject:
        def getRootFolder(self) -> Any:
            return root_a

        def getProject(self) -> Any:
            return _FakeProject()

    items = list_project_tree_from_ghidra(_FakeGhidraProject(), normalized_folder="/", max_results=50)
    names = {i["name"] for i in items}
    assert "tool.exe" in names
