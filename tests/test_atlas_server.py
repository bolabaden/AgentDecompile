"""Tests for atlas_server.py's JSON API handlers and HTTP wrapper."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from agentdecompile_recovery.atlas_server import (
    AtlasServerState,
    handle_build_prompt,
    handle_load_project,
    handle_save_prompt,
    serve_atlas,
)
from agentdecompile_recovery.decomp_function_corpus import CorpusDump, DecompFunctionDoc, VectorEntry
from agentdecompile_recovery.decomp_indexer import write_index

pytestmark = pytest.mark.unit


def _seed_index(project_root: Path) -> None:
    dump = CorpusDump(
        platform="win32",
        functions=[
            DecompFunctionDoc(id="fn1", name="target_func", asm_code="push ebp\nret", asm_module_path="a.c"),
            DecompFunctionDoc(
                id="fn2",
                name="similar_func",
                c_code="int similar_func(void) { return 1; }",
                c_module_path="a.c",
                asm_code="push ebp\nret",
                asm_module_path="a.s",
            ),
        ],
        vectors=[VectorEntry(id="fn1", embedding=[1.0, 0.0]), VectorEntry(id="fn2", embedding=[0.9, 0.1])],
    )
    write_index(project_root, dump, {})


class TestHandleLoadProject:
    def test_returns_404_when_no_index_written(self, tmp_path: Path):
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")

        payload, status = handle_load_project(state)

        assert status == 404
        assert "error" in payload

    def test_loads_functions_and_populates_corpus(self, tmp_path: Path):
        _seed_index(tmp_path)
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")

        payload, status = handle_load_project(state)

        assert status == 200
        assert state.corpus is not None
        names = [fn["name"] for fn in payload["data"]["functions"]]
        assert "target_func" in names


class TestHandleBuildPrompt:
    def test_returns_400_before_load_project(self, tmp_path: Path):
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")

        payload, status = handle_build_prompt(state, "fn1")

        assert status == 400
        assert "not loaded" in payload["error"].lower()

    def test_builds_prompt_after_load_project(self, tmp_path: Path):
        _seed_index(tmp_path)
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")
        handle_load_project(state)

        payload, status = handle_build_prompt(state, "fn1")

        assert status == 200
        assert "target_func" in payload["prompt"]

    def test_returns_400_for_unknown_function(self, tmp_path: Path):
        _seed_index(tmp_path)
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")
        handle_load_project(state)

        payload, status = handle_build_prompt(state, "nonexistent")

        assert status == 400


class TestHandleSavePrompt:
    def test_writes_prompt_md_and_settings_yaml(self, tmp_path: Path):
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")

        payload, status = handle_save_prompt(
            state, function_name="my_func", prompt_content="# decompile this", asm="push ebp\nret\n"
        )

        assert status == 200
        prompt_dir = tmp_path / "prompts" / "my_func"
        assert (prompt_dir / "prompt.md").read_text(encoding="utf-8") == "# decompile this"
        assert 'functionName: "my_func"' in (prompt_dir / "settings.yaml").read_text(encoding="utf-8")

    def test_falls_back_to_placeholder_object_path_without_symbol_map(self, tmp_path: Path):
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")

        handle_save_prompt(state, function_name="my_func", prompt_content="x", asm="ret")

        settings = (tmp_path / "prompts" / "my_func" / "settings.yaml").read_text(encoding="utf-8")
        assert "OBJECT_FILE_NOT_FOUND" in settings


class TestServeAtlasHttp:
    def test_serves_load_project_and_build_prompt_over_real_http(self, tmp_path: Path):
        _seed_index(tmp_path)
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")
        server = serve_atlas(state, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            load_req = Request(
                f"http://127.0.0.1:{port}/api/loadProject",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(load_req, timeout=5) as resp:
                load_payload = json.loads(resp.read())
            assert any(fn["name"] == "target_func" for fn in load_payload["data"]["functions"])

            build_req = Request(
                f"http://127.0.0.1:{port}/api/buildPrompt",
                data=json.dumps({"functionId": "fn1"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(build_req, timeout=5) as resp:
                build_payload = json.loads(resp.read())
            assert "target_func" in build_payload["prompt"]
        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_serves_ui_html_over_get(self, tmp_path: Path):
        state = AtlasServerState(project_root=tmp_path, prompts_dir=tmp_path / "prompts", platform="win32")
        server = serve_atlas(state, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                html = resp.read().decode("utf-8")
                content_type = resp.headers.get("Content-Type")
            assert content_type is not None and "text/html" in content_type
            assert "<html>" in html
            assert "/api/loadProject" in html
            assert "/api/buildPrompt" in html
            assert "/api/savePrompt" in html
        finally:
            server.shutdown()
            thread.join(timeout=5)
