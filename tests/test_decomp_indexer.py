"""Tests for decomp_indexer.py, ported from the upstream indexer.spec.ts.

Upstream's C-AST-scanning path (via @ast-grep/napi -- NONMATCH/#if 0/static
inline skipping) and objdiff-based assembly extraction aren't ported here (see
decomp_indexer.py's module docstring), so the spec cases that exercise those
specifically ("skips NONMATCH-wrapped functions", "skips '#if 0'-wrapped
functions", "skips 'static inline' functions") are not translated. Everything
else -- unmatched-assembly scanning, incremental content-hash diffing,
embedding preservation, progress callbacks, call-graph extraction, and atomic
DB writes -- is.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.decomp_function_corpus import CorpusDump, DecompFunctionDoc, VectorEntry
from agentdecompile_recovery.decomp_indexer import (
    CFunctionRecord,
    IndexCodebaseConfig,
    IndexProgress,
    clean_function_text,
    content_hash,
    index_codebase,
    load_existing_index,
    write_index,
)
from agentdecompile_recovery.semantic_embedder import SemanticEmbedder

pytestmark = pytest.mark.unit


def _write_asm(path, name: str, body_lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"\tthumb_func_start {name}", f"{name}:", *body_lines, f"\tthumb_func_end {name}"]
    path.write_text("\n".join(lines))


class TestCleanFunctionText:
    def test_strips_end_nonmatch_prefix_followed_by_blank_lines(self):
        input_text = "END_NONMATCH\n\nvoid sub_804AC58(ClosingWall *wall)\n{\n    // body\n}"
        expected = "void sub_804AC58(ClosingWall *wall)\n{\n    // body\n}"
        assert clean_function_text(input_text) == expected

    def test_strips_end_nonmatch_prefix_followed_by_single_newline(self):
        input_text = "END_NONMATCH\nvoid func(void) {}"
        assert clean_function_text(input_text) == "void func(void) {}"

    def test_does_not_modify_text_without_end_nonmatch(self):
        input_text = "void myFunc(int x)\n{\n    return;\n}"
        assert clean_function_text(input_text) == input_text

    def test_does_not_strip_end_nonmatch_in_the_middle_of_text(self):
        input_text = "void func(void)\n{\n    END_NONMATCH\n}"
        assert clean_function_text(input_text) == input_text


class TestWriteIndex:
    def test_writes_index_atomically(self, tmp_path):
        dump = CorpusDump(
            platform="gba",
            functions=[
                DecompFunctionDoc(
                    id="func1", name="func1", asm_code="push {lr}\nbx lr", asm_module_path="src/func1.s"
                )
            ],
            vectors=[],
        )

        write_index(tmp_path, dump, {"func1": "abc123"})

        loaded_dump, content_hashes = load_existing_index(tmp_path)
        assert loaded_dump is not None
        assert len(loaded_dump.functions) == 1
        assert loaded_dump.functions[0].name == "func1"
        assert loaded_dump.platform == "gba"
        assert content_hashes["func1"] == "abc123"

    def test_does_not_leave_tmp_file_on_success(self, tmp_path):
        dump = CorpusDump(platform="gba", functions=[], vectors=[])

        write_index(tmp_path, dump, {})

        files = sorted(p.name for p in tmp_path.iterdir())
        assert files == ["decomp-function-index.json"]


class TestIndexCodebase:
    def test_scans_unmatched_assembly_functions_from_asm_folders(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        _write_asm(
            project_root / "asm" / "non_matching" / "code.s",
            "MyFunc",
            ["\tpush {r4, lr}", "\tmov r0, #1", "\tpop {r4}", "\tbx lr"],
        )

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm/non_matching"],
        )
        result = index_codebase(config)

        assert result.stats.unmatched_functions == 1
        assert len(result.dump.functions) == 1
        assert result.dump.functions[0].name == "MyFunc"
        assert result.dump.functions[0].asm_code == (
            "\tthumb_func_start MyFunc\nMyFunc:\n\tpush {r4, lr}\n\tmov r0, #1\n\tpop {r4}\n\tbx lr\n"
            "\tthumb_func_end MyFunc"
        )
        assert result.dump.functions[0].c_code is None

    def test_skips_empty_functions(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_dir = project_root / "asm"
        asm_dir.mkdir()
        (asm_dir / "empty.s").write_text(
            "\tthumb_func_start EmptyFunc\nEmptyFunc:\n\tthumb_func_end EmptyFunc"
        )

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )
        result = index_codebase(config)

        assert result.stats.unmatched_functions == 0
        assert len(result.dump.functions) == 0

    def test_resolves_matched_c_functions_via_matching_asm_folder(self, tmp_path):
        # Positive-control replacement for the upstream ast-grep-driven NONMATCH/
        # #if-0/static-inline tests: here the caller supplies the already-filtered
        # C function record directly (see module docstring for why).
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        _write_asm(project_root / "asm" / "matchings" / "NormalFunc.s", "NormalFunc", ["\tpush {lr}", "\tbx lr"])

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            matching_asm_folders=["asm/matchings"],
            c_functions=[
                CFunctionRecord(name="NormalFunc", c_code="void NormalFunc(int a) { }", c_module_path="src/test.c")
            ],
        )
        result = index_codebase(config)

        names = [fn.name for fn in result.dump.functions]
        assert names == ["NormalFunc"]
        assert result.stats.matched_functions == 1
        assert result.dump.functions[0].c_code == "void NormalFunc(int a) { }"

    def test_excludes_c_functions_under_excluded_directories(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        _write_asm(project_root / "asm" / "matchings" / "ToolFunc.s", "ToolFunc", ["\tpush {lr}", "\tbx lr"])

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            matching_asm_folders=["asm/matchings"],
            exclude_from_scan=["tools"],
            c_functions=[
                CFunctionRecord(name="ToolFunc", c_code="void ToolFunc(void) { }", c_module_path="tools/test.c")
            ],
        )
        result = index_codebase(config)

        assert result.stats.matched_functions == 0
        assert result.dump.functions == []

    def test_computes_incremental_diff_against_existing_db(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text(
            "\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA\n\n"
            "\tthumb_func_start FuncB\nFuncB:\n\tmov r0, #1\n\tbx lr\n\tthumb_func_end FuncB"
        )

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        result1 = index_codebase(config)
        assert result1.stats.new_count == 2
        assert result1.stats.unchanged_count == 0

        write_index(project_root, result1.dump, result1.content_hashes)
        existing_dump, existing_hashes = load_existing_index(project_root)

        result2 = index_codebase(config, existing_dump=existing_dump, existing_content_hashes=existing_hashes)
        assert result2.stats.new_count == 0
        assert result2.stats.unchanged_count == 2
        assert result2.stats.updated_count == 0
        assert result2.stats.removed_count == 0

    def test_detects_updated_functions_on_reindex(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        result1 = index_codebase(config)
        write_index(project_root, result1.dump, result1.content_hashes)

        asm_path.write_text(
            "\tthumb_func_start FuncA\nFuncA:\n\tpush {r4, lr}\n\tmov r0, #42\n\tpop {r4}\n\tbx lr\n"
            "\tthumb_func_end FuncA"
        )

        existing_dump, existing_hashes = load_existing_index(project_root)
        result2 = index_codebase(config, existing_dump=existing_dump, existing_content_hashes=existing_hashes)

        assert result2.stats.updated_count == 1
        assert result2.stats.unchanged_count == 0

    def test_detects_removed_functions_on_reindex(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text(
            "\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA\n\n"
            "\tthumb_func_start FuncB\nFuncB:\n\tmov r0, #1\n\tbx lr\n\tthumb_func_end FuncB"
        )

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        result1 = index_codebase(config)
        write_index(project_root, result1.dump, result1.content_hashes)

        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        existing_dump, existing_hashes = load_existing_index(project_root)
        result2 = index_codebase(config, existing_dump=existing_dump, existing_content_hashes=existing_hashes)

        assert result2.stats.removed_count == 1
        assert len(result2.dump.functions) == 1

    def test_preserves_existing_embeddings_for_unchanged_functions(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        result1 = index_codebase(config)
        result1.dump.vectors.append(VectorEntry(id="FuncA", embedding=[0.1, 0.2, 0.3]))
        write_index(project_root, result1.dump, result1.content_hashes)

        existing_dump, existing_hashes = load_existing_index(project_root)
        result2 = index_codebase(config, existing_dump=existing_dump, existing_content_hashes=existing_hashes)

        assert len(result2.dump.vectors) == 1
        assert result2.dump.vectors[0].id == "FuncA"
        assert result2.dump.vectors[0].embedding == [0.1, 0.2, 0.3]

    def test_embeds_new_functions_via_injected_embedder(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        seen_texts: list[str] = []

        def fake_backend(texts: list[str]) -> list[list[float]]:
            seen_texts.extend(texts)
            return [[1.0, 2.0] for _ in texts]

        result = index_codebase(config, embedder=SemanticEmbedder(backend=fake_backend))

        assert len(result.dump.vectors) == 1
        assert result.dump.vectors[0].id == "FuncA"
        assert result.dump.vectors[0].embedding == [1.0, 2.0]
        assert len(seen_texts) == 1
        # Embedding text is preprocessed (function-body isolated), not raw asm with directives.
        assert "thumb_func_start" not in seen_texts[0]

    def test_handles_missing_asm_directories_gracefully(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["nonexistent/asm"],
        )
        result = index_codebase(config)

        assert result.stats.unmatched_functions == 0
        assert len(result.dump.functions) == 0

    def test_reports_progress_callbacks(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )

        progress_phases: list[str] = []

        def on_progress(p: IndexProgress) -> None:
            progress_phases.append(p.phase)

        index_codebase(config, on_progress=on_progress)

        assert "scanning-c" in progress_phases
        assert "scanning-asm" in progress_phases
        assert "diffing" in progress_phases
        assert "writing" in progress_phases

    def test_extracts_call_graph_from_assembly(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text(
            "\tthumb_func_start Caller\nCaller:\n\tpush {lr}\n\tbl Helper\n\tbl AnotherFunc\n\tpop {r0}\n"
            "\tbx r0\n\tthumb_func_end Caller"
        )

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )
        result = index_codebase(config)

        caller = next(fn for fn in result.dump.functions if fn.name == "Caller")
        assert "Helper" in caller.calls_functions
        assert "AnotherFunc" in caller.calls_functions

    def test_includes_content_hashes_in_result(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        map_file_path = project_root / "test.map"
        map_file_path.write_text("")

        asm_path = project_root / "asm" / "code.s"
        asm_path.parent.mkdir(parents=True)
        asm_path.write_text("\tthumb_func_start FuncA\nFuncA:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end FuncA")

        config = IndexCodebaseConfig(
            project_root=project_root,
            map_file_path=map_file_path,
            platform="arm",
            non_matching_asm_folders=["asm"],
        )
        result = index_codebase(config)

        assert result.dump.platform == "arm"
        assert "FuncA" in result.content_hashes
        assert isinstance(result.content_hashes["FuncA"], str)


class TestContentHash:
    def test_same_asm_and_c_code_produce_the_same_hash(self):
        assert content_hash("mov r0, #1", "int f(void) {}") == content_hash("mov r0, #1", "int f(void) {}")

    def test_different_asm_code_produces_a_different_hash(self):
        assert content_hash("mov r0, #1") != content_hash("mov r0, #2")

    def test_different_c_code_produces_a_different_hash(self):
        assert content_hash("mov r0, #1", "a") != content_hash("mov r0, #1", "b")

    def test_missing_c_code_is_treated_like_empty_string(self):
        assert content_hash("mov r0, #1", None) == content_hash("mov r0, #1", "")
