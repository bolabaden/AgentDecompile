from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.contract import PIPELINE_STAGES
from agentdecompile_recovery.corpus.canon import canonicalize, is_eh_clone
from agentdecompile_recovery.corpus.cli import main as corpus_main
from agentdecompile_recovery.corpus.ghidra_sanitize import sanitize_body
from agentdecompile_recovery.corpus.identity import bind_identities, propagate_compiling_source
from agentdecompile_recovery.corpus.match_engine import PAIR_POLICY, match_binaries, score_features
from agentdecompile_recovery.corpus.naming import choose_name, resolve_members
from agentdecompile_recovery.corpus.pipeline import run_corpus_pipeline
from agentdecompile_recovery.corpus.registry import add_binary, new_corpus, save_corpus
from agentdecompile_recovery.corpus.source_claims import is_recovered_source
from agentdecompile_recovery.corpus.workspace import rel_source

pytestmark = pytest.mark.unit

ADD_C = "int add_one(int x) { return x + 1; }\n"
MAIN_C = "int add_one(int x);\nint main(void) { return add_one(40) - 41; }\n"
SHIM_C = "void copied(void) { __asm { nop } }\n"


def test_source_cross_match_is_after_compile() -> None:
    stages = list(PIPELINE_STAGES)
    assert stages.index("identify") < stages.index("generate-projects")
    assert stages.index("recover-source") < stages.index("preparse")
    assert stages.index("preparse") < stages.index("compile")
    assert stages.index("compile") < stages.index("apply-cross-build")
    assert stages.index("apply-cross-build") < stages.index("llm-cleanup")
    assert stages.index("llm-cleanup") < stages.index("verify-byte-accuracy")


def test_placeholder_never_overwrites_stronger_name() -> None:
    name, tier = choose_name("CGuiObject", "stabs", "FUN_00401000", "placeholder")
    assert name == "CGuiObject"
    assert tier == "stabs"
    name, tier = choose_name("FUN_00401000", "placeholder", "CGuiObject", "human")
    assert name == "CGuiObject"
    assert tier == "human"


def test_machine_code_shim_is_not_source() -> None:
    assert is_recovered_source(ADD_C)
    assert not is_recovered_source(SHIM_C)
    assert not is_recovered_source("void f(void) { __declspec(naked) }")
    assert not is_recovered_source("data: .byte 0x90")
    # Linker symbol alias is not inline assembly (kotorxid realc).
    assert is_recovered_source('extern float *g_fFPS_ptr __asm__("PTR_g_fFPS");\nint f(void) { return 1; }\n')


def test_stabs_path_becomes_workspace_relative() -> None:
    assert rel_source("/Users/dev/src/game/add.cpp") == "dev/src/game/add.cpp"
    assert rel_source("/AspyrBuild/depot/game/add.cpp") == "AspyrBuild/depot/game/add.cpp"
    assert rel_source("/tmp/../etc/passwd.c") is None


def test_source_is_not_copied_until_compile(tmp_path: Path) -> None:
    functions = {
        "donor": [{"id": "a", "name": "add_one", "size": 32, "source": ADD_C}],
        "other": [{"id": "b", "name": "add_one", "size": 32, "source": ""}],
    }
    bindings = bind_identities(functions)
    assert bindings
    empty = propagate_compiling_source(functions, bindings, compiled_ids=set())
    assert empty == []
    assert functions["other"][0]["source"] == ""
    placed = propagate_compiling_source(functions, bindings, compiled_ids={"a"})
    assert placed
    assert functions["other"][0]["source"] == ADD_C
    assert functions["other"][0]["source_binary"] == "donor"


def test_source_binary_follows_binding_when_ids_collide() -> None:
    functions = {
        "other": [{"id": "a", "name": "add_one", "size": 32, "source": ""}],
        "donor": [{"id": "a", "name": "add_one", "size": 32, "source": ADD_C}],
    }
    bindings = bind_identities(functions)
    propagate_compiling_source(functions, bindings, compiled_ids={"a"})
    assert functions["other"][0]["source"] == ADD_C
    assert functions["other"][0]["source_binary"] == "donor"


def test_shim_never_propagates() -> None:
    functions = {
        "donor": [{"id": "a", "name": "copied", "size": 8, "source": SHIM_C}],
        "other": [{"id": "b", "name": "copied", "size": 8, "source": ""}],
    }
    bindings = bind_identities(functions)
    placed = propagate_compiling_source(functions, bindings, compiled_ids={"a"})
    assert placed == []
    assert functions["other"][0]["source"] == ""


@pytest.mark.skipif(shutil.which("cc") is None and shutil.which("gcc") is None, reason="no C compiler")
def test_donor_project_links_complete_executable(tmp_path: Path) -> None:
    corpus = new_corpus("fixture")
    add_binary(corpus, binary_id="donor", path=tmp_path / "donor.bin", debug="stabs", donor=True)
    add_binary(corpus, binary_id="other", path=tmp_path / "other.bin", debug="none")
    save_corpus(tmp_path / "corpus.json", corpus)
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "donor.functions.json").write_text(
        json.dumps(
            [
                {
                    "id": "add",
                    "name": "add_one",
                    "size": 32,
                    "source_file": "/depot/game/add.c",
                    "source": ADD_C,
                    "callees": [],
                },
                {
                    "id": "main",
                    "name": "main",
                    "size": 24,
                    "source_file": "/depot/game/main.c",
                    "source": MAIN_C,
                    "callees": ["add"],
                },
            ]
        ),
        encoding="utf-8",
    )
    (snap / "other.functions.json").write_text(
        json.dumps(
            [
                {
                    "id": "add2",
                    "name": "add_one",
                    "size": 30,
                    "source": "",
                    "incoming_name": "FUN_00401000",
                    "incoming_tier": "placeholder",
                },
                {"id": "shim", "name": "copied", "size": 8, "source": SHIM_C},
            ]
        ),
        encoding="utf-8",
    )
    work = tmp_path / "work"
    summary = run_corpus_pipeline(
        corpus,
        work_dir=work,
        snapshot_dir=snap,
        stop_after="verify-byte-accuracy",
    )
    assert summary["completeExecutable"] is True
    exe = work / "linked" / "donor.recovered"
    assert exe.is_file() and exe.stat().st_size > 0
    apply_rows = json.loads((work / "apply-cross-build.json").read_text(encoding="utf-8"))
    assert apply_rows["count"] >= 1
    state = json.loads((work / "functions-state.json").read_text(encoding="utf-8"))
    assert state["other"][0]["source"] == ADD_C
    assert state["other"][1]["source_claim"] == "not-source"
    assert (work / "workspace" / "depot" / "game" / "add.c").is_file()
    verify = json.loads((work / "verify-byte-accuracy.json").read_text(encoding="utf-8"))
    assert verify["byteAccuracy"] is None
    graph = json.loads((work / "call-graph.json").read_text(encoding="utf-8"))
    assert any(edge.get("kind") == "identity" for edge in graph["edges"])


def test_cli_add_binary_and_stages(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.json"
    assert corpus_main(["init", "--id", "demo", "--out", str(corpus)]) == 0
    assert (
        corpus_main(
            [
                "add-binary",
                "--corpus",
                str(corpus),
                "--id",
                "mac-debug",
                "--path",
                "/binaries/debug",
                "--debug",
                "stabs",
                "--donor",
            ]
        )
        == 0
    )
    data = json.loads(corpus.read_text(encoding="utf-8"))
    assert data["donorId"] == "mac-debug"
    assert data["binaries"][0]["debug"] == "stabs"
    assert (
        corpus_main(
            [
                "add-binary",
                "--corpus",
                str(corpus),
                "--id",
                "win-release",
                "--path",
                "/binaries/release",
                "--arch",
                "x86",
                "--bits",
                "32",
                "--format",
                "PE",
                "--game",
                "demo",
            ]
        )
        == 0
    )
    data = json.loads(corpus.read_text(encoding="utf-8"))
    member = next(item for item in data["binaries"] if item["id"] == "win-release")
    assert member["arch"] == "x86"
    assert member["bits"] == 32
    assert member["format"] == "PE"
    assert member["game"] == "demo"
    assert corpus_main(["stages"]) == 0


def test_name_precedence_rescues_placeholder() -> None:
    won = resolve_members(
        [
            {"id": "a", "name": "FUN_00401000", "name_origin": "bare"},
            {"id": "b", "name": "UpdateActions", "stabs_name": "CSWSCreature::UpdateActions", "source_file": "nwscreature.cpp"},
        ]
    )
    assert won["name"] == "CSWSCreature::UpdateActions"
    assert won["tier"] == "stabs"
    assert won["rescued_placeholder"] is True


def test_ghidra_sanitize_flattens_measured_spellings() -> None:
    src = "void __thiscall CExoArrayList<CExoString>::~CExoArrayList(CExoArrayList<CExoString> *this) { this->field110_0x1c8 = 0; }\n"
    out = sanitize_body(src)
    assert "__thiscall" not in out
    assert "__fastcall" in out
    assert "edx_unused" in out
    assert "CExoArrayList_CExoString" in out
    assert "field_1c8" in out
    assert "::" not in out


def test_matcher_accepts_shared_rare_string() -> None:
    left = [
        {
            "id": "a",
            "name": "FUN_1",
            "strings": ["unique-dialog-line"],
            "consts": [0xDEADBEEF],
            "n_blocks": 4,
            "cyclomatic": 3,
            "n_callees": 2,
            "n_instr": 40,
        }
    ]
    right = [
        {
            "id": "b",
            "name": "FUN_2",
            "strings": ["unique-dialog-line"],
            "consts": [0xDEADBEEF],
            "n_blocks": 4,
            "cyclomatic": 3,
            "n_callees": 2,
            "n_instr": 42,
        }
    ]
    score, ev = score_features(left[0], right[0], same_arch=True)
    assert ev["strings"] == 1.0
    assert score > 0.7
    hits = match_binaries(left, right, left_meta={"arch": "x86", "bits": 32, "format": "PE", "game": "g"}, right_meta={"arch": "x86", "bits": 32, "format": "PE", "game": "g"})
    assert hits and hits[0]["status"] == "auto"
    bindings = bind_identities(
        {"left": left, "right": right},
        metas={
            "left": {"arch": "x86", "bits": 32, "format": "PE", "game": "g"},
            "right": {"arch": "x86", "bits": 32, "format": "PE", "game": "g"},
        },
    )
    assert bindings
    assert bindings[0]["threshold"] == PAIR_POLICY["same_platform"]["auto"][0]


def test_canon_and_eh_clone() -> None:
    assert is_eh_clone("Foo", "void Foo() [clone .eh]")
    key = canonicalize("AddHelpPanel", namespace="CSWGuiMainInterface")
    assert key["canon_key"] == "CSWGuiMainInterface::AddHelpPanel"
