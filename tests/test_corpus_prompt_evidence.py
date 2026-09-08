from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

import pytest

from agentdecompile_recovery.corpus import genproject, prompt_evidence

pytestmark = pytest.mark.unit


def _db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript("""
      CREATE TABLE func(binary_id INTEGER, addr INTEGER, name TEXT, namespace TEXT,
        source TEXT, size INTEGER, calling_convention TEXT, return_type TEXT,
        param_count INTEGER, param_types TEXT, stack_frame_size INTEGER,
        stack_param_size INTEGER, stack_local_size INTEGER, signature TEXT,
        n_instr INTEGER, n_blocks INTEGER, n_edges INTEGER, back_edges INTEGER,
        cyclomatic INTEGER, n_callees INTEGER, indirect_calls TEXT, data_refs TEXT,
        strings TEXT, consts TEXT, ext_calls TEXT, name_origin TEXT,
        source_file TEXT, object_file TEXT, stabs_name TEXT, stabs_type TEXT);
      CREATE TABLE calledge(binary_id INTEGER, caller_addr INTEGER, callee_addr INTEGER);
      CREATE TABLE identity(logical_id INTEGER, binary_id INTEGER, addr INTEGER,
        confidence REAL, method TEXT);
      CREATE TABLE binary(id INTEGER, repo_path TEXT);
    """)
    cols = 30
    values = [1, 0x401000, "Target", "", "analysis", 12, "__cdecl", "int",
              0, "[]", 8, 0, 8, "int Target(void)", 4, 1, 0, 0, 1, 1,
              "[]", "[]", '["real string"]', '[7]', '["puts"]', "symbol",
              "src/target.cpp", "target.obj", None, None]
    con.execute(f"INSERT INTO func VALUES ({','.join('?' for _ in range(cols))})", values)
    con.execute("INSERT INTO func VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [1, 0x402000, "Callee", "", "analysis", 8, "__cdecl", "void", 0,
                 "[]", 0, 0, 0, "void Callee(void)", 2, 1, 0, 0, 1, 0, "[]",
                 "[]", "[]", "[]", "[]", "symbol", None, None, None, None])
    con.execute("INSERT INTO calledge VALUES (1,0x401000,0x402000)")
    con.execute("INSERT INTO binary VALUES (1,'/arbitrary/corpus.bin')")
    con.execute("INSERT INTO identity VALUES (9,1,0x401000,0.99,'symbol')")
    return con


def test_packet_uses_exact_target_data() -> None:
    with mock.patch(
        "agentdecompile_recovery.corpus.prompt_evidence._pyghidra_export",
        return_value={"status": "complete", "n_instructions": 4, "n_refs": 1},
    ):
        packet = prompt_evidence.collect(
            _db(), binary_id=1, repo_path="/arbitrary/corpus.bin",
            fn={"addr": 0x401000, "logical_id": 9, "canonical_name": "Target"},
        )
    assert packet["target"]["address"] == "0x00401000"
    assert packet["function"]["strings"] == ["real string"]
    assert packet["relationships"]["callees"][0]["name"] == "Callee"


def test_prompt_has_provenance_and_no_generic_platform_examples() -> None:
    fn = {"addr": 0x401000, "canonical_name": "KnownName", "calling_convention": "__cdecl",
          "ret_imm": 0, "n_instances": 1, "confidence": 1.0}
    evidence = {"function": {"strings": ["hello"], "n_instr": 4},
                "relationships": {}, "pyghidra": {"status": "complete", "n_instructions": 4, "n_refs": 1},
                "agentdecompile": {"status": "not-configured"}}
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        obj = out / "target.o"
        obj.write_bytes(b"obj")
        genproject.write_prompt(fn, out, obj, "disassembly", None, evidence)
        pdir = out / "prompts" / "F_00401000"
        text = (pdir / "prompt.md").read_text()
        assert "`evidence.json`" in text
        assert "Referenced strings: `hello`" in text
        assert "Game Boy" not in text
        assert "GBA" not in text
        assert json.loads((pdir / "evidence.json").read_text())


def test_prompt_renders_complete_agentdecompile_facts() -> None:
    fn = {"addr": 0x401000, "canonical_name": "KnownName",
          "calling_convention": "__cdecl", "ret_imm": 0,
          "n_instances": 1, "confidence": 1.0}
    evidence = {
        "function": {}, "relationships": {}, "pyghidra": {"status": "complete"},
        "agentdecompile": {
            "status": "complete", "collection": "cached",
            "function": {"signature": "int KnownName(void)"},
            "calls": {
                "callerCount": 1, "calleeCount": 1,
                "callers": [{"name": "Caller", "address": "00400000"}],
                "callees": [{"name": "Callee", "address": "00402000"}],
            },
            "references": {
                "incomingRowsReturned": 2, "outgoingRowsReturned": 1,
                "to": [{}, {}], "from": [{}],
            },
        },
    }
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        obj = out / "target.o"
        obj.write_bytes(b"obj")
        genproject.write_prompt(fn, out, obj, "disassembly", None, evidence)
        text = (out / "prompts/F_00401000/prompt.md").read_text()
        assert "int KnownName(void)" in text
        assert "1 callers and 1 callees" in text
        assert "`Caller` (00400000)" in text
        assert "bounded evidence rows, not claimed as complete totals" in text
        assert "provenance: `cached` collection" in text


def test_generator_prefetches_once_and_binds_packets_by_address() -> None:
    fns = [{"addr": 0x401000}, {"addr": 0x402000}]
    live = {
        0x401000: {"status": "complete", "address": "0x00401000"},
        0x402000: {"status": "complete", "address": "0x00402000"},
    }
    with mock.patch(
        "agentdecompile_recovery.corpus.genproject.prompt_evidence.collect_agentdecompile_batch",
        return_value=live,
    ) as collect_batch, mock.patch(
        "agentdecompile_recovery.corpus.genproject.prompt_evidence.collect",
        side_effect=lambda _con, **kwargs: {
            "target": kwargs["fn"]["addr"],
            "agentdecompile": kwargs["agent_context"],
        },
    ) as collect_one:
        packets = genproject.collect_prompt_evidence_batch(
            object(), binary_id=7, repo_path="/arbitrary/game.bin", fns=fns,
        )
    collect_batch.assert_called_once_with("/arbitrary/game.bin", [0x401000, 0x402000])
    assert collect_one.call_count == 2
    assert packets[0x401000]["agentdecompile"]["address"] == "0x00401000"
    assert packets[0x402000]["agentdecompile"]["address"] == "0x00402000"


def test_agentdecompile_collects_a_batch_in_one_local_cli_process() -> None:
    def step(name, payload):
        return {
            "name": name,
            "success": True,
            "result": {"isError": False, "content": [
                {"type": "text", "text": json.dumps(payload)}
            ]},
        }

    addresses = [0x401000, 0x402000]
    results = [step("open", {"serverConnected": True})]
    for addr in addresses:
        hx = f"{addr:08x}"
        results.extend([
            step("get-functions", {"name": f"Fn{hx}", "address": hx,
                                   "signature": "int fn(void)",
                                   "callingConvention": "__cdecl"}),
            step("get-functions", {"address": hx, "callerCount": 1,
                                   "calleeCount": 1,
                                   "callers": [{"name": "Caller", "address": "00400000"}],
                                   "callees": [{"name": "Callee", "address": "00403000"}]}),
            step("get-references", {"target": hx,
                                    "referencesTo": [{"fromAddress": "00400000"}],
                                    "referencesFrom": []}),
        ])
    stdout = "Initializing PyGhidra (local mode)...\n" + json.dumps(
        {"success": True, "steps": results}
    )

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        local_project = root / "projects"
        local_project.mkdir()
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            sequence = json.loads(Path(command[-2]).read_text())
            assert len(sequence) == 7
            assert not any(
                s.get("arguments", {}).get("view") == "decompile"
                for s in sequence
            )
            return CompletedProcess(command, 1, stdout=stdout, stderr="one optional step failed")

        with mock.patch.object(prompt_evidence, "AGENT_CACHE", root / "cache"), \
             mock.patch.object(prompt_evidence, "AGENT_LOCK", root / "cache" / ".lock"), \
             mock.patch.object(prompt_evidence, "AGENT_LOCAL_PROJECT", local_project), \
             mock.patch.object(prompt_evidence.ge, "SSH_KEY", str(root / "key")), \
             mock.patch("agentdecompile_recovery.corpus.prompt_evidence._agent_revision", return_value="test-rev"), \
             mock.patch("agentdecompile_recovery.corpus.prompt_evidence.subprocess.run", side_effect=fake_run), \
             mock.patch.dict("os.environ", {"AGENT_DECOMPILE_SHARED": "1"}):
            (root / "key").write_text("test key")
            packets = prompt_evidence.collect_agentdecompile_batch(
                "/arbitrary/game.bin", addresses,
            )
            cached = prompt_evidence.collect_agentdecompile_batch(
                "/arbitrary/game.bin", addresses,
            )

        assert len(calls) == 1
        assert "--local" in calls[0][0]
        assert packets[0x401000]["status"] == "complete"
        assert packets[0x401000]["addressVerified"]
        assert packets[0x401000]["function"]["name"] == "Fn00401000"
        assert packets[0x402000]["calls"]["calleeCount"] == 1
        assert packets[0x401000]["references"]["to"][0]["fromAddress"] == "00400000"
        assert cached[0x401000]["collection"] == "cached"


def test_pyghidra_lookup_accepts_sixteen_digit_entry_keys() -> None:
    with tempfile.TemporaryDirectory() as td:
        knowledge = Path(td) / "knowledge.sqlite"
        con = sqlite3.connect(knowledge)
        con.execute("""CREATE TABLE func_knowledge(
            program TEXT, entry_hex TEXT, name TEXT, size INTEGER,
            file_offset INTEGER, calling_convention TEXT, signature TEXT,
            decompiled TEXT, asm TEXT, n_instructions INTEGER, n_refs INTEGER
        )""")
        con.execute("INSERT INTO func_knowledge VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ("x64.exe", "0000000140100000", "Target64", 8, 0,
                     "__cdecl", "void Target64(void)", "code", "asm", 2, 1))
        con.commit()
        con.close()
        with mock.patch.object(prompt_evidence, "KNOWLEDGE_DB", knowledge):
            row = prompt_evidence._pyghidra_export("x64.exe", 0x140100000)
        assert row["status"] == "complete"
        assert row["name"] == "Target64"
        assert row["decompiled_bytes"] == 4


def test_optional_decomp_hint_maps_sixteen_digit_entry_keys() -> None:
    mapping = genproject.entry_hex_map([{"addr": 0x140100000}])
    assert mapping["0000000140100000"] == 0x140100000


def test_agent_packet_does_not_claim_complete_without_exact_info() -> None:
    packet = prompt_evidence._compact_agent_packet(
        "/arbitrary/game.bin", 0x401000,
        {"info": {"address": "00402000"}}, "shared-repository",
    )
    assert packet["status"] == "partial"
    assert not packet["addressVerified"]
    assert "calls" in packet["missingViews"]

    with tempfile.TemporaryDirectory() as td, \
         mock.patch.object(prompt_evidence, "AGENT_CACHE", Path(td)):
        assert prompt_evidence._cache_agent_packet(
            "/arbitrary/game.bin", 0x401000, packet,
        ) is None
        assert not any(Path(td).rglob("*.json"))


def test_cli_argv_prefers_venv_script_over_uv() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        venv_cli = root / ".venv" / "bin" / "agentdecompile-cli"
        venv_cli.parent.mkdir(parents=True)
        venv_cli.write_text("#!/bin/sh\n")
        venv_cli.chmod(0o755)
        with mock.patch.object(prompt_evidence, "AGENTDECOMPILE_ROOT", root), \
             mock.patch("agentdecompile_recovery.corpus.prompt_evidence.shutil.which",
                        return_value="/opt/uv"):
            argv = prompt_evidence._agentdecompile_cli_argv()
        assert argv == [str(venv_cli)]


def test_cli_argv_names_missing_tools() -> None:
    with tempfile.TemporaryDirectory() as td, \
         mock.patch.object(prompt_evidence, "AGENTDECOMPILE_ROOT", Path(td)), \
         mock.patch("agentdecompile_recovery.corpus.prompt_evidence.shutil.which",
                    return_value=None):
        assert prompt_evidence._agentdecompile_cli_argv() is None


def test_cache_is_bound_to_effective_project_configuration() -> None:
    packet = {
        "schema": prompt_evidence.AGENT_SCHEMA,
        "status": "complete",
        "agentdecompileRevision": "rev",
        "collectedAt": "2099-01-01T00:00:00+00:00",
        "binding": {"mode": "shared-repository", "programPath": "/arbitrary/game.bin"},
    }
    with tempfile.TemporaryDirectory() as td, \
         mock.patch.object(prompt_evidence, "AGENT_CACHE", Path(td)), \
         mock.patch("agentdecompile_recovery.corpus.prompt_evidence._agent_revision", return_value="rev"):
        prompt_evidence._cache_agent_packet("/arbitrary/game.bin", 0x401000, packet)
        assert prompt_evidence._cached_agent_context(
            "/arbitrary/game.bin", 0x401000, packet["binding"],
        ) is not None
        assert prompt_evidence._cached_agent_context(
            "/arbitrary/game.bin", 0x401000,
            {"mode": "local-project", "programPath": "/arbitrary/game.bin"},
        ) is None
