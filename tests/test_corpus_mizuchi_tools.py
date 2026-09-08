from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus import (
    collect_source,
    coverage_report,
    mizuchi_tools_cli,
    mkobj,
)
from agentdecompile_recovery.corpus.cli import build_parser, main as corpus_main

pytestmark = pytest.mark.unit


def test_mizuchi_commands_registered_on_corpus_parser() -> None:
    subs = build_parser()._subparsers._group_actions[0].choices  # type: ignore[attr-defined]
    missing = sorted(mizuchi_tools_cli.MIZUCHI_COMMANDS - set(subs))
    assert missing == [], f"missing subcommands: {missing}"


def test_collect_source_and_coverage_report_offline(tmp_path: Path) -> None:
    cov = tmp_path / "coverage"
    cov.mkdir()
    (cov / "demo.jsonl").write_text(
        json.dumps(
            {
                "function": "addOne",
                "byteExact": True,
                "size": 16,
                "convention": "stdcall",
                "address": "0x401000",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    projects = tmp_path / "projects" / "demo_batch"
    projects.mkdir(parents=True)
    (projects / "manifest.json").write_text(json.dumps({"program": "demo"}), encoding="utf-8")
    (projects / "run-results-001.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "success": True,
                        "promptPath": "addOne",
                        "attempts": [
                            {
                                "pluginResults": [
                                    {
                                        "pluginId": "claude-runner",
                                        "data": {"generatedCode": "int addOne(void) { return 1; }\n"},
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "recovered"
    result = collect_source.collect(
        projects_dir=tmp_path / "projects",
        coverage_dir=cov,
        out_dir=out,
        recovery_root=tmp_path,
    )
    assert result["byte_exact"] == 1
    assert (out / "demo" / "addOne.c").is_file()

    summary = coverage_report.summarize(cov)
    text = coverage_report.format_report(summary)
    assert "demo" in text
    assert summary["grand"]["exact"] == 1


def test_mkobj_cli_roundtrip(tmp_path: Path) -> None:
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90" * 4 + b"\xc3")
    out = tmp_path / "fn.o"
    assert (
        corpus_main(
            [
                "mkobj",
                "--binary", str(raw),
                "--offset", "4",
                "--size", "1",
                "--name", "ret",
                "-o", str(out),
            ]
        )
        == 0
    )
    assert out.is_file()
    assert mkobj.MACHINE["coff-i386"] == 0x014C


def test_cli_coverage_report_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cov = tmp_path / "coverage"
    cov.mkdir()
    (cov / "p.jsonl").write_text(
        json.dumps({"function": "f", "matched": True, "byteExact": True, "size": 8}) + "\n",
        encoding="utf-8",
    )
    assert corpus_main(["coverage-report", "--coverage-dir", str(cov), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["grand"]["exact"] == 1
