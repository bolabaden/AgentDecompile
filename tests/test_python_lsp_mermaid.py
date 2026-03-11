from __future__ import annotations

import json
import subprocess
import sys

from pathlib import Path


def test_python_lsp_mermaid_generates_expected_edges(tmp_path: Path) -> None:
    package_dir = tmp_path / "samplepkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "a.py").write_text(
        "from samplepkg.b import baz\n\n"
        "def foo():\n"
        "    return 1\n\n"
        "def bar():\n"
        "    foo()\n"
        "    baz()\n",
        encoding="utf-8",
    )
    (package_dir / "b.py").write_text(
        "from samplepkg.a import foo\n\n"
        "def baz():\n"
        "    return foo()\n",
        encoding="utf-8",
    )

    script_path = Path(__file__).resolve().parents[1] / "helper_scripts" / "python_lsp_mermaid.py"
    output_path = tmp_path / "diagram.mmd"
    json_path = tmp_path / "diagram.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(script_path),
            str(package_dir),
            "--root",
            str(tmp_path),
            "--output",
            str(output_path),
            "--json-output",
            str(json_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert output_path.exists(), completed.stderr
    assert json_path.exists(), completed.stderr

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    summary = payload["summary"]
    assert summary["resolved_calls"] >= 3
    assert summary["placeholder_calls"] == 0

    call_edges = {
        (edge["source"], edge["target"])
        for edge in payload["edges"]
        if edge["kind"] == "calls"
    }
    import_edges = {
        (edge["source"], edge["target"])
        for edge in payload["edges"]
        if edge["kind"] == "imports"
    }

    assert ("samplepkg.a.bar", "samplepkg.a.foo") in call_edges
    assert ("samplepkg.a.bar", "samplepkg.b.baz") in call_edges
    assert ("samplepkg.b.baz", "samplepkg.a.foo") in call_edges
    assert ("module::samplepkg.a", "module::samplepkg.b") in import_edges

    mermaid = output_path.read_text(encoding="utf-8")
    assert "flowchart TD" in mermaid
    assert "samplepkg.a" in mermaid
    assert "samplepkg.b" in mermaid


def test_python_lsp_mermaid_resolves_class_and_alias_calls(tmp_path: Path) -> None:
    package_dir = tmp_path / "samplepkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "helpers.py").write_text(
        "class Worker:\n"
        "    def run(self):\n"
        "        return 1\n"
        "\n"
        "def helper():\n"
        "    return Worker()\n",
        encoding="utf-8",
    )
    (package_dir / "main.py").write_text(
        "from samplepkg.helpers import Worker, helper as make_worker\n"
        "import samplepkg.helpers as helpers\n"
        "\n"
        "class Service:\n"
        "    def start(self):\n"
        "        self.finish()\n"
        "        worker = Worker()\n"
        "        worker.run()\n"
        "        make_worker()\n"
        "        helpers.helper()\n"
        "\n"
        "    def finish(self):\n"
        "        return None\n",
        encoding="utf-8",
    )

    script_path = Path(__file__).resolve().parents[1] / "helper_scripts" / "python_lsp_mermaid.py"
    output_path = tmp_path / "diagram.mmd"
    json_path = tmp_path / "diagram.json"

    subprocess.run(
        [
            sys.executable,
            str(script_path),
            str(package_dir),
            "--root",
            str(tmp_path),
            "--output",
            str(output_path),
            "--json-output",
            str(json_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    call_edges = {
        (edge["source"], edge["target"])
        for edge in payload["edges"]
        if edge["kind"] == "calls"
    }
    assert payload["summary"]["placeholder_calls"] == 0

    assert ("samplepkg.main.Service.start", "samplepkg.main.Service.finish") in call_edges
    assert ("samplepkg.main.Service.start", "samplepkg.helpers.Worker") in call_edges
    assert ("samplepkg.main.Service.start", "samplepkg.helpers.helper") in call_edges