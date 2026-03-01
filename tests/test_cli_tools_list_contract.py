from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


@dataclass(frozen=True)
class DocumentedTool:
    name: str
    params: tuple[str, ...]


def _normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z]", "", value.lower().strip())


def _server_url() -> str:
    return os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL", "http://127.0.0.1:8080")


def _run_cli(server_url: str, tool_name: str, payload: dict[str, object], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        "-m",
        "agentdecompile_cli.cli",
        "--server-url",
        server_url,
        "tool",
        tool_name,
        json.dumps(payload),
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _probe_server_or_skip() -> str:
    server_url = _server_url()
    probe = _run_cli(server_url, "list-project-files", {})
    combined = f"{probe.stdout}\n{probe.stderr}"

    if "Cannot connect to AgentDecompile server" in combined:
        pytest.skip(f"MCP server unavailable at {server_url}")

    if probe.returncode not in (0, 1):
        pytest.skip(f"MCP server probe failed with unexpected exit code {probe.returncode} at {server_url}")

    return server_url


def _extract_block(text: str, start_header_regex: str, end_header_regex: str | None = None) -> str:
    start_match = re.search(start_header_regex, text, flags=re.MULTILINE)
    if start_match is None:
        return ""

    start_index = start_match.end()
    if end_header_regex is None:
        return text[start_index:]

    end_match = re.search(end_header_regex, text[start_index:], flags=re.MULTILINE)
    if end_match is None:
        return text[start_index:]
    return text[start_index : start_index + end_match.start()]


def _parse_canonical_tools_from_tools_list(tools_list_text: str) -> list[DocumentedTool]:
    canonical_block = _extract_block(
        tools_list_text,
        r"^## Canonical Tools \(\d+\)\s*$",
        r"^## (?:Legacy Tool Name Forwards|Vendor Alias Forwards)\s*$",
    )

    if not canonical_block.strip():
        return []

    split_parts = re.split(r"^### `([^`]+)`\s*$", canonical_block, flags=re.MULTILINE)
    tools: list[DocumentedTool] = []

    for idx in range(1, len(split_parts), 2):
        tool_name = split_parts[idx].strip()
        body = split_parts[idx + 1]

        params_block_match = re.search(
            r"\*\*Parameters\*\*:\n(.*?)(?:\n\*\*Overloads\*\*|\n\*\*Synonyms\*\*|\n\*\*Examples\*\*|\Z)",
            body,
            flags=re.DOTALL,
        )
        params: list[str] = []
        if params_block_match is not None:
            for line in params_block_match.group(1).splitlines():
                param_match = re.match(r"^- `([^`]+)` \([^)]+\):", line.strip())
                if param_match is None:
                    continue
                param = param_match.group(1).strip()
                if param.lower() == "none":
                    continue
                params.append(param)

        tools.append(DocumentedTool(name=tool_name, params=tuple(params)))

    return tools


def _parse_legacy_forward_names_from_tools_list(tools_list_text: str) -> list[str]:
    legacy_block = _extract_block(
        tools_list_text,
        r"^## (?:Legacy Tool Name Forwards|Vendor Alias Forwards)\s*$",
        r"^## Parameter Normalization Notes",
    )
    if not legacy_block.strip():
        return []

    names = re.findall(r"^### `([^`]+)`(?: \(forwards to `[^`]+`\))?\s*$", legacy_block, flags=re.MULTILINE)
    return [n.strip() for n in names if n.strip()]


def _default_mode_for_tool(tool_name: str) -> str:
    tool_norm: str = _normalize_identifier(tool_name)
    mode_map: dict[str, str] = {
        "analyzedataflow": "backward",
        "analyzevtables": "analyze",
        "getcallgraph": "graph",
        "inspectmemory": "bytes",
        "managebookmarks": "list",
        "managecomments": "list",
        "managedatatypes": "list",
        "managefiles": "list",
        "managefunction": "list",
        "managefunctiontags": "list",
        "managestrings": "list",
        "managestructures": "list",
        "managesymbols": "symbols",
        "searchconstants": "value",
        "syncsharedproject": "pull",
    }
    return mode_map.get(tool_norm, "list")


def _example_param_value(tool_name: str, param_name: str) -> object:
    norm = _normalize_identifier(param_name)
    tool_norm = _normalize_identifier(tool_name)

    path_parameter_aliases_set: set[str] = {
        "programpath",
        "binaryname",
        "binarypath",
        "destinationfolder",
        "destinationpath",
        "filepath",
        "folderpath",
        "newpath",
        "path",
        "sourcepath",
        "targetprogram",
    }
    if norm in path_parameter_aliases_set:
        return "/__agentdecompile__/nonexistent.bin"

    if norm in {
        "outputpath",
    }:
        return "/tmp/agentdecompile-contract-out.txt"

    if norm in {
        "address",
        "addressorsymbol",
        "functionaddress",
        "startaddress",
        "variableaddress",
        "vtableaddress",
    }:
        return "0x401000"

    if norm in {
        "functionidentifier",
        "function",
        "functionnameoraddress",
        "identifier",
        "nameoraddress",
        "target",
    }:
        return "main"

    if norm in {
        "analyzers",
        "bookmarks",
        "categories",
        "comments",
        "commenttypes",
        "fields",
        "functionaddresses",
        "functions",
        "gdts",
        "identifiers",
        "propagateprogrampaths",
        "tags",
        "targetprogrampaths",
    }:
        return []

    if norm in {
        "datatypemappings",
        "programoptions",
        "variablemappings",
    }:
        return {}

    if norm in {
        "action",
        "command",
        "mode",
        "op",
        "operation",
    }:
        return _default_mode_for_tool(tool_name)

    if norm == "direction":
        if tool_norm == "analyzedataflow":
            return "backward"
        return "to"

    if norm == "format":
        if tool_norm == "export":
            return "sarif"
        if tool_norm in {
            "getdata",
            "inspectmemory",
        }:
            return "hex"
        return "json"

    if norm == "view":
        if tool_norm == "getfunctions":
            return "info"
        if tool_norm == "getdata":
            return "hex"
        return "list"

    if norm in {
        "suggestiontype",
    }:
        return "function_names"

    if norm in {
        "code",
    }:
        return "print('contract-test')"

    if norm in {
        "analyzeafterimport",
        "casesensitive",
        "clearexisting",
        "createifnotexists",
        "demangleall",
        "dryrun",
        "enableversioncontrol",
        "filterdefaultnames",
        "force",
        "hastags",
        "includebuiltin",
        "includecallees",
        "includecallers",
        "includecomments",
        "includecontext",
        "includedatarefs",
        "includeexternal",
        "includeflow",
        "includeincomingreferences",
        "includerefcontext",
        "includereferencecontext",
        "includereferencingfunctions",
        "includesmallvalues",
        "keepcheckedout",
        "mirrorfs",
        "packed",
        "propagate",
        "propagatecomments",
        "propagatenames",
        "propagatetags",
        "recursive",
        "removeall",
        "setasprimary",
        "stripallcontainerpath",
        "stripleadingpath",
        "untagged",
        "verbose",
    }:
        if norm in {
            "force",
            "removeall",
        }:
            return False
        if norm in {
            "dryrun",
        }:
            return True
        return True

    if norm in {
        "batchsize",
        "contextlines",
        "count",
        "depth",
        "length",
        "limit",
        "linenumber",
        "maxcallers",
        "maxcount",
        "maxdepth",
        "maxentries",
        "maxinstructions",
        "maxreferencers",
        "maxresults",
        "maxvalue",
        "maxworkers",
        "minsimilarity",
        "minvalue",
        "offset",
        "propagatemaxcandidates",
        "propagatemaxinstructions",
        "serverport",
        "size",
        "startindex",
        "topn",
        "value",
    }:
        if norm == "minsimilarity":
            return 0
        return 1

    if norm in {
        "languageid",
    }:
        return "x86:LE:64:default"

    if norm in {
        "compilerspecid",
    }:
        return "gcc"

    if norm in {
        "processor",
        "language",
    }:
        return "x86"

    if norm in {
        "endian",
    }:
        return "little"

    if norm in {
        "archive",
        "archivename",
        "category",
        "categorypath",
        "comment",
        "datatype",
        "datatypestring",
        "description",
        "filter",
        "importname",
        "labelname",
        "libraryfilter",
        "libraryname",
        "message",
        "name",
        "newname",
        "newtype",
        "oldname",
        "prototype",
        "query",
        "searchstring",
        "typename",
        "variablename",
    }:
        return "test"

    return "test"


def _payload_for_tool(tool: DocumentedTool) -> dict[str, object]:
    payload: dict[str, object] = {}
    for param in tool.params:
        payload[param] = _example_param_value(tool.name, param)

    # Safety and practical defaults for destructive or mode-dependent tools.
    payload.setdefault("confirm", False)
    if _normalize_identifier(tool.name) == "deleteprojectbinary":
        payload.setdefault("programPath", "/__agentdecompile__/nonexistent.bin")
        payload["confirm"] = False

    return payload


def _combined_output(proc: subprocess.CompletedProcess[str]) -> str:
    return f"{proc.stdout}\n{proc.stderr}".strip()


def _is_contract_failure_output(output: str) -> bool:
    lowered: str = output.lower()
    hard_fail_markers: tuple[str, ...] = (
        "arguments must be a json object",
        "invalid json arguments",
        "no such option",
        "unknown tool",
    )
    return any(marker in lowered for marker in hard_fail_markers)


def test_tools_list_documented_canonical_tools_and_params_cli_contract() -> None:
    server_url: str = _probe_server_or_skip()

    repo_root: Path = Path(__file__).resolve().parent.parent
    tools_list_path: Path = repo_root / "TOOLS_LIST.md"
    tools_list_text: str = tools_list_path.read_text(encoding="utf-8")

    documented_tools: list[DocumentedTool] = _parse_canonical_tools_from_tools_list(tools_list_text)
    assert documented_tools, "Expected canonical tools in TOOLS_LIST.md"

    failures: list[str] = []

    for documented_tool in documented_tools:
        payload: dict[str, object] = _payload_for_tool(documented_tool)
        proc: subprocess.CompletedProcess[str] = _run_cli(server_url, documented_tool.name, payload)
        output: str = _combined_output(proc)

        if proc.returncode not in (0, 1):
            failures.append(f"{documented_tool.name}: unexpected exit code {proc.returncode}\n{output}")
            continue

        if _is_contract_failure_output(output):
            failures.append(f"{documented_tool.name}: contract marker failure\n{output}")

    assert not failures, "\n\n".join(failures)


def test_tools_list_documented_legacy_forward_names_cli_contract() -> None:
    server_url: str = _probe_server_or_skip()

    repo_root: Path = Path(__file__).resolve().parent.parent
    tools_list_path: Path = repo_root / "TOOLS_LIST.md"
    tools_list_text: str = tools_list_path.read_text(encoding="utf-8")

    legacy_forward_names: list[str] = _parse_legacy_forward_names_from_tools_list(tools_list_text)
    assert legacy_forward_names, "Expected legacy tool-name forwards in TOOLS_LIST.md"

    failures: list[str] = []

    for legacy_name in legacy_forward_names:
        proc: subprocess.CompletedProcess[str] = _run_cli(server_url, legacy_name, {})
        output: str = _combined_output(proc)

        if proc.returncode not in (0, 1):
            failures.append(f"{legacy_name}: unexpected exit code {proc.returncode}\n{output}")
            continue

        if "unknown tool" in output.lower():
            failures.append(f"{legacy_name}: unknown tool reported\n{output}")

    assert not failures, "\n\n".join(failures)
