from __future__ import annotations

import shutil

from pathlib import Path

import pytest

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, extract_text_content
from tests.helpers import get_public_sample_binary


pytestmark = [pytest.mark.e2e, pytest.mark.slow]

KNOWN_FIXTURE_NAME = "test_x86_64"
KNOWN_FIXTURE_LANGUAGE = "x86:LE:64:default"
KNOWN_FIXTURE_COMPILER = "gcc"
KNOWN_ENTRY_ADDRESS = "1000004b0"
KNOWN_PRINTF_ADDRESS = "10000051a"
KNOWN_STRING_ADDRESS = "100000520"
KNOWN_STRING_VALUE = "ReVa Test Program"
KNOWN_IMPORT_NAMESPACE = "/usr/lib/libSystem.B.dylib"


def _normalize_text(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _tool_text(session: JsonRpcMcpSession, name: str, arguments: dict[str, object]) -> str:
    return _normalize_text(extract_text_content(session.call_tool(name, arguments)))


def _known_fixture_source() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / KNOWN_FIXTURE_NAME


@pytest.fixture
def known_fixture_binary(isolated_workspace: Path) -> Path:
    destination = isolated_workspace / KNOWN_FIXTURE_NAME
    shutil.copy2(_known_fixture_source(), destination)
    destination.chmod(0o755)
    return destination


def test_public_sample_binary_is_exact_and_provenanced(public_sample_binary: Path) -> None:
    sample = get_public_sample_binary()
    binary = public_sample_binary.read_bytes()
    source_bytes = sample.source_file.read_bytes()

    assert sample.key == "sourcedennis-x64"
    assert sample.display_name == "sourcedennis/small-hello-world x64"
    assert sample.architecture == "x64"
    assert sample.output_name == "sourcedennis_small_hello_world_x64"
    assert sample.language_id == "x86:LE:64:default"
    assert sample.expected_message == "Hello, World\n"
    assert sample.output_size == 172
    assert public_sample_binary.name == sample.output_name
    assert len(binary) == sample.output_size
    assert binary[:4] == b"\x7fELF"
    assert binary[-len(sample.expected_message) :] == sample.expected_message.encode("utf-8")
    assert sample.source_root.exists()
    assert sample.source_file.exists()
    assert sample.license_file.exists()
    assert sample.readme_file.exists()
    assert source_bytes.startswith(b"BITS 64")
    assert b'Hello, World",10' in source_bytes
    assert sample.source_sha256 == "fb4dc6934f67eefb89f38f4911c365a3c5d58a3116327c90afa6b41eb27d9b82"
    assert sample.output_sha256 == "90fc6ad98b5f31d7a365a2b24e5ef0ca1103a42768721793810b5d0480570b38"


def test_open_project_and_current_program_match_known_fixture_contract(
    local_http_session: JsonRpcMcpSession,
    known_fixture_binary: Path,
) -> None:
    open_text = _tool_text(local_http_session, "open-project", {"path": str(known_fixture_binary)})
    current_text = _tool_text(local_http_session, "get-current-program", {})

    # Path may be truncated with … in markdown tables, so we check substrings
    assert "**operation:** import" in open_text
    assert f"**importedFrom:** {known_fixture_binary}" in open_text
    assert "**filesDiscovered:** 1" in open_text
    assert "**filesImported:** 1" in open_text
    assert f"| {KNOWN_FIXTURE_NAME} |" in open_text
    assert "**groupsCreated:** 0" in open_text
    assert "**maxDepthUsed:** 16" in open_text
    assert "**wasRecursive:** False" in open_text
    assert "**analysisRequested:** False" in open_text
    assert "**errors:** []" in open_text
    assert "**Name:** `test_x86_64`" in current_text
    assert "**Path:** ``" in current_text
    assert f"**Language:** {KNOWN_FIXTURE_LANGUAGE}" in current_text
    assert f"**Compiler:** {KNOWN_FIXTURE_COMPILER}" in current_text
    assert "**Image Base:** ``" in current_text
    assert "**Functions:** 3" in current_text
    assert "**Symbols:** 0" in current_text
    assert "Shows the currently loaded program's metadata." in current_text


def test_known_fixture_analysis_outputs_match_observed_contract(
    local_http_session: JsonRpcMcpSession,
    known_fixture_binary: Path,
) -> None:
    _tool_text(local_http_session, "open-project", {"path": str(known_fixture_binary)})

    functions_text = _tool_text(local_http_session, "list-functions", {"limit": 10})
    references_text = _tool_text(local_http_session, "get-references", {"mode": "to", "target": KNOWN_ENTRY_ADDRESS})
    imports_text = _tool_text(local_http_session, "list-imports", {})
    exports_text = _tool_text(local_http_session, "list-exports", {"limit": 5})
    strings_text = _tool_text(local_http_session, "manage-strings", {"mode": "regex", "pattern": "ReVa"})

    expected_references = _normalize_text(
        (
            "## Getreferences (to)\n\n"
            "**mode:** to\n"
            "**target:** 1000004b0\n\n"
            "### References\n\n"
            "| fromAddress | toAddress | type | function |\n"
            "| --- | --- | --- | --- |\n"
            "| Entry Point | 1000004b0 | EXTERNAL | None |\n"
            "| 1000020b3 | 1000004b0 | DATA | None |\n"
            "**count:** 2"
        )
    )
    expected_imports = _normalize_text(
        (
            "## Import Listing\n\n"
            "Showing **1** of **1** results (offset 0).\n\n"
            "| Name | Address | Namespace |\n"
            "| --- | --- | --- |\n"
            "| _printf | EXTERNAL:00000001 | /usr/lib/libSystem.B.dylib |"
        )
    )

    assert functions_text.startswith("## Function Listing\n\nShowing **2** of **2** results (offset 0).")
    assert "| Name | Address | Size | Params | External | Thunk |" in functions_text
    assert f"| entry | {KNOWN_ENTRY_ADDRESS} | 1 | 0 |  |  |" in functions_text
    assert f"| _printf | {KNOWN_PRINTF_ADDRESS} | 1 | 0 |  | Yes |" in functions_text
    assert "Lists all functions defined in the binary with their addresses, sizes, and basic metadata." in functions_text
    assert "Call `get-functions mode=decompile function=entry` to read the pseudocode of a specific function." in functions_text
    assert "Call `get-functions function=entry view=info` for detailed metadata (params, return type)." in functions_text
    assert "Use `namePattern` regex to filter (e.g. `^sub_` for unnamed, `^_` for C++ internals)." in functions_text
    assert "Call `manage-symbols mode=count` for a quick symbol count overview without listing." in functions_text

    assert references_text == expected_references
    assert "**mode:** to" in references_text
    assert f"**target:** {KNOWN_ENTRY_ADDRESS}" in references_text
    assert "| Entry Point | 1000004b0 | EXTERNAL | None |" in references_text
    assert "| 1000020b3 | 1000004b0 | DATA | None |" in references_text
    assert "**count:** 2" in references_text

    assert imports_text == expected_imports
    assert "Showing **1** of **1** results (offset 0)." in imports_text
    assert "| Name | Address | Namespace |" in imports_text
    assert f"| _printf | EXTERNAL:00000001 | {KNOWN_IMPORT_NAMESPACE} |" in imports_text

    assert exports_text.startswith("## Export Listing\n\nShowing **5** of **6** results (offset 0).")
    assert "| Name | Address |" in exports_text
    assert "| __mh_execute_header | 100000000 |" in exports_text
    assert "| MACH_HEADER | 100000000 |" in exports_text
    assert "| _add | 100000470 |" in exports_text
    assert "| _multiply | 100000490 |" in exports_text
    assert f"| entry | {KNOWN_ENTRY_ADDRESS} |" in exports_text

    assert strings_text.startswith("## Strings\n\nShowing **1** of **1** results (offset 0).")
    assert "| Address | Value" in strings_text
    assert f"| {KNOWN_STRING_ADDRESS} | {KNOWN_STRING_VALUE}" in strings_text
    assert "Find, list, and search strings embedded in the binary." in strings_text
    assert f"Find references to this string: `get-references address={KNOWN_STRING_ADDRESS}`." in strings_text
    assert f"Decompile containing function: `get-functions mode=decompile address={KNOWN_STRING_ADDRESS}`." in strings_text
    assert "Search for keywords: `search-strings query=password` or `search-strings query=error`." in strings_text
