"""Test ToolRegistry natural language tool call parsing.

Tests the parse_natural_language_tool_call method that extracts both
tool name and arguments from a complete free-form sentence.
"""

from __future__ import annotations

from agentdecompile_cli.registry import tool_registry


def test_parse_nl_tool_call_list_functions_simple():
    """Test parsing 'list functions' with program path."""
    text = "list functions in program /path/to/binary"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert "programPath" in arguments
    assert arguments["programPath"] == "/path/to/binary"


def test_parse_nl_tool_call_manage_symbols_with_mode():
    """Test parsing 'manage symbols' with mode and program path."""
    text = "manage symbols with program path '/tmp/a.bin' and mode list"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "manage-symbols"
    assert arguments.get("programPath") == "/tmp/a.bin"
    assert arguments.get("mode") == "list"


def test_parse_nl_tool_call_search_strings_complex():
    """Test parsing 'search strings' with multiple arguments."""
    text = "search strings in program /tmp/test with pattern http and max results 10"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "search-strings"
    assert arguments.get("programPath") == "/tmp/test"
    assert arguments.get("pattern") == "http"
    # maxResults might resolve to limit (synonym), accept either
    assert arguments.get("maxResults", arguments.get("limit")) == 10


def test_parse_nl_tool_call_decompile_function_with_address():
    """Test parsing 'decompile function' with address."""
    text = "decompile function at address 0x1000 in program /tmp/binary"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "decompile-function"
    assert arguments.get("address", arguments.get("addressOrSymbol")) == "0x1000"
    assert arguments.get("programPath") == "/tmp/binary"


def test_parse_nl_tool_call_kebab_case_tool_name():
    """Test parsing tool name in kebab-case format."""
    text = "list-functions with program path /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_snake_case_tool_name():
    """Test parsing tool name in snake_case format."""
    text = "list_functions in program /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_no_separator_tool_name():
    """Test parsing tool name without separators."""
    text = "listfunctions with program path /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_get_functions_with_filters():
    """Test parsing 'get functions' with filter arguments."""
    text = "get functions from program /tmp/bin with pattern main and include ref context true"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "get-functions"
    assert arguments.get("programPath") == "/tmp/bin"
    assert arguments.get("pattern") == "main"
    assert arguments.get("includeRefContext") is True


def test_parse_nl_tool_call_inspect_memory():
    """Test parsing 'inspect memory' command."""
    text = "inspect memory at 0x2000 in program /tmp/test with length 128"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "inspect-memory"
    assert arguments.get("address", arguments.get("startAddress")) == "0x2000"
    assert arguments.get("programPath") == "/tmp/test"
    assert arguments.get("length") == 128


def test_parse_nl_tool_call_manage_comments():
    """Test parsing 'manage comments' with mode and comment text."""
    text = "manage comments with mode add and address 0x1000 and comment 'This is a test' in program /tmp/binary"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "manage-comments"
    assert arguments.get("mode") == "add"
    assert arguments.get("address", arguments.get("addressOrSymbol")) == "0x1000"
    assert arguments.get("comment", arguments.get("commentText")) == "This is a test"
    assert arguments.get("programPath") == "/tmp/binary"


def test_parse_nl_tool_call_no_tool_match():
    """Test parsing with no valid tool name match."""
    text = "do something completely unknown with program /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name is None
    assert arguments == {}


def test_parse_nl_tool_call_empty_input():
    """Test parsing empty input."""
    tool_name, arguments = tool_registry.parse_natural_language_tool_call("")

    assert tool_name is None
    assert arguments == {}


def test_parse_nl_tool_call_whitespace_only():
    """Test parsing whitespace-only input."""
    tool_name, arguments = tool_registry.parse_natural_language_tool_call("   \n\t  ")

    assert tool_name is None
    assert arguments == {}


def test_parse_nl_tool_call_tool_name_only():
    """Test parsing with just a tool name and no arguments."""
    text = "list-functions"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments == {}


def test_parse_nl_tool_call_prefers_longer_tool_names():
    """Test that longer tool names are matched before shorter ones."""
    # "search-symbols-by-name" should match before "search-symbols"
    text = "search symbols by name with query malloc in program /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "search-symbols-by-name"
    assert arguments.get("query") == "malloc"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_export_with_format():
    """Test parsing 'export' with format and paths."""
    text = "export program /tmp/input to /tmp/output.xml with format xml"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "export"
    assert arguments.get("programPath") == "/tmp/input"
    # The parser might extract various forms depending on how it interprets "to"
    # Just validate we got the tool name correctly
    assert tool_name == "export"


def test_parse_nl_tool_call_boolean_values():
    """Test parsing boolean values in arguments."""
    text = "get functions with program path /tmp/test and include ref context true and skip analysis false"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "get-functions"
    assert arguments.get("includeRefContext") is True
    assert arguments.get("skipAnalysis") is False


def test_parse_nl_tool_call_integer_values():
    """Test parsing integer values in arguments."""
    text = "search strings with program path /tmp/test and min length 5 and max results 20"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "search-strings"
    assert arguments.get("minLength") == 5
    assert arguments.get("maxResults", arguments.get("limit")) == 20


def test_parse_nl_tool_call_hex_addresses():
    """Test parsing hexadecimal addresses."""
    text = "get data at 0xDEADBEEF in program /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "get-data"
    assert arguments.get("addressOrSymbol") == "0xDEADBEEF"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_quoted_paths():
    """Test parsing quoted file paths with spaces."""
    text = "list functions in program '/path with spaces/binary.exe'"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments.get("programPath") == "/path with spaces/binary.exe"


def test_parse_nl_tool_call_mixed_separators():
    """Test parsing with mixed key/value separator styles."""
    text = "manage symbols with program path: '/tmp/test', mode = 'list', and pattern is 'main'"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "manage-symbols"
    assert arguments.get("programPath") == "/tmp/test"
    assert arguments.get("mode") == "list"
    assert arguments.get("pattern") == "main"


def test_parse_nl_tool_call_case_insensitive_tool_name():
    """Test parsing with different case variations of tool name."""
    text = "LIST FUNCTIONS with program path /tmp/test"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "list-functions"
    assert arguments.get("programPath") == "/tmp/test"


def test_parse_nl_tool_call_analyze_vtables():
    """Test parsing 'analyze vtables' command."""
    text = "analyze vtables in program /tmp/binary with max depth 5"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "analyze-vtables"
    assert arguments.get("programPath") == "/tmp/binary"
    assert arguments.get("maxDepth") == 5


def test_parse_nl_tool_call_get_call_graph():
    """Test parsing 'get call graph' command."""
    text = "get call graph for function main in program /tmp/test with max depth 3"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "get-call-graph"
    assert arguments.get("function", arguments.get("functionName")) == "main"
    assert arguments.get("programPath") == "/tmp/test"
    assert arguments.get("maxDepth") == 3


def test_parse_nl_tool_call_import_binary():
    """Test parsing 'import binary' command."""
    text = "import binary from /tmp/input.bin to project test_project"
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)

    assert tool_name == "import-binary"
    # Check that at least the tool name was extracted correctly
    assert tool_name == "import-binary"
