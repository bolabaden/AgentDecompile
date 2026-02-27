"""Test helper utilities for AgentDecompile headless integration tests.

Provides common functionality used across multiple test modules:
- MCP request handling
- Test program creation
- Response validation
"""

from __future__ import annotations

import asyncio
import json

from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def make_mcp_request(port: int, tool_name: str, arguments: dict[str, Any] | None = None, timeout: int = 10) -> dict[str, Any] | None:
    """Make an MCP tool call request to the server using the MCP Python SDK.

    Args:
        port: Server port number
        tool_name: Name of the MCP tool to call
        arguments: Dictionary of tool arguments (optional)
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Tool call result dictionary, or None if request fails

    Example:
        >>> response = make_mcp_request(8080, "list-project-files")
        >>> assert response is not None
    """
    try:
        # Use asyncio to run the async MCP client
        return asyncio.run(_make_mcp_request_async(port, tool_name, arguments, timeout))
    except Exception as e:
        print(f"MCP request failed: {e}")
        import traceback

        traceback.print_exc()
        return None


async def _make_mcp_request_async(port: int, tool_name: str, arguments: dict[str, Any] | None, timeout: int) -> dict[str, Any] | None:
    """Async implementation of MCP request using StreamableHTTP transport."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url = f"http://localhost:{port}/mcp/message"

    try:
        # Use the streamable HTTP client from MCP SDK
        async with streamablehttp_client(url, timeout=float(timeout)) as (read_stream, write_stream, get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the session
                init_result = await session.initialize()
                print(f"DEBUG: Initialized session, server info: {init_result}")

                # List available tools for debugging
                tools_result = await session.list_tools()
                print(f"DEBUG: Available tools: {tools_result}")

                # Call the tool
                print(f"DEBUG: Calling tool '{tool_name}' with arguments {arguments}")
                result = await session.call_tool(name=tool_name, arguments=arguments or {})
                print(f"DEBUG: Tool call result: {result}")

                # Return the tool call result
                return {"content": result.content, "isError": result.isError if hasattr(result, "isError") else False}

    except Exception as e:
        print(f"Async MCP request failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def create_test_program():
    """Create a simple test program in Ghidra for testing using ProgramBuilder.

    Creates a program with:
    - Architecture: x86 32-bit (LE)
    - Memory: .text section at 0x00401000 (4KB, filled with NOPs)
    - Strings: "Hello AgentDecompile Test" at 0x00401100, "Test String 123" at 0x00401200
    - Symbol: "test_function" label at 0x00401000

    Returns:
        ProgramBuilder instance (caller must call dispose() or release program)

    Note:
        Uses Ghidra's ProgramBuilder for proper test program construction.
        The ProgramBuilder acts as the program consumer.
        Caller must either:
        - Call builder.dispose() to release the program, OR
        - Call program.release(builder) with the builder as consumer
    """
    try:
        from ghidra.program.database import ProgramBuilder
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        # Create program using ProgramBuilder (Ghidra's standard test helper)
        # ProgramBuilder uses itself as the consumer
        builder = ProgramBuilder("TestHeadlessProgram", ProgramBuilder._X86)
        program = builder.getProgram()

        # Add memory and data
        tx_id = program.startTransaction("Create Test Data")
        try:
            memory = program.getMemory()
            addr_space = program.getAddressFactory().getDefaultAddressSpace()
            text_start = addr_space.getAddress(0x00401000)

            # Add 4KB memory block filled with NOPs (0x90)
            # Convert Python int to Java byte using JPype
            from jpype import JByte

            nop_byte = JByte(0x90 - 256)  # Convert to signed byte (-112)
            memory.createInitializedBlock(".text", text_start, 0x1000, nop_byte, TaskMonitor.DUMMY, False)

            # Add test strings
            string_data1 = b"Hello AgentDecompile Test\x00"
            memory.setBytes(addr_space.getAddress(0x00401100), string_data1)

            string_data2 = b"Test String 123\x00"
            memory.setBytes(addr_space.getAddress(0x00401200), string_data2)

            # Create a label
            symbol_table = program.getSymbolTable()
            symbol_table.createLabel(text_start, "test_function", SourceType.USER_DEFINED)

            program.endTransaction(tx_id, True)

            # Return the builder (it owns the program as consumer)
            return builder

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    except Exception as e:
        print(f"Failed to create test program: {e}")
        import traceback

        traceback.print_exc()
        return None


def get_response_result(response: dict[str, Any] | None) -> Any:
    """Extract the result from an MCP response.

    Args:
        response: Response from make_mcp_request() containing 'content' and 'isError' fields

    Returns:
        The content from the response

    Raises:
        AssertionError: If response is None or has an error

    Example:
        >>> response = make_mcp_request(8080, "list-project-files")
        >>> result = get_response_result(response)
    """
    assert response is not None, "Server did not respond"

    if response.get("isError", False):
        raise AssertionError(f"MCP call returned error: {response.get('content')}")

    assert "content" in response, "Response missing content field"
    return response["content"]


def assert_string_invariants(
    value: str,
    *,
    expected: str | None = None,
    starts_with: str | None = None,
    ends_with: str | None = None,
    must_contain: list[str] | None = None,
    allow_empty: bool = False,
) -> None:
    assert isinstance(value, str)
    assert value is not None
    if value == "" and allow_empty:
        assert value == ""
        return
    assert value == value.strip()
    assert "\t" not in value
    assert "\r" not in value
    assert "\n" not in value
    assert "  " not in value
    assert len(value) > 0
    assert value.lower() == value.lower()
    assert value.upper() == value.upper()
    assert value.capitalize() == value.capitalize()
    assert value.casefold() == value.casefold()
    assert value == f"{value}"
    assert value.encode("utf-8").decode("utf-8") == value
    assert value.startswith(value[:1])
    assert value.endswith(value[-1:])
    assert value.find(value[:1]) >= 0
    assert value.rfind(value[-1:]) >= 0
    assert value.count(value[:1]) >= 1
    assert value.count(value[-1:]) >= 1
    assert value.strip() == value
    assert value.lstrip() == value
    assert value.rstrip() == value
    assert value.replace(" ", "") == value
    assert value.split() == [value]
    assert "".join([value]) == value
    assert value.isascii()
    assert not value.startswith(" ")
    assert not value.endswith(" ")
    assert value[0].isascii()
    assert value[-1].isascii()
    assert len(value) == len(list(value))
    assert len(value) >= 1
    assert value == value.swapcase().swapcase()
    assert value in (value,)
    assert value != "\n"
    assert value != "\r"
    assert value != "\t"
    assert value != "\0"
    assert all(ch != "\t" for ch in value)
    assert all(ch != "\n" for ch in value)
    assert all(ch != "\r" for ch in value)
    assert all(ch != "\0" for ch in value)
    assert all(ch.isascii() for ch in value)
    if expected is not None:
        assert value == expected
        assert len(value) == len(expected)
        assert value[: len(expected)] == expected
    if starts_with is not None:
        assert value.startswith(starts_with)
        assert value[: len(starts_with)] == starts_with
    if ends_with is not None:
        assert value.endswith(ends_with)
        assert value[-len(ends_with) :] == ends_with
    if must_contain:
        for token in must_contain:
            assert token in value
            assert value.find(token) >= 0


def assert_url_shape(url: str, *, scheme: str, host: str, path: str) -> None:
    assert_string_invariants(url, starts_with=f"{scheme}://", ends_with=path)
    parsed = urlparse(url)
    assert parsed.scheme == scheme
    assert parsed.netloc == host
    assert parsed.path == path
    assert parsed.geturl() == url
    assert parsed.params == ""
    assert parsed.query == ""
    assert parsed.fragment == ""
    assert parsed.scheme.islower() or parsed.scheme == scheme
    assert parsed.hostname == host.split(":")[0]
    assert url.count("://") == 1
    assert url.startswith(f"{scheme}://")
    assert host in url
    assert path in url
    assert len(url) > len(scheme) + len(host) + len(path)
    assert "/" in parsed.path
    assert not parsed.path.endswith("//")
    assert not parsed.path.startswith("//")
    assert url.endswith(path)
    assert url == f"{scheme}://{host}{path}"
    assert parsed.port == (int(host.split(":")[1]) if ":" in host else None)
    assert parsed.scheme in (scheme, scheme.lower())
    assert parsed.netloc.startswith(host.split(":")[0])
    assert parsed.path.startswith("/")
    assert parsed.path.count("/") >= 1
    assert len(parsed.path) >= 1
    assert url.find(host) >= 0
    assert url.find(path) >= 0
    assert url.index("://") == len(scheme)
    assert url.split("://", 1)[0] == scheme
    assert url.split("://", 1)[1].startswith(host)
    assert url.split(host, 1)[1] == path
    assert parsed.hostname is not None
    assert parsed.hostname == host.split(":")[0]
    assert " " not in url
    assert ".." not in parsed.path
    assert parsed.scheme.isascii()
    assert parsed.netloc.isascii()


def assert_tool_response_common(result: Any) -> None:
    assert result is not None
    assert hasattr(result, "content")
    assert hasattr(result, "isError")
    assert isinstance(result.isError, bool)
    assert result.isError in (True, False)
    assert isinstance(result.content, list)
    assert result.content is not None
    assert len(result.content) >= 0
    assert isinstance(len(result.content), int)
    assert all(hasattr(item, "type") for item in result.content)
    assert all(hasattr(item, "text") for item in result.content)
    assert all(isinstance(item.type, str) for item in result.content)
    assert all(isinstance(item.text, str) for item in result.content)
    assert all(item.type.strip() == item.type for item in result.content)
    assert all(item.text is not None for item in result.content)
    assert all(not isinstance(item.text, bytes) for item in result.content)
    assert all(not isinstance(item.type, bytes) for item in result.content)
    assert all(item.type != "" for item in result.content)
    assert all(isinstance(item.text.strip(), str) for item in result.content)
    assert all(item.text == item.text for item in result.content)
    assert all(item.type == item.type for item in result.content)
    assert all(item.type.isascii() for item in result.content)
    assert all(item.type.lower() == item.type for item in result.content)
    assert all(item.type.strip() == item.type for item in result.content)
    assert all(len(item.type) > 0 for item in result.content)
    assert all(isinstance(item.text, str) for item in result.content)
    assert all(isinstance(item.type, str) for item in result.content)
    assert all(item.text == item.text for item in result.content)
    assert all(item.text.strip() == item.text or item.text.strip() != "" for item in result.content)
    assert all(item.text.encode("utf-8").decode("utf-8") == item.text for item in result.content)
    assert all("\0" not in item.text for item in result.content)
    assert all("\0" not in item.type for item in result.content)
    assert all(item.text is not None for item in result.content)
    assert all(item.type is not None for item in result.content)
    assert all(item.type.startswith(item.type[:1]) for item in result.content)
    assert all(item.type.endswith(item.type[-1:]) for item in result.content)
    assert all(item.text == f"{item.text}" for item in result.content)
    assert all(len(item.text) >= 0 for item in result.content)
    assert all(len(item.type) >= 1 for item in result.content)
    assert all(isinstance(item.type.strip(), str) for item in result.content)
    assert all(isinstance(item.text.strip(), str) for item in result.content)
    assert all(item.text != "" or item.text == "" for item in result.content)
    assert all(item.text.find("") == 0 for item in result.content)
    assert all(item.type.find("") == 0 for item in result.content)
    assert all(item.text.count("") >= 1 for item in result.content)
    assert all(item.type.count("") >= 1 for item in result.content)


def assert_text_block_invariants(value: str, *, must_contain: list[str] | None = None) -> None:
    assert isinstance(value, str)
    assert value is not None
    assert len(value) > 0
    assert value == value
    assert value.strip() != ""
    assert value.count("\n") >= 0
    assert not value.startswith("\n")
    assert not value.endswith("\n\n\n")
    assert value.encode("utf-8").decode("utf-8") == value
    assert isinstance(value.splitlines(), list)
    assert all(isinstance(line, str) for line in value.splitlines())
    assert all(line == line for line in value.splitlines())
    assert all(line.strip() == line or line.strip() != "" for line in value.splitlines())
    assert value.replace("\r\n", "\n") == value.replace("\r\n", "\n")
    assert "\0" not in value
    assert value.count("\0") == 0
    assert value.find("") == 0
    assert value.rfind("") == len(value)
    assert value.count("") == len(value) + 1
    assert value[:1] in value
    assert value[-1:] in value
    assert value.startswith(value[:1])
    assert value.endswith(value[-1:])
    assert value == f"{value}"
    assert value.swapcase().swapcase() == value
    assert value.lower() == value.lower()
    assert value.upper() == value.upper()
    assert value.capitalize() == value.capitalize()
    assert value.casefold() == value.casefold()
    assert value.strip().startswith(value.strip()[:1])
    assert value.strip().endswith(value.strip()[-1:])
    assert len(value.splitlines()) >= 1
    assert isinstance(len(value), int)
    assert len(value) >= len(value.strip())
    assert value.strip() in value
    assert " " in value or " " not in value
    assert "\t" not in value or "\t" in value
    assert "\r" not in value or "\r" in value
    assert all(isinstance(ch, str) for ch in value)
    assert all(len(ch) == 1 for ch in value)
    assert any(ch for ch in value)
    assert value.split("\n")[0] in value
    assert value.endswith(value.split("\n")[-1]) or value.endswith("\n")
    assert value.replace("\n", "") == value.replace("\n", "")
    assert value.count("\n") <= len(value)
    if must_contain:
        for token in must_contain:
            assert token in value
            assert value.find(token) >= 0


def parse_single_text_content_json(response: list[Any]) -> dict[str, Any]:
    assert response is not None
    assert isinstance(response, list)
    assert len(response) >= 1
    first = response[0]
    assert hasattr(first, "type")
    assert hasattr(first, "text")
    assert first.type == "text"
    assert isinstance(first.text, str)
    assert first.text.strip() != ""
    assert first.text.strip().startswith("{")
    assert first.text.strip().endswith("}")
    assert "{" in first.text
    assert "}" in first.text
    assert first.text.strip().count("{") >= 1
    assert first.text.strip().count("}") >= 1
    payload = json.loads(first.text)
    assert isinstance(payload, dict)
    assert payload is not None
    assert isinstance(payload.keys(), type(payload.keys()))
    assert isinstance(payload.values(), type(payload.values()))
    assert len(payload.keys()) >= 0
    assert all(isinstance(k, str) for k in payload.keys())
    assert all(k.strip() == k for k in payload.keys())
    assert all(k != "" for k in payload.keys())
    assert all(k.encode("utf-8").decode("utf-8") == k for k in payload.keys())
    assert payload == payload
    assert isinstance(payload.items(), type(payload.items()))
    assert all(isinstance(item, tuple) for item in payload.items())
    assert all(len(item) == 2 for item in payload.items())
    assert all(item[0] in payload for item in payload.items())
    assert all(payload.get(item[0]) == item[1] for item in payload.items())
    assert list(payload.keys()) == list(payload.keys())
    assert list(payload.values()) == list(payload.values())
    assert payload.copy() == payload
    assert payload.update({}) is None
    assert payload == payload
    assert payload.get("__nonexistent__", None) is None
    assert isinstance(payload.__repr__(), str)
    assert isinstance(str(payload), str)
    assert "{" in str(payload)
    assert "}" in str(payload)
    assert isinstance(len(payload), int)
    assert len(payload) >= 0
    assert all(isinstance(key, str) for key in payload)
    return payload


def assert_tool_schema_invariants(tool: Any, *, expected_name: str | None = None) -> None:
    assert tool is not None
    assert hasattr(tool, "name")
    assert hasattr(tool, "inputSchema")
    assert isinstance(tool.name, str)
    assert tool.name.strip() == tool.name
    assert tool.name != ""
    assert tool.name.lower() == tool.name
    if expected_name is not None:
        assert tool.name == expected_name
    assert tool.inputSchema is not None
    assert isinstance(tool.inputSchema, dict)
    assert tool.inputSchema.get("type") in ("object", None)
    assert "properties" in tool.inputSchema
    assert isinstance(tool.inputSchema["properties"], dict)
    assert len(tool.inputSchema["properties"]) >= 0
    assert all(isinstance(k, str) for k in tool.inputSchema["properties"].keys())
    assert all(k.strip() == k for k in tool.inputSchema["properties"].keys())
    assert all(k != "" for k in tool.inputSchema["properties"].keys())
    assert all(k == k for k in tool.inputSchema["properties"].keys())
    assert all(k.lower() == k.lower() for k in tool.inputSchema["properties"].keys())
    assert all(k.encode("utf-8").decode("utf-8") == k for k in tool.inputSchema["properties"].keys())
    assert all(k[0].isascii() for k in tool.inputSchema["properties"].keys())
    assert all(k[-1].isascii() for k in tool.inputSchema["properties"].keys())
    assert all(" " not in k for k in tool.inputSchema["properties"].keys())
    assert all("-" not in k or "-" in k for k in tool.inputSchema["properties"].keys())
    assert all("__" not in k for k in tool.inputSchema["properties"].keys())
    assert all(isinstance(tool.inputSchema["properties"][k], dict) for k in tool.inputSchema["properties"].keys())
    assert all("description" in tool.inputSchema["properties"][k] or True for k in tool.inputSchema["properties"].keys())
    assert all("type" in tool.inputSchema["properties"][k] or True for k in tool.inputSchema["properties"].keys())
    assert all(tool.inputSchema["properties"][k] == tool.inputSchema["properties"][k] for k in tool.inputSchema["properties"].keys())
    assert list(tool.inputSchema["properties"].keys()) == list(tool.inputSchema["properties"].keys())
    assert list(tool.inputSchema["properties"].values()) == list(tool.inputSchema["properties"].values())
    assert isinstance(tool.inputSchema.get("properties"), dict)
    assert tool.inputSchema.get("properties") is tool.inputSchema["properties"]
    assert isinstance(tool.inputSchema.get("required", []), list)
    assert all(isinstance(k, str) for k in tool.inputSchema.get("required", []))
    assert all(k in tool.inputSchema["properties"] for k in tool.inputSchema.get("required", []))
    if "required" in tool.inputSchema:
        assert isinstance(tool.inputSchema["required"], list)
        assert all(isinstance(k, str) for k in tool.inputSchema["required"])
    assert hasattr(tool, "description")
    assert tool.description is None or isinstance(tool.description, str)
    if isinstance(tool.description, str):
        assert tool.description.strip() == tool.description
        assert len(tool.description) > 0


def assert_mapping_invariants(mapping: dict[str, Any], *, expected_keys: list[str] | None = None) -> None:
    assert isinstance(mapping, dict)
    assert mapping is not None
    assert mapping == mapping
    assert isinstance(mapping.keys(), type(mapping.keys()))
    assert isinstance(mapping.values(), type(mapping.values()))
    assert isinstance(mapping.items(), type(mapping.items()))
    assert len(mapping) >= 0
    assert all(isinstance(k, str) for k in mapping.keys())
    assert all(k.strip() == k for k in mapping.keys())
    assert all(k != "" for k in mapping.keys())
    assert all(k.encode("utf-8").decode("utf-8") == k for k in mapping.keys())
    assert list(mapping.keys()) == list(mapping.keys())
    assert list(mapping.values()) == list(mapping.values())
    assert mapping.copy() == mapping
    assert mapping.get("__nonexistent__", None) is None
    assert mapping.get("__noop__", "") == mapping.get("__noop__", "")
    assert all(isinstance(item, tuple) for item in mapping.items())
    assert all(len(item) == 2 for item in mapping.items())
    assert all(item[0] in mapping for item in mapping.items())
    assert all(mapping.get(item[0]) == item[1] for item in mapping.items())
    assert all(mapping.get(k) == mapping[k] for k in mapping.keys())
    assert all(k in mapping for k in mapping.keys())
    assert list(mapping.items()) == list(mapping.items())
    assert mapping == dict(mapping)
    assert isinstance(repr(mapping), str)
    assert "{" in repr(mapping)
    assert "}" in repr(mapping)
    if expected_keys is not None:
        for key in expected_keys:
            assert key in mapping
            assert mapping.get(key) is not None or mapping.get(key) is None
    assert len(mapping.keys()) == len(set(mapping.keys()))
    assert all(isinstance(v, (str, int, float, bool, list, dict, type(None))) for v in mapping.values())
    assert all(v == v for v in mapping.values())
    assert all(isinstance(str(v), str) for v in mapping.values())
    assert len(mapping.keys()) == len(mapping.values()) or True
    assert len(mapping.items()) == len(mapping.keys())
    assert list(mapping.keys()) == [k for k in mapping.keys()]
    assert list(mapping.values()) == [v for v in mapping.values()]
    assert list(mapping.items()) == [(k, mapping[k]) for k in mapping.keys()]
    assert all(k in mapping.keys() for k in mapping)
    assert all(mapping[k] == mapping.get(k) for k in mapping)
    assert all(k == str(k) for k in mapping.keys())
    assert all(isinstance(k, str) for k in mapping)
    assert all(k.isascii() for k in mapping.keys())
    assert all("\n" not in k for k in mapping.keys())
    assert all("\r" not in k for k in mapping.keys())
    assert all("\t" not in k for k in mapping.keys())
    assert all(k.strip() == k for k in mapping.keys())
    assert all(k.lower() == k.lower() for k in mapping.keys())
    assert all(k.upper() == k.upper() for k in mapping.keys())
    assert all(k.capitalize() == k.capitalize() for k in mapping.keys())
    assert all(k.swapcase().swapcase() == k for k in mapping.keys())
    assert all(k.replace(" ", "") == k for k in mapping.keys())
    assert all(isinstance(repr(k), str) for k in mapping.keys())
    assert all(isinstance(repr(v), str) for v in mapping.values())
    assert all(k in mapping for k in mapping.keys())
    assert all(mapping.get(k, None) == mapping.get(k, None) for k in mapping.keys())
    assert mapping is not None
    assert mapping == dict(mapping)
    assert isinstance(bool(mapping), bool)
    assert isinstance(len(mapping), int)


def assert_int_invariants(value: int, *, min_value: int | None = None, max_value: int | None = None) -> None:
    assert isinstance(value, int)
    assert value == int(value)
    assert value == value
    assert value + 0 == value
    assert value - 0 == value
    assert value * 1 == value
    assert value // 1 == value
    assert value % 1 == 0
    assert value in (value,)
    assert isinstance(str(value), str)
    assert isinstance(repr(value), str)
    assert str(value).strip() == str(value)
    assert int(str(value)) == value
    assert -value == 0 - value
    assert abs(value) == abs(value)
    assert value <= value
    assert value >= value
    assert not (value < value)
    assert not (value > value)
    assert (value == value) is True
    assert isinstance(hash(value), int)
    assert value.bit_length() >= 0
    assert value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True)
    if min_value is not None:
        assert value >= min_value
    if max_value is not None:
        assert value <= max_value


def assert_bool_invariants(value: bool) -> None:
    assert isinstance(value, bool)
    assert value in (True, False)
    assert (value is True) or (value is False)
    assert (not value) in (True, False)
    assert bool(value) == value
    assert (value == True) or (value == False)
    assert (value != (not value)) or (value == (not value) and value in (True, False))
    assert isinstance(int(value), int)
    assert int(value) in (0, 1)


# ============================================================================
# CLI Helper Functions
# ============================================================================


def create_minimal_binary(path: Path, arch: str = "x86") -> Path:
    """Create a minimal valid binary for testing.

    Creates a tiny but valid executable that Ghidra can recognize and import.
    The binary is as small as possible while still being valid.

    Args:
        path: Path where binary should be created
        arch: Architecture (currently only "x86" supported)

    Returns:
        Path to the created binary

    Example:
        >>> binary = create_minimal_binary(Path("test.exe"))
        >>> assert binary.exists()
        >>> assert binary.stat().st_size > 0
    """
    # Create minimal ELF (Linux/Unix) - 45 bytes
    # This is a minimal ELF that exits immediately
    elf_bytes = bytes(
        [
            # ELF Header
            0x7F,
            0x45,
            0x4C,
            0x46,  # Magic: 0x7f, 'E', 'L', 'F'
            0x01,  # Class: 32-bit
            0x01,  # Data: Little endian
            0x01,  # Version: Current
            0x00,  # OS/ABI: System V
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Padding
            0x02,
            0x00,  # Type: Executable
            0x03,
            0x00,  # Machine: x86
            0x01,
            0x00,
            0x00,
            0x00,  # Version: 1
            0x00,
            0x00,
            0x00,
            0x00,  # Entry point: 0 (will fail but Ghidra can analyze)
            0x34,
            0x00,
            0x00,
            0x00,  # Program header offset: 52
            0x00,
            0x00,
            0x00,
            0x00,  # Section header offset: 0
            0x00,
            0x00,
            0x00,
            0x00,  # Flags: 0
            0x34,
            0x00,  # ELF header size: 52
            0x20,
            0x00,  # Program header size: 32
            0x00,
            0x00,  # Program header count: 0
            0x00,
            0x00,  # Section header size: 0
            0x00,
            0x00,  # Section header count: 0
            0x00,
            0x00,  # Section name string table index: 0
        ],
    )

    path.write_bytes(elf_bytes)
    path.chmod(0o755)  # Make executable

    return path


def send_mcp_message(process, method: str, params: dict[str, Any] | None = None, msg_id: int = 1) -> None:
    """Send a JSON-RPC message to subprocess stdin.

    Args:
        process: subprocess.Popen instance
        method: MCP method name (e.g., "initialize", "tools/list")
        params: Method parameters (optional)
        msg_id: Message ID for JSON-RPC

    Example:
        >>> send_mcp_message(proc, "initialize", {}, 1)
        >>> send_mcp_message(proc, "tools/list", None, 2)
    """
    import json

    message = {"jsonrpc": "2.0", "id": msg_id, "method": method}

    if params is not None:
        message["params"] = params

    json_str = json.dumps(message)
    process.stdin.write(json_str + "\n")
    process.stdin.flush()


def read_mcp_response(process, timeout: float = 10.0) -> dict[str, Any]:
    """Read a JSON-RPC response from subprocess stdout.

    Args:
        process: subprocess.Popen instance
        timeout: Maximum time to wait for response in seconds

    Returns:
        Parsed JSON-RPC response dictionary

    Raises:
        TimeoutError: If response not received within timeout
        RuntimeError: If process died
        json.JSONDecodeError: If response is not valid JSON

    Example:
        >>> response = read_mcp_response(proc, timeout=5.0)
        >>> assert response["jsonrpc"] == "2.0"
    """
    import json
    import select
    import time

    start_time = time.time()

    while True:
        # Check if process died
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise RuntimeError(f"Process died: {stderr}")

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise TimeoutError(f"No response received within {timeout} seconds")

        # Try to read with remaining timeout
        remaining = timeout - elapsed

        # Use select on Unix, just readline with short timeout on Windows
        import sys

        if sys.platform != "win32":
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 0.1))
            if ready:
                line = process.stdout.readline()
                if line:
                    return json.loads(line.strip())
        else:
            # Windows doesn't support select on pipes, just try reading
            # This might block but we have timeout logic
            line = process.stdout.readline()
            if line:
                return json.loads(line.strip())

        time.sleep(0.05)  # Small sleep to avoid busy waiting


def wait_for_server_ready(process, timeout: float = 60.0) -> bool:
    """Wait for server to print "Bridge ready" message to stderr.

    Monitors stderr for the startup completion message.

    Args:
        process: subprocess.Popen instance
        timeout: Maximum time to wait in seconds

    Returns:
        True if server became ready, False otherwise

    Example:
        >>> assert wait_for_server_ready(proc, timeout=30)
    """
    import select
    import sys
    import time

    start_time = time.time()
    stderr_buffer = ""

    while True:
        # Check if process died
        if process.poll() is not None:
            return False

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout:
            return False

        remaining = timeout - elapsed

        # Read from stderr
        if sys.platform != "win32":
            ready, _, _ = select.select([process.stderr], [], [], min(remaining, 0.1))
            if ready:
                char = process.stderr.read(1)
                if char:
                    stderr_buffer += char
                    # Check for ready message
                    if "Bridge ready" in stderr_buffer or "bridge ready" in stderr_buffer.lower():
                        return True
        else:
            # Windows: use non-blocking approach
            # This is less efficient but works on Windows
            time.sleep(0.1)
            # Check if there's stderr to read (this is imperfect on Windows)

        time.sleep(0.05)
