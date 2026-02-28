# AgentDecompile Tests

Professional pytest suite for testing AgentDecompile with PyGhidra.

## Overview

These tests verify that AgentDecompile components work together correctly:

- **Integration Tests**: PyGhidra initialization, launcher lifecycle, tool connectivity
- **Unit Tests**: Individual tool providers, normalization, configuration
- **E2E Tests**: Full CLI workflows and cross-client compatibility  
- **Provider Tests**: Each of the 19 tool providers in isolation

## Test Types and Organization

Tests are organized by functionality (37 test files total):

### Core Tests
- `test_pyghidra.py` - PyGhidra initialization
- `test_launcher.py` - AgentDecompileLauncher lifecycle
- `test_mcp_tools.py` - MCP tool connectivity
- `test_config.py` - Configuration loading
- `test_session_context.py` - Session context management

### CLI Tests
- `test_cli_connect_mode.py` - CLI in connect mode (server attachment)
- `test_cli_dynamic.py` - CLI dynamic tool execution
- `test_cli_e2e.py` - CLI end-to-end workflows
- `test_cli_helpers.py` - CLI helper utilities
- `test_cli_project_manager.py` - CLI project management

### Tool Provider Tests (19 providers)
- `test_provider_symbols.py` - Symbol management
- `test_provider_functions.py` - Function analysis
- `test_provider_memory.py` - Memory inspection
- `test_provider_callgraph.py` - Call graph analysis
- `test_provider_comments.py` - Comments/annotations
- `test_provider_bookmarks.py` - Bookmarks
- `test_provider_project.py` - Project management
- `test_provider_strings.py` - String management
- `test_provider_structures_datatypes_data.py` - Data types and structures
- `test_provider_xrefs.py` - Cross-references
- `test_provider_dataflow.py` - Data flow analysis
- `test_provider_getfunction.py` - Function retrieval
- `test_provider_import_export.py` - Import/export operations
- `test_provider_constants.py` - Constants and data
- `test_provider_decompiler.py` - Decompiler integration
- `test_provider_vtable.py` - Virtual table analysis
- `test_provider_suggestions.py` - Suggestion generation

### Normalization and Compatibility Tests
- `test_normalization_combinatorial.py` - Comprehensive normalization coverage
- `test_python_tool_registry_parity.py` - Tool registry parity checks

### Workflow and Integration Tests
- `test_e2e_workflow.py` - End-to-end workflow scenarios
- `test_dynamic_tool_executor.py` - Dynamic tool execution
- `test_import_e2e.py` - Binary import workflows

### Helpers and Configuration
- `conftest.py` - Pytest fixtures (shared across all tests)
- `helpers.py` - Utility functions (MCP requests, program creation)

## Running Tests

### Prerequisites

```bash
# Install dependencies with uv
uv sync
# or: pip install -r tests/requirements.txt

# Ensure GHIDRA_INSTALL_DIR is set
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # or set via Windows environment

# AgentDecompile is installed as editable package (via uv sync)
```

### Run All Tests

```bash
uv run pytest tests/ -v
```

### Run Tests by Category

```bash
# Core functionality tests only
uv run pytest tests/test_launcher.py tests/test_config.py -v

# CLI tests
uv run pytest tests/test_cli_*.py -v

# Provider tests
uv run pytest tests/test_provider_*.py -v

# Normalization/compatibility tests
uv run pytest tests/test_*normalization*.py tests/test_*compatibility*.py -v
```

### Run Tests Matching Pattern

```bash
uv run pytest tests/ -k "symbols" -v          # All symbol-related tests
uv run pytest tests/ -k "provider" -v         # All provider tests
uv run pytest tests/ -k "normalize" -v        # All normalization tests
```

### Run with Timeout

```bash
uv run pytest tests/ -v --timeout=180  # 3-minute timeout per test
```

### Run with Different Output

```bash
uv run pytest tests/ -v --tb=short    # Shorter tracebacks
uv run pytest tests/ -v --tb=line     # One-line tracebacks
uv run pytest tests/ -v -s            # Show print statements
```

## Test Markers

Tests use pytest markers for filtering:

```bash
@pytest.mark.unit        # Unit tests (mocked PyGhidra)
@pytest.mark.integration # Integration tests (requires PyGhidra)
@pytest.mark.e2e         # End-to-end tests
@pytest.mark.slow        # Slow tests (skip with --ignore-slow)
```

Run only specific markers:
```bash
uv run pytest tests/ -m integration -v
uv run pytest tests/ -m "not slow" -v
```

## CI Integration

The GitHub Actions workflow (`.github/workflows/test-headless.yml`) runs these tests:

- **Matrix**: Ubuntu/macOS × Ghidra 12.0/latest
- **Timeout**: 30 minutes per job
- **Python**: 3.10
- **Artifacts**: Uploads test results and logs

Workflow steps:
1. Setup Java 21 (required for PyGhidra)
2. Install Ghidra
3. Build AgentDecompile extension with Gradle
4. Install extension to Ghidra
5. Setup Python and `uv`
6. Install Python dependencies (`uv sync`)
7. Install PyGhidra from local Ghidra
8. Run pytest (`uv run pytest tests/ -v --timeout=180`)
9. Upload test results and artifacts

## Writing New Tests

### Example: Test a New Tool Provider

```python
# tests/test_provider_mytool.py
import pytest
from tests.helpers import get_response_result

class TestMyToolProvider:
    """Test my-tool-provider functionality"""

    def test_tool_is_callable(self, mcp_client):
        """my-tool is registered and responds"""
        response = mcp_client.call_tool("my-tool", {
            "programPath": "/TestProgram"
        })

        assert response is not None
        result = get_response_result(response)
        assert result is not None

    def test_tool_with_arguments(self, mcp_client):
        """my-tool accepts expected arguments"""
        response = mcp_client.call_tool("my-tool", {
            "programPath": "/TestProgram",
            "myArg": "someValue"
        })

        result = get_response_result(response)
        assert "expected_field" in result
```

### Example: Test Normalization

```python
# tests/test_my_normalization.py
import pytest
from agentdecompile_cli.registry import normalize_identifier

def test_tool_name_normalization():
    """Tool names normalize correctly"""
    assert normalize_identifier("my-tool") == "mytool"
    assert normalize_identifier("MY_TOOL") == "mytool"
    assert normalize_identifier("myTool") == "mytool"

def test_with_mcp_client(mcp_client):
    """Tool accepts any normalized variant"""
    # All these should call the same tool
    for name_variant in ["my-tool", "MY-TOOL", "my_tool", "myTool"]:
        response = mcp_client.call_tool(name_variant, {"programPath": "/TestProgram"})
        assert response is not None
```

## Troubleshooting

### PyGhidra Initialization Fails
```
Error: GHIDRA_INSTALL_DIR not set
```
Set the environment variable:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # Linux/macOS
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra   # Windows  
```

### Tests Timeout
If tests timeout during CI:
1. Increase the `--timeout` value (default 180 seconds)
2. Look for slow fixtures or heavy operations
3. Mark very slow tests with `@pytest.mark.slow`

### Fixture Issues
If you get fixture errors, ensure:
- `conftest.py` is in the top-level tests/ directory
- Fixtures are properly scoped (session, module, function, etc.)
- Dependencies are installed (`uv sync`)

## Performance

Typical test execution times:

- **PyGhidra initialization**: 10-30 seconds (once per session)
- **Server start**: 2-5 seconds (per test using `server` fixture)
- **MCP request**: <1 second
- **Full test suite**: ~2-5 minutes (depends on test count)

## Best Practices

1. **Use fixtures** - Reuse `ghidra_initialized` and `mcp_client` rather than creating new ones
2. **Test one thing** - Keep tests focused on a single behavior
3. **Use markers** - Mark slow tests with `@pytest.mark.slow`
4. **Clean up** - Ensure temporary projects/files are cleaned up after tests
5. **Verify state changes** - For integration tests, verify actual program state changed

## Related Documentation

- **Main README**: [README.md](../README.md) - Project overview
- **CI Workflows**: [../.github/CI_WORKFLOWS.md](../.github/CI_WORKFLOWS.md) - Complete CI documentation
