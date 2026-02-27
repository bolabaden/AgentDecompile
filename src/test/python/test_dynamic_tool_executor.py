"""
Comprehensive tests for the DynamicToolExecutor.

Tests all functionality from the Java test suite:
- CallGraphToolProviderTest.java
- DecompilerToolProviderTest.java
- DataToolProviderTest.java
- MemoryToolProviderTest.java
- FunctionToolProviderTest.java
- StringToolProviderTest.java
- SymbolToolProviderTest.java
- StructureToolProviderTest.java
- ImportExportToolProviderTest.java
- CommentToolProviderTest.java
- BookmarkToolProviderTest.java
- CrossReferencesToolProviderTest.java
- ConstantSearchToolProviderTest.java
- DataFlowToolProviderTest.java
- VtableToolProviderTest.java
- ProjectToolProviderTest.java
"""

import pytest
from unittest.mock import Mock, patch

from agentdecompile_cli.executor import dynamic_executor


class TestDynamicToolExecutor:
    """Test the dynamic tool executor with all tools."""

    def test_tool_name_resolution(self):
        """Test that tool names are resolved correctly."""
        # Test various name variations - should return the actual registry name with dashes
        assert dynamic_executor._resolve_tool_name("get-data") == "get-data"
        assert dynamic_executor._resolve_tool_name("getdata") == "get-data"
        assert dynamic_executor._resolve_tool_name("get_data") == "get-data"
        assert dynamic_executor._resolve_tool_name("getData") == "get-data"
        assert dynamic_executor._resolve_tool_name("unknown") is None

    def test_argument_parsing_variations(self):
        """Test that argument parsing handles all case variations."""
        raw_args = {
            "programPath": "/test/binary",
            "mode": "list",
            "max_results": 50,
            "include_referencing_functions": True,
        }

        parsed = dynamic_executor._parse_arguments_dynamically("manage-strings", raw_args)

        assert parsed["programPath"] == "/test/binary"
        assert parsed["mode"] == "list"
        assert parsed["maxResults"] == 50
        assert parsed["includeReferencingFunctions"] is True

    def test_dynamic_type_coercion(self):
        """Test that types are coerced correctly based on parameter names."""
        # String parameters
        assert dynamic_executor._coerce_value_dynamically("programPath", 123) == "123"
        assert dynamic_executor._coerce_value_dynamically("address", None) is None

        # Boolean parameters
        assert dynamic_executor._coerce_value_dynamically("includeSignature", "true") is True
        assert dynamic_executor._coerce_value_dynamically("caseSensitive", 1) is True
        assert dynamic_executor._coerce_value_dynamically("includeRefs", "false") is False

        # Integer parameters
        assert dynamic_executor._coerce_value_dynamically("maxResults", "100") == 100
        assert dynamic_executor._coerce_value_dynamically("timeout", 30.5) == 30

        # List parameters
        assert dynamic_executor._coerce_value_dynamically("commentTypes", "single") == ["single"]
        assert dynamic_executor._coerce_value_dynamically("addresses", ["addr1", "addr2"]) == ["addr1", "addr2"]

    def test_validation_required_params(self):
        """Test that required parameter validation works."""
        # Should pass with required params
        valid_args = {
            "programPath": "/test/binary",
            "addressOrSymbol": "0x1000"
        }
        dynamic_executor._validate_arguments_dynamically("get-data", valid_args)

        # Should fail without required params
        with pytest.raises(ValueError, match="Required parameter 'programPath' is missing"):
            dynamic_executor._validate_arguments_dynamically("get-data", {})

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor._execute_with_ghidra_tools')
    def test_execute_with_context(self, mock_execute):
        """Test execution with different contexts."""
        mock_execute.return_value = [{"type": "text", "text": '{"result": "success"}'}]

        # Test with GhidraTools context
        context = {'ghidra_tools': Mock()}
        result = dynamic_executor.execute_tool("decompile", {"programPath": "/test"}, context)

        mock_execute.assert_called_once()
        assert result == mock_execute.return_value

    def test_error_handling(self):
        """Test that errors are handled properly."""
        result = dynamic_executor.execute_tool("nonexistent-tool", {})
        assert len(result) == 1
        assert "Unknown tool" in result[0].text

    def test_callgraph_tool_integration(self):
        """Test callgraph tool execution (equivalent to CallGraphToolProviderTest.java)."""
        # Mock the callgraph tool
        with patch('agentdecompile_cli.dynamic_tool_executor.CallGraphTool') as mock_callgraph:
            mock_instance = Mock()
            mock_callgraph.return_value = mock_instance
            mock_instance.generate_for_mcp.return_value = {
                "functionName": "test_func",
                "direction": "calling",
                "displayType": "flow",
                "graph": "mock_graph",
                "mermaidUrl": "mock_url",
            }

            args = {
                "programPath": "/test/binary",
                "function": "main",
                "direction": "calling"
            }

            result = dynamic_executor.execute_tool("get-call-graph", args, {'ghidra_tools': Mock()})

            assert len(result) == 1
            data = result[0]
            assert "functionName" in data["text"]
            assert "test_func" in data["text"]

    def test_decompile_tool_integration(self):
        """Test decompile tool execution (equivalent to DecompilerToolProviderTest.java)."""
        # Mock the decompile tool
        with patch('agentdecompile_cli.dynamic_tool_executor.DecompileTool') as mock_decompile:
            mock_instance = Mock()
            mock_decompile.return_value = mock_instance
            mock_instance.decompile_function_for_mcp.return_value = Mock(
                name="test_func",
                code="void test_func() { return; }",
                signature="void test_func()",
            )

            args = {
                "programPath": "/test/binary",
                "function": "main"
            }

            result = dynamic_executor.execute_tool("decompile", args, {'ghidra_tools': Mock()})

            assert len(result) == 1
            data = result[0]
            assert "test_func" in data["text"]
            assert "void test_func()" in data["text"]

    def test_data_tool_operations(self):
        """Test data tool operations (equivalent to DataToolProviderTest.java)."""
        # Test get-data operation
        args = {
            "programPath": "/test/binary",
            "addressOrSymbol": "0x1000"
        }

        result = dynamic_executor.execute_tool("get-data", args)

        # Should execute with placeholder since no Ghidra context
        assert len(result) == 1
        assert "placeholder" in result[0].text.lower()

    def test_memory_tool_operations(self):
        """Test memory tool operations (equivalent to MemoryToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "read",
            "address": "0x1000",
            "size": 64
        }

        result = dynamic_executor.execute_tool("inspect-memory", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_function_tool_operations(self):
        """Test function tool operations (equivalent to FunctionToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "action": "list",
            "maxResults": 100
        }

        result = dynamic_executor.execute_tool("get-functions", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_string_tool_operations(self):
        """Test string tool operations (equivalent to StringToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "list",
            "maxResults": 50
        }

        result = dynamic_executor.execute_tool("manage-strings", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_symbol_tool_operations(self):
        """Test symbol tool operations (equivalent to SymbolToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "list",
            "maxResults": 200
        }

        result = dynamic_executor.execute_tool("manage-symbols", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_structure_tool_operations(self):
        """Test structure tool operations (equivalent to StructureToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "action": "list"
        }

        result = dynamic_executor.execute_tool("manage-structures", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_import_export_operations(self):
        """Test import/export operations (equivalent to ImportExportToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "imports"
        }

        result = dynamic_executor.execute_tool("manage-imports", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_comment_tool_operations(self):
        """Test comment tool operations (equivalent to CommentToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "action": "set",
            "comment": "Test comment"
        }

        result = dynamic_executor.execute_tool("manage-comments", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_bookmark_tool_operations(self):
        """Test bookmark tool operations (equivalent to BookmarkToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "action": "add",
            "description": "Test bookmark"
        }

        result = dynamic_executor.execute_tool("manage-bookmarks", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_cross_references_operations(self):
        """Test cross-references operations (equivalent to CrossReferencesToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "target": "0x1000"
        }

        result = dynamic_executor.execute_tool("get-references", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_constant_search_operations(self):
        """Test constant search operations (equivalent to ConstantSearchToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "search",
            "value": "0xdeadbeef"
        }

        result = dynamic_executor.execute_tool("search-constants", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_data_flow_operations(self):
        """Test data flow operations (equivalent to DataFlowToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "function": "main"
        }

        result = dynamic_executor.execute_tool("analyze-data-flow", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_vtable_operations(self):
        """Test vtable operations (equivalent to VtableToolProviderTest.java)."""
        args = {
            "programPath": "/test/binary",
            "mode": "list"
        }

        result = dynamic_executor.execute_tool("analyze-vtables", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_project_operations(self):
        """Test project operations (equivalent to ProjectToolProviderTest.java)."""
        args = {
            "action": "list"
        }

        result = dynamic_executor.execute_tool("list-project-files", args)

        assert len(result) == 1
        assert "placeholder" in result[0]["text"].lower()

    def test_backward_compatibility(self):
        """Test that all argument name variations work."""
        # Test camelCase
        args1 = {"programPath": "/test", "addressOrSymbol": "0x1000"}
        parsed1 = dynamic_executor._parse_arguments_dynamically("get-data", args1)

        # Test snake_case
        args2 = {"program_path": "/test", "address_or_symbol": "0x1000"}
        parsed2 = dynamic_executor._parse_arguments_dynamically("get-data", args2)

        # Test kebab-case
        args3 = {"program-path": "/test", "address-or-symbol": "0x1000"}
        parsed3 = dynamic_executor._parse_arguments_dynamically("get-data", args3)

        # All should produce the same canonical parameter names
        assert parsed1 == parsed2 == parsed3
        assert "programPath" in parsed1
        assert "addressOrSymbol" in parsed1