"""
Tests for CLI dynamic command generation and execution.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch

from agentdecompile_cli.cli import main


class TestCliDynamic:
    """Test CLI dynamic functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_dynamic_command_generation(self, mock_execute):
        """Test that dynamic commands are generated from tool registry."""
        mock_execute.return_value = [{"type": "text", "text": '{"result": "success"}'}]

        # Test a dynamically generated command
        result = self.runner.invoke(main, ['get-data', '--program-path', '/test/binary', '--address-or-symbol', '0x1000'])

        assert result.exit_code == 0
        mock_execute.assert_called_once()
        call_args = mock_execute.call_args[0]
        assert call_args[0] == "get-data"
        assert "programPath" in call_args[1]
        assert "addressOrSymbol" in call_args[1]

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_argument_case_variations(self, mock_execute):
        """Test that CLI accepts various argument case formats."""
        mock_execute.return_value = [{"type": "text", "text": '{"result": "success"}'}]

        # Test with different argument formats
        test_cases = [
            ['get-data', '--program-path', '/test', '--address-or-symbol', '0x1000'],  # kebab-case
            ['get-data', '--programPath', '/test', '--addressOrSymbol', '0x1000'],    # camelCase
        ]

        for args in test_cases:
            result = self.runner.invoke(main, args)
            assert result.exit_code == 0

        # Should be called twice (once for each test case)
        assert mock_execute.call_count == 2

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_callgraph_cli(self, mock_execute):
        """Test callgraph CLI command."""
        mock_execute.return_value = [{"type": "text", "text": '{"functionName": "main", "graph": "test"}'}]

        result = self.runner.invoke(main, [
            'get-call-graph',
            '--program-path', '/test/binary',
            '--function', 'main',
            '--direction', 'calling'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("get-call-graph", {
            "programPath": "/test/binary",
            "function": "main",
            "direction": "calling"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_decompile_cli(self, mock_execute):
        """Test decompile CLI command."""
        mock_execute.return_value = [{"type": "text", "text": '{"name": "main", "code": "int main() { return 0; }"}'}]

        result = self.runner.invoke(main, [
            'decompile',
            '--program-path', '/test/binary',
            '--function', 'main'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("decompile", {
            "programPath": "/test/binary",
            "function": "main"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_symbol_operations_cli(self, mock_execute):
        """Test symbol operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"symbols": ["func1", "func2"]}'}]

        result = self.runner.invoke(main, [
            'manage-symbols',
            '--program-path', '/test/binary',
            '--mode', 'list',
            '--max-results', '100'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("manage-symbols", {
            "programPath": "/test/binary",
            "mode": "list",
            "maxResults": 100
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_string_operations_cli(self, mock_execute):
        """Test string operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"strings": ["hello", "world"]}'}]

        result = self.runner.invoke(main, [
            'manage-strings',
            '--program-path', '/test/binary',
            '--mode', 'list'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("manage-strings", {
            "programPath": "/test/binary",
            "mode": "list"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_memory_operations_cli(self, mock_execute):
        """Test memory operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"data": "deadbeef"}'}]

        result = self.runner.invoke(main, [
            'inspect-memory',
            '--program-path', '/test/binary',
            '--mode', 'read',
            '--address', '0x1000',
            '--size', '64'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("inspect-memory", {
            "programPath": "/test/binary",
            "mode": "read",
            "address": "0x1000",
            "size": 64
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_comment_operations_cli(self, mock_execute):
        """Test comment operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"success": true}'}]

        result = self.runner.invoke(main, [
            'manage-comments',
            '--program-path', '/test/binary',
            '--action', 'set',
            '--comment', 'Test comment',
            '--address-or-symbol', '0x1000'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("manage-comments", {
            "programPath": "/test/binary",
            "action": "set",
            "comment": "Test comment",
            "addressOrSymbol": "0x1000"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_bookmark_operations_cli(self, mock_execute):
        """Test bookmark operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"success": true}'}]

        result = self.runner.invoke(main, [
            'manage-bookmarks',
            '--program-path', '/test/binary',
            '--action', 'add',
            '--description', 'Test bookmark'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("manage-bookmarks", {
            "programPath": "/test/binary",
            "action": "add",
            "description": "Test bookmark"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_structure_operations_cli(self, mock_execute):
        """Test structure operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"structures": []}'}]

        result = self.runner.invoke(main, [
            'manage-structures',
            '--program-path', '/test/binary',
            '--action', 'list'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("manage-structures", {
            "programPath": "/test/binary",
            "action": "list"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_cross_references_cli(self, mock_execute):
        """Test cross-references via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"references": []}'}]

        result = self.runner.invoke(main, [
            'get-references',
            '--program-path', '/test/binary',
            '--target', '0x1000'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("get-references", {
            "programPath": "/test/binary",
            "target": "0x1000"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_constant_search_cli(self, mock_execute):
        """Test constant search via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"results": []}'}]

        result = self.runner.invoke(main, [
            'search-constants',
            '--program-path', '/test/binary',
            '--mode', 'search',
            '--value', '0xdeadbeef'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("search-constants", {
            "programPath": "/test/binary",
            "mode": "search",
            "value": "0xdeadbeef"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_data_flow_analysis_cli(self, mock_execute):
        """Test data flow analysis via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"analysis": {}}'}]

        result = self.runner.invoke(main, [
            'analyze-data-flow',
            '--program-path', '/test/binary',
            '--function', 'main'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("analyze-data-flow", {
            "programPath": "/test/binary",
            "function": "main"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_vtable_analysis_cli(self, mock_execute):
        """Test vtable analysis via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"vtables": []}'}]

        result = self.runner.invoke(main, [
            'analyze-vtables',
            '--program-path', '/test/binary',
            '--mode', 'list'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("analyze-vtables", {
            "programPath": "/test/binary",
            "mode": "list"
        })

    @patch('agentdecompile_cli.dynamic_tool_executor.dynamic_executor.execute_tool')
    def test_project_operations_cli(self, mock_execute):
        """Test project operations via CLI."""
        mock_execute.return_value = [{"type": "text", "text": '{"files": []}'}]

        result = self.runner.invoke(main, [
            'list-project-files'
        ])

        assert result.exit_code == 0
        mock_execute.assert_called_once_with("list-project-files", {})

    def test_invalid_tool_error(self):
        """Test error handling for invalid tools."""
        result = self.runner.invoke(main, ['nonexistent-tool'])

        assert result.exit_code == 1
        assert "Unknown tool" in result.output

    def test_required_parameter_validation(self):
        """Test that required parameters are validated."""
        result = self.runner.invoke(main, ['get-data'])

        assert result.exit_code == 1
        assert "programPath is required" in result.output