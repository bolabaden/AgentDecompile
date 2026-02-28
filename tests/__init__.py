"""AgentDecompile Integration Tests

This package contains integration tests for AgentDecompile's headless mode using PyGhidra.

These tests verify that AgentDecompile components work together:
- PyGhidra can initialize Ghidra
- AgentDecompileLauncher can start/stop servers
- MCP tools are accessible and functional
- Configuration files are loaded correctly

Test Structure:
- test_pyghidra.py - PyGhidra integration verification
- test_launcher.py - AgentDecompileLauncher lifecycle tests
- test_mcp_tools.py - MCP tool connectivity and functionality
- test_config.py - Configuration file loading tests

Fixtures (conftest.py):
- ghidra_initialized - One-time PyGhidra initialization (session scope)
- test_program - Shared test program with memory and strings (session scope)
- server - Start/stop server for each test (function scope)
- mcp_client - MCP request helper (function scope)

Usage:
    pytest tests/ -v
    pytest tests/test_launcher.py -v
    pytest tests/ -k "config" -v
    pytest tests/ --timeout=60
"""
