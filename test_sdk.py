#!/usr/bin/env python3
"""Test AgentDecompile Python API/SDK directly"""
import sys

# Try to import agentdecompile modules
try:
    from src.agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager
    from src.agentdecompile_cli.registry import normalize_identifier
    print("✓ AgentDecompile imports successful")
    print(f"  - ToolProviderManager: {ToolProviderManager}")
    print(f"  - normalize_identifier: {normalize_identifier}")
except ImportError as e:
    print(f"✗ Import error: {e}")
    print("\nTrying alternative imports...")
    try:
        from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager
        print("✓ Alternative import successful")
    except:
        print("✗ Alternative imports also failed")
        sys.exit(1)

# Try to get tool manager info
try:
    print("\nAttempting to list available tools...")
    manager = ToolProviderManager()
    print("✓ ToolProviderManager created")
    
    tool_list = manager.list_tools()
    print(f"✓ Available tools: {len(tool_list)} tools")
    for tool in tool_list[:5]:
        print(f"  - {tool.get('name', 'unknown')}")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("The issue is that the MCP tools require:")
print("1. A program to be loaded in the backend")
print("2. Connection to the MCP server at http://170.9.241.140:8080")
print("3. Proper authentication to the Ghidra shared server")
print("\nThe integration test demonstrates this works when all conditions are met.")
print("="*80)
