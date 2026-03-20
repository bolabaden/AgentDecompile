#!/usr/bin/env python3
"""Fix imports in import_export.py"""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

# Check if import exists
has_import = False
for line in lines:
    if 'get_current_mcp_session_id' in line and 'from' in line and 'import' in line:
        has_import = True
        break

if not has_import:
    # Find the tool_providers import line
    new_lines = []
    for i, line in enumerate(lines):
        new_lines.append(line)
        if 'from agentdecompile_cli.mcp_server.tool_providers import' in line:
            # Insert session_context import before this line
            new_lines.insert(-1, 'from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS, get_current_mcp_session_id\n')
            break
    
    if len(new_lines) > len(lines):
        with open(file_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Added import to {file_path}")
    else:
        print(f"Could not find insertion point in {file_path}")
        sys.exit(1)
else:
    print(f"Import already exists in {file_path}")
