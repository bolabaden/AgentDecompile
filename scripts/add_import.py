#!/usr/bin/env python3
from __future__ import annotations

import sys

file_path = sys.argv[1]

with open(file_path, "r") as f:
    lines = f.readlines()

# Find the tool_providers import line and add session_context import before it
new_lines = []
added = False
for i, line in enumerate(lines):
    if not added and "from agentdecompile_cli.mcp_server.tool_providers import" in line:
        new_lines.append("from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS, get_current_mcp_session_id\n")
        added = True
    new_lines.append(line)

if added:
    with open(file_path, "w") as f:
        f.writelines(new_lines)
    print(f"Added import to {file_path}")
else:
    print(f"Could not find tool_providers import line in {file_path}")
