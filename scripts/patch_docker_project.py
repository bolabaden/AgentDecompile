#!/usr/bin/env python3
"""Patch project.py in Docker container to add fallback for repository name."""
import sys

file_path = sys.argv[1] if len(sys.argv) > 1 else '/ghidra/venv/lib/python3.12/site-packages/agentdecompile_cli/mcp_server/providers/project.py'

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
patched = False
while i < len(lines):
    line = lines[i]
    new_lines.append(line)
    
    # Look for the pattern: repository_names line followed by requested_repository_name line
    if (not patched and 
        'repository_names: list[str] = [str(name) for name in repository_names_raw]' in line and
        i + 1 < len(lines) and
        'requested_repository_name = self._infer_requested_shared_repository_name' in lines[i + 1]):
        # Add fallback after requested_repository_name line
        new_lines.append(lines[i + 1])  # Add the requested_repository_name line
        i += 1
        # Insert fallback code
        new_lines.append('        # FALLBACK: if inference failed, use path as repo name\n')
        new_lines.append('        if requested_repository_name is None and path and path.strip() and "/" not in path.strip().rstrip("/"):\n')
        new_lines.append('            requested_repository_name = path.strip().rstrip("/")\n')
        new_lines.append('            logger.info("[connect-shared-project] FALLBACK: Using path=%r as repository name", requested_repository_name)\n')
        patched = True
    
    i += 1

if patched:
    with open(file_path, 'w') as f:
        f.writelines(new_lines)
    print(f"Patched {file_path}")
    sys.exit(0)
else:
    print(f"Pattern not found in {file_path}")
    sys.exit(1)
