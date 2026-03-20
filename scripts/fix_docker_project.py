#!/usr/bin/env python3
"""Fix and patch project.py in Docker container."""
import sys

file_path = sys.argv[1] if len(sys.argv) > 1 else '/ghidra/venv/lib/python3.12/site-packages/agentdecompile_cli/mcp_server/providers/project.py'

with open(file_path, 'r') as f:
    content = f.read()

# Find the line with requested_repository_name = self._infer...
# and add fallback after it
lines = content.split('\n')
new_lines = []
i = 0
patched = False

while i < len(lines):
    line = lines[i]
    new_lines.append(line)
    
    # Look for: requested_repository_name = self._infer_requested_shared_repository_name(args, path)
    if (not patched and 
        'requested_repository_name = self._infer_requested_shared_repository_name(args, path)' in line):
        # Add fallback after this line
        new_lines.append('        # FALLBACK: if inference failed, use path as repo name')
        new_lines.append('        if requested_repository_name is None and path and path.strip() and "/" not in path.strip().rstrip("/"):')
        new_lines.append('            requested_repository_name = path.strip().rstrip("/")')
        new_lines.append('            logger.info("[connect-shared-project] FALLBACK: Using path=%r as repository name", requested_repository_name)')
        patched = True
    
    i += 1

if patched:
    with open(file_path, 'w') as f:
        f.write('\n'.join(new_lines))
    print(f"Patched {file_path}")
    sys.exit(0)
else:
    print(f"Pattern not found in {file_path}")
    sys.exit(1)
