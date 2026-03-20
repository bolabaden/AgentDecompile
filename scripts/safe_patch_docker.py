#!/usr/bin/env python3
"""Safely patch project.py to add repository name fallback."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
patched = False

while i < len(lines):
    line = lines[i]
    new_lines.append(line)
    
    # Look for the exact line: requested_repository_name = self._infer_requested_shared_repository_name(args, path)
    if (not patched and 
        line.strip() == 'requested_repository_name = self._infer_requested_shared_repository_name(args, path)'):
        # Add fallback immediately after
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
    print(f"Pattern not found. First 50 lines:")
    for i, line in enumerate(lines[:50]):
        if 'requested_repository_name' in line or 'repository_names' in line:
            print(f"{i+1}: {line.rstrip()}")
    sys.exit(1)
