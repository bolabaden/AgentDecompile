#!/usr/bin/env python3
"""Fix duplicate if check."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
found_first = False
while i < len(lines):
    line = lines[i]
    # Look for duplicate "if server_host and repository_name:"
    if 'if server_host and repository_name:' in line:
        if found_first:
            # Skip this duplicate line and the next "# Use analyzeHeadless" comment if present
            i += 1
            if i < len(lines) and '# Use analyzeHeadless' in lines[i]:
                i += 1
            continue
        else:
            found_first = True
    new_lines.append(line)
    i += 1

with open(file_path, 'w') as f:
    f.writelines(new_lines)

print(f"Fixed duplicate check in {file_path}")
