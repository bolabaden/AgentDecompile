#!/usr/bin/env python3
"""Fix indentation properly."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Find the problematic section
    if 'if server_host and repository_name:' in line and i + 1 < len(lines):
        new_lines.append(line)
        i += 1
        # Skip empty line
        if i < len(lines) and not lines[i].strip():
            i += 1
        # Fix indentation of all lines until we hit a line with less indentation
        while i < len(lines):
            current = lines[i]
            # Stop if we hit a line that's not indented (end of block) or has less indentation
            if current.strip() and not current.startswith(' '):
                break
            # If line starts with too many spaces (20+), reduce to 16
            if current.startswith('                    '):  # 20 spaces
                new_lines.append('                ' + current[20:])  # 16 spaces
            elif current.startswith('                '):  # 16 spaces - already correct
                new_lines.append(current)
            elif not current.strip():  # Empty line
                new_lines.append(current)
            else:
                # Less indentation - we're done with this block
                break
            i += 1
        continue
    
    new_lines.append(line)
    i += 1

with open(file_path, 'w') as f:
    f.writelines(new_lines)

print(f"Fixed indentation in {file_path}")
