#!/usr/bin/env python3
"""Fix indentation after if server_host check."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
in_block = False
while i < len(lines):
    line = lines[i]
    
    # Find the line with "if server_host and repository_name:" that's at wrong indentation
    if 'if server_host and repository_name:' in line and i > 0:
        # Check if next line has wrong indentation (starts with too many spaces)
        if i + 1 < len(lines):
            next_line = lines[i + 1]
            # If next line starts with more than 16 spaces (wrong indentation), fix it
            if next_line.startswith('                    ') and not next_line.strip().startswith('#'):
                # This line should be indented 16 spaces (4 levels), not 20
                new_lines.append(line)
                # Fix all following lines until we hit a line with less indentation
                i += 1
                while i < len(lines):
                    current = lines[i]
                    # If line is empty or has less indentation, we're done
                    if not current.strip() or (current.strip() and not current.startswith('                    ')):
                        break
                    # Fix indentation: remove 4 spaces
                    if current.startswith('                    '):
                        new_lines.append(current[4:])
                    else:
                        new_lines.append(current)
                    i += 1
                continue
    
    new_lines.append(line)
    i += 1

with open(file_path, 'w') as f:
    f.writelines(new_lines)

print(f"Fixed indentation in {file_path}")
