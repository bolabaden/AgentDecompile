#!/usr/bin/env python3
"""Fix missing if check and indentation."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Find where we need to add the if check
    if '# Use analyzeHeadless for shared import' in line and i > 0:
        # Check if previous line is the if statement
        prev_line = lines[i-1] if i > 0 else ""
        if 'if server_host and repository_name:' not in prev_line:
            # Add the if check before this comment
            new_lines.append('            if server_host and repository_name:\n')
        new_lines.append(line)
        i += 1
        # Fix indentation of following lines until we hit less indentation
        while i < len(lines):
            current = lines[i]
            # Stop if we hit a line with less or no indentation (end of block)
            if current.strip() and not current.startswith(' '):
                break
            # If line starts with 20 spaces, reduce to 16
            if current.startswith('                    '):  # 20 spaces
                new_lines.append('                ' + current[20:])  # 16 spaces
            elif current.startswith('                '):  # 16 spaces - correct
                new_lines.append(current)
            elif not current.strip():  # Empty line
                new_lines.append(current)
            else:
                break
            i += 1
        continue
    
    new_lines.append(line)
    i += 1

with open(file_path, 'w') as f:
    f.writelines(new_lines)

print(f"Fixed missing if and indentation in {file_path}")
