#!/usr/bin/env python3
"""Patch old code structure to handle repository creation."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
patched = False

while i < len(lines):
    line = lines[i]
    
    # Look for: if not repository_names:
    # This is where it raises "No repositories found"
    if (not patched and 
        line.strip() == 'if not repository_names:' and
        i > 0 and 'repository_names: list[str] = [str(name) for name in repository_names_raw]' in lines[i-1]):
        # Before the "No repositories found" check, add logic to create repo if path is provided
        # Insert before the if statement
        new_lines.append('        # FALLBACK: if no repos found but path looks like a repo name, try to create it\n')
        new_lines.append('        if not repository_names and path and path.strip() and "/" not in path.strip().rstrip("/") and auth_provided:\n')
        new_lines.append('            try:\n')
        new_lines.append('                logger.info("[connect-shared-project] FALLBACK: Creating repository %r from path", path.strip())\n')
        new_lines.append('                created_repo = server_adapter.createRepository(path.strip())\n')
        new_lines.append('                if created_repo is not None or server_adapter.getRepository(path.strip()) is not None:\n')
        new_lines.append('                    repository_names = [path.strip()]\n')
        new_lines.append('                    logger.info("[connect-shared-project] FALLBACK: Repository %r created successfully", path.strip())\n')
        new_lines.append('            except Exception as repo_exc:\n')
        new_lines.append('                logger.warning("[connect-shared-project] FALLBACK: Failed to create repository %r: %s", path.strip(), repo_exc)\n')
        new_lines.append('                pass  # Fall through to "No repositories found" error\n')
        new_lines.append(line)  # Add the original if statement
        patched = True
    else:
        new_lines.append(line)
    
    i += 1

if patched:
    with open(file_path, 'w') as f:
        f.writelines(new_lines)
    print(f"Patched {file_path}")
    sys.exit(0)
else:
    print(f"Pattern not found")
    # Show context
    for i, line in enumerate(lines):
        if 'repository_names: list[str]' in line or 'if not repository_names:' in line:
            print(f"{i+1}: {line.rstrip()}")
            if i+1 < len(lines):
                print(f"{i+2}: {lines[i+1].rstrip()}")
    sys.exit(1)
