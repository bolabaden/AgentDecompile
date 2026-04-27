#!/usr/bin/env python3
"""Patch import_export.py to fix shared repo function rename persistence"""

import re

filepath = 'src/agentdecompile_cli/mcp_server/providers/import_export.py'

with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line with the comment about "not modified" by reopening
target_idx = None
for i, line in enumerate(lines):
    if '"not modified" by reopening loads a fresh ProgramDB' in line:
        target_idx = i
        break

if target_idx is None:
    print("ERROR: Could not find target comment line")
    exit(1)

print(f"Found target line at index {target_idx}: {lines[target_idx].strip()[:50]}")

# The next few lines should be:
# handler = GhidraDefaultCheckinHandler(comment, _keep, False)
# if program_for_ops is not None:
#     try:
#         program_for_ops.forceLock(...)

# Find the "handler =" line
handler_idx = None
for i in range(target_idx, min(target_idx + 10, len(lines))):
    if 'handler = GhidraDefaultCheckinHandler' in lines[i]:
        handler_idx = i
        break

if handler_idx is None:
    print("ERROR: Could not find handler line")
    exit(1)

print(f"Found handler line at index {handler_idx}")

# Insert the new code after the handler line
new_code = '''            # For shared repos, ensure pending function renames are saved before checkin
            has_pending_renames_for_shared = False
            if repo_shared and program_for_ops is not None:
                try:
                    func_snap_pre_checkin = self._snapshot_user_defined_function_names(program_for_ops)
                    has_pending_renames_for_shared = bool(func_snap_pre_checkin)
                    if has_pending_renames_for_shared:
                        logger.info("versioned checkin shared-repo: detected %d pending function renames before save", len(func_snap_pre_checkin))
                except Exception as e:
                    logger.debug("versioned checkin shared-repo pre-checkin rename detection failed: %s", e)
'''

insertion_idx = handler_idx + 1
lines.insert(insertion_idx, new_code)

# Now find and update the line with program_for_ops.forceLock and add logic after it
# Look for forceLock call
forceLock_idx = None
for i in range(insertion_idx, min(insertion_idx + 20, len(lines))):
    if 'program_for_ops.forceLock' in lines[i]:
        forceLock_idx = i
        break

if forceLock_idx is None:
    print("ERROR: Could not find forceLock line")
    exit(1)

print(f"Found forceLock line at index {forceLock_idx}")

# Insert metadata update code after forceLock
metadata_code = '''                    # If shared repo has pending function renames, mark program as modified to ensure save includes them
                    if has_pending_renames_for_shared:
                        try:
                            pm = program_for_ops.getMetadata()
                            if pm is not None:
                                pm.putString("agentdecompile:pending_renames", "1")
                        except Exception:
                            pass
'''

insertion_idx2 = forceLock_idx + 1
lines.insert(insertion_idx2, metadata_code)

with open(filepath, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Successfully patched!")
print(f"Added {len(new_code.splitlines())} lines for rename detection")
print(f"Added {len(metadata_code.splitlines())} lines for metadata marking")
