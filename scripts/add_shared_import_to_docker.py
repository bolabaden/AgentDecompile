#!/usr/bin/env python3
"""Add _handle_shared_import method to Docker container's import_export.py."""
import sys

file_path = sys.argv[1]

# Read the shared import method from source
shared_import_code = '''    def _handle_shared_import(
        self,
        source: Path,
        recursive: bool,
        analyze_after_import: bool,
    ) -> dict[str, Any]:
        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        if not handle or str(handle.get("mode", "")).lower() != "shared-server":
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "Shared version-control import requires an active shared-server session. Call open against the shared server first.",
            }

        server_host = str(handle.get("server_host") or "").strip()
        server_port = int(handle.get("server_port") or 13100)
        repository_name = str(handle.get("repository_name") or "").strip()
        server_username = str(handle.get("server_username") or "").strip()
        server_password = str(handle.get("server_password") or "")
        repository_adapter = handle.get("repository_adapter")

        if not server_host or not repository_name or repository_adapter is None:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "Shared version-control import requires repository session state. Re-run open against the shared server and retry.",
            }

        # Use analyzeHeadless for shared import (simpler than PyGhidra API for this)
        ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
        if not ghidra_install_dir:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "GHIDRA_INSTALL_DIR not set; cannot use analyzeHeadless for shared import.",
            }

        try:
            from agentdecompile_cli.mcp_server.providers.import_export import _build_analyze_headless_import_command
            repo_url = f"{server_username}:{server_password}@{server_host}:{server_port}/{repository_name}"
            command = _build_analyze_headless_import_command(
                ghidra_install_dir=ghidra_install_dir,
                project_path=None,  # Not needed for shared
                repo_url=repo_url,
                source_file=str(source),
                program_name=source.name,
                analyze=analyze_after_import,
            )
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                return {
                    "action": "import",
                    "importedFrom": str(source),
                    "analysisRequested": analyze_after_import,
                    "versionControlRequested": True,
                    "versionControlEnabled": True,
                    "success": True,
                    "repository": repository_name,
                }
            else:
                return {
                    "action": "import",
                    "importedFrom": str(source),
                    "analysisRequested": analyze_after_import,
                    "versionControlRequested": True,
                    "versionControlEnabled": False,
                    "success": False,
                    "error": f"analyzeHeadless import failed: {result.stderr}",
                }
        except Exception as exc:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": f"Shared import failed: {exc}",
            }
'''

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
patched = False

while i < len(lines):
    line = lines[i]
    new_lines.append(line)
    
    # Look for: if enable_version_control:
    if (not patched and 
        line.strip() == 'if enable_version_control:' and
        i + 1 < len(lines) and
        'return create_success_response' in lines[i + 1]):
        # Replace the error return with a call to _handle_shared_import
        new_lines.append('            return create_success_response(self._handle_shared_import(source, recursive, analyze_after_import))\n')
        # Skip the old error return block (next few lines)
        i += 1
        while i < len(lines) and ('return create_success_response' in lines[i] or '}' in lines[i] or '],' in lines[i] or '"error"' in lines[i]):
            i += 1
        i -= 1  # Back up one line
        patched = True
    i += 1

# Add the _handle_shared_import method before the class ends or before another method
# Find a good place to insert it (before _handle_export or at the end of the class)
insert_pos = None
for i, line in enumerate(new_lines):
    if 'def _handle_export(' in line:
        insert_pos = i
        break

if insert_pos is None:
    # Find the end of the class
    for i in range(len(new_lines) - 1, -1, -1):
        if new_lines[i].strip().startswith('class ') and 'ImportExport' in new_lines[i]:
            # Find the next method
            for j in range(i + 1, len(new_lines)):
                if new_lines[j].strip().startswith('def ') and new_lines[j].strip().startswith('def _handle_'):
                    insert_pos = j
                    break
            break

if insert_pos and patched:
    # Insert the method
    new_lines.insert(insert_pos, '\n' + shared_import_code + '\n')
    with open(file_path, 'w') as f:
        f.writelines(new_lines)
    print(f"Patched {file_path}")
    sys.exit(0)
else:
    print(f"Could not patch: patched={patched}, insert_pos={insert_pos}")
    sys.exit(1)
