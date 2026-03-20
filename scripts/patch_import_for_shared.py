#!/usr/bin/env python3
"""Patch import to support shared mode with analyzeHeadless."""
import sys
import re

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    content = f.read()

# Replace the enable_version_control error block with shared mode support
old_pattern = r'(\s+if enable_version_control:\s+return create_success_response\(\s+\{\s+"action": "import",\s+"importedFrom": file_path,\s+"analysisRequested": analyze_after_import,\s+"versionControlRequested": True,\s+"versionControlEnabled": False,\s+"success": False,\s+"error": "Automatic promotion[^"]+",\s+\},\s+\))'

new_code = '''        if enable_version_control:
            # Check if we're in shared-server mode
            session_id = get_current_mcp_session_id()
            session = SESSION_CONTEXTS.get_or_create(session_id)
            handle = session.project_handle if isinstance(session.project_handle, dict) else None
            if handle and str(handle.get("mode", "")).lower() == "shared-server":
                # Use analyzeHeadless for shared import
                server_host = str(handle.get("server_host") or "").strip()
                server_port = int(handle.get("server_port") or 13100)
                repository_name = str(handle.get("repository_name") or "").strip()
                server_username = str(handle.get("server_username") or "").strip()
                server_password = str(handle.get("server_password") or "")
                if server_host and repository_name:
                    import subprocess
                    ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR", "/ghidra")
                    script_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
                    analyze_headless = os.path.join(ghidra_install_dir, "support", script_name)
                    if os.path.exists(analyze_headless):
                        repo_url = f"{server_username}:{server_password}@{server_host}:{server_port}/{repository_name}"
                        source_path = str(Path(file_path).expanduser().resolve())
                        cmd = [
                            analyze_headless,
                            "/tmp", "temp_import",
                            "-connect", f"{server_host}:{server_port}",
                            "-p", repo_url,
                            "-import", source_path,
                        ]
                        if analyze_after_import:
                            cmd.extend(["-analysisTimeoutPerFile", "300"])
                        try:
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                            if result.returncode == 0:
                                return create_success_response({
                                    "action": "import",
                                    "importedFrom": file_path,
                                    "analysisRequested": analyze_after_import,
                                    "versionControlRequested": True,
                                    "versionControlEnabled": True,
                                    "success": True,
                                    "repository": repository_name,
                                })
                        except Exception as e:
                            logger.warning(f"analyzeHeadless import failed: {e}")
            return create_success_response(
                {
                    "action": "import",
                    "importedFrom": file_path,
                    "analysisRequested": analyze_after_import,
                    "versionControlRequested": True,
                    "versionControlEnabled": False,
                    "success": False,
                    "error": "Automatic promotion of a local import into shared-project version control is not implemented here. Open a shared-server project first, then import through a shared-backed workflow.",
                },
            )'''

# Simple line-by-line replacement
lines = content.split('\n')
new_lines = []
i = 0
in_block = False
block_start = None

while i < len(lines):
    line = lines[i]
    
    if 'if enable_version_control:' in line:
        block_start = i
        in_block = True
        # Add the new code
        new_lines.extend(new_code.split('\n'))
        # Skip until we find the closing of the return statement
        i += 1
        paren_count = 0
        while i < len(lines):
            if '(' in lines[i]:
                paren_count += lines[i].count('(')
            if ')' in lines[i]:
                paren_count -= lines[i].count(')')
            if paren_count == 0 and lines[i].strip().endswith(')'):
                i += 1
                break
            i += 1
        continue
    
    new_lines.append(line)
    i += 1

with open(file_path, 'w') as f:
    f.write('\n'.join(new_lines))

print(f"Patched {file_path}")
