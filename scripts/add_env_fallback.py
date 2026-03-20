#!/usr/bin/env python3
"""Add environment variable fallback for shared import."""
import sys

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    content = f.read()

# Add env var fallback after the handle check fails
old_pattern = '''            if handle and handle.get("server_host") and handle.get("repository_name"):
                # Use analyzeHeadless for shared import
                server_host = str(handle.get("server_host") or "").strip()
                server_port = int(handle.get("server_port") or 13100)
                repository_name = str(handle.get("repository_name") or "").strip()
                server_username = str(handle.get("server_username") or "").strip()
                server_password = str(handle.get("server_password") or "")'''

new_pattern = '''            # Try to get shared server info from session handle, or fall back to env vars
            server_host = None
            server_port = 13100
            repository_name = None
            server_username = None
            server_password = None
            
            if handle and handle.get("server_host") and handle.get("repository_name"):
                server_host = str(handle.get("server_host") or "").strip()
                server_port = int(handle.get("server_port") or 13100)
                repository_name = str(handle.get("repository_name") or "").strip()
                server_username = str(handle.get("server_username") or "").strip()
                server_password = str(handle.get("server_password") or "")
            else:
                # Fallback to environment variables
                server_host = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_HOST")
                server_port = int(os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "13100"))
                repository_name = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY")
                server_username = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME")
                server_password = os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD")
            
            if server_host and repository_name:
                # Use analyzeHeadless for shared import'''

if old_pattern in content:
    content = content.replace(old_pattern, new_pattern)
    with open(file_path, 'w') as f:
        f.write(content)
    print(f"Added env var fallback to {file_path}")
else:
    print(f"Pattern not found in {file_path}")
    sys.exit(1)
