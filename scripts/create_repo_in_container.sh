#!/bin/sh
# Create Ghidra repository using PyGhidra from inside the container
python3 << 'PYEOF'
import sys
sys.path.insert(0, '/ghidra/Ghidra/Features/PyGhidra/pypkg')
from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator

server_host = "127.0.0.1"
server_port = 13100
username = "ghidra"
password = "admin"
repo_name = "agentrepo"

print(f"Connecting to {server_host}:{server_port} as {username}...")
ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, password))
server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, True)
if not server_adapter.isConnected():
    server_adapter.connect()

print("Listing existing repositories...")
existing = list(server_adapter.getRepositoryNames() or [])
print(f"Found {len(existing)} repositories: {existing}")

if repo_name in existing:
    print(f"Repository '{repo_name}' already exists")
else:
    print(f"Creating repository '{repo_name}'...")
    created = server_adapter.createRepository(repo_name)
    if created is None:
        existing_after = list(server_adapter.getRepositoryNames() or [])
        if repo_name in existing_after:
            print(f"Repository '{repo_name}' created successfully")
        else:
            print(f"Failed to create repository '{repo_name}'")
            sys.exit(1)
    else:
        print(f"Repository '{repo_name}' created successfully")

print("Done.")
PYEOF
