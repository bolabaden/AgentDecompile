#!/usr/bin/env python3
"""Create Ghidra repository using the same code path as the backend."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator  # pyright: ignore

server_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 13100
username = sys.argv[3] if len(sys.argv) > 3 else "ghidra"
password = sys.argv[4] if len(sys.argv) > 4 else "admin"
repo_name = sys.argv[5] if len(sys.argv) > 5 else "agentrepo"

print(f"Connecting to {server_host}:{server_port} as {username}...")
try:
    ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, password))
    server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, True)
    if not server_adapter.isConnected():
        server_adapter.connect()
    
    print(f"Listing existing repositories...")
    existing = list(server_adapter.getRepositoryNames() or [])
    print(f"Found {len(existing)} repositories: {existing}")
    
    if repo_name in existing:
        print(f"Repository '{repo_name}' already exists")
    else:
        print(f"Creating repository '{repo_name}'...")
        created = server_adapter.createRepository(repo_name)
        if created is None:
            # Check if it was created
            existing_after = list(server_adapter.getRepositoryNames() or [])
            if repo_name in existing_after:
                print(f"Repository '{repo_name}' created successfully")
            else:
                print(f"Failed to create repository '{repo_name}'")
                sys.exit(1)
        else:
            print(f"Repository '{repo_name}' created successfully")
    
    print("Done.")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
