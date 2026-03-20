#!/usr/bin/env python3
"""Create a Ghidra repository via the server API."""
import sys
from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator  # pyright: ignore

server_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 13100
username = sys.argv[3] if len(sys.argv) > 3 else "ghidra"
password = sys.argv[4] if len(sys.argv) > 4 else "admin"
repo_name = sys.argv[5] if len(sys.argv) > 5 else "agentrepo"

print(f"Connecting to {server_host}:{server_port} as {username}...")
ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, password))
server_adapter = ClientUtil.getRepositoryServer(server_host, server_port, True)
if not server_adapter.isConnected():
    server_adapter.connect()

print(f"Creating repository '{repo_name}'...")
created = server_adapter.createRepository(repo_name)
if created:
    print(f"Repository '{repo_name}' created successfully")
else:
    existing = server_adapter.getRepository(repo_name)
    if existing:
        print(f"Repository '{repo_name}' already exists")
    else:
        print(f"Failed to create repository '{repo_name}'")
        sys.exit(1)

print("Done.")
