#!/usr/bin/env python3
"""Direct test of MCP tool analysis workflow"""
import subprocess
import json
import os

# Set environment for connection to backend
env = os.environ.copy()
env['AGENT_DECOMPILE_SERVER_HOST'] = '170.9.241.140'
env['AGENT_DECOMPILE_SERVER_PORT'] = '13100'
env['AGENT_DECOMPILE_SERVER_USERNAME'] = 'OpenKotOR'
env['AGENT_DECOMPILE_SERVER_PASSWORD'] = 'MuchaShakaPaka'
env['AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY'] = 'Odyssey'
env['AGENT_DECOMPILE_BACKEND_URL'] = 'http://170.9.241.140:8080'

BACKEND_URL = 'http://170.9.241.140:8080'
PROGRAM_PATH = '/K1/k1_win_gog_swkotor.exe'

def run_cmd(description, cmd, timeout=120):
    print(f"\n{'='*80}")
    print(f"{description}")
    print(f"{'='*80}")
    print(f"Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            shell=False
        )
        if result.returncode == 0:
            print(f"✓ SUCCESS")
            try:
                # Try to parse JSON output if present
                if result.stdout.strip().startswith('{'):
                    data = json.loads(result.stdout)
                    print(json.dumps(data, indent=2)[:500])  # Print first 500 chars
                else:
                    print(result.stdout[:500])
            except:
                print(result.stdout[:500])
        else:
            print(f"✗ FAILED (exit code: {result.returncode})")
            print(f"STDERR: {result.stderr[:500]}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"✗ TIMEOUT after {timeout}s")
        return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

# Step 1: Open the program
success = run_cmd(
    "Step 1: Open program from shared server",
    [
        'uv', 'run', 'agentdecompile-cli',
        '--server-url', BACKEND_URL,
        'open',
        '--server_host', '170.9.241.140',
        '--server_port', '13100',
        '--server_username', 'OpenKotOR',
        '--server_password', 'MuchaShakaPaka',
        PROGRAM_PATH
    ],
    timeout=60
)

if not success:
    print("\n⚠ Failed to open program. Trying without server credentials...")
    run_cmd(
        "Step 1b: Open program (attempt 2)",
        ['uv', 'run', 'agentdecompile-cli', '--server-url', BACKEND_URL, 'list', 'project-files'],
        timeout=30
    )
else:
    # Step 2: List functions
    run_cmd(
        "Step 2: List functions",
        [
            'uv', 'run', 'agentdecompile-cli',
            '--server-url', BACKEND_URL,
            'get-functions',
            '--program_path', PROGRAM_PATH,
            '--limit', '10'
        ]
    )

    # Step 3: List structures
    run_cmd(
        "Step 3: List structures",
        [
            'uv', 'run', 'agentdecompile-cli',
            '--server-url', BACKEND_URL,
            'tool', 'manage-structures',
            json.dumps({'action': 'list', 'programPath': PROGRAM_PATH, 'limit': 10})
        ]
    )

    # Step 4: List comments
    run_cmd(
        "Step 4: Search comments",
        [
            'uv', 'run', 'agentdecompile-cli',
            '--server-url', BACKEND_URL,
            'tool', 'manage-comments',
            json.dumps({'action': 'search', 'programPath': PROGRAM_PATH, 'searchText': '.', 'limit': 10})
        ]
    )

    # Step 5: List symbols/labels
    run_cmd(
        "Step 5: List symbols",
        [
            'uv', 'run', 'agentdecompile-cli',
            '--server-url', BACKEND_URL,
            'tool', 'manage-symbols',
            json.dumps({'mode': 'symbols', 'programPath': PROGRAM_PATH, 'limit': 10})
        ]
    )

    # Step 6: Get first function and try to match it in another program
    print("\n" + "="*80)
    print("Step 6: Get functions for matching")
    print("="*80)
    result = subprocess.run(
        [
            'uv', 'run', 'agentdecompile-cli',
            '--server-url', BACKEND_URL,
            'get-functions',
            '--program_path', PROGRAM_PATH,
            '--limit', '1'
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60
    )
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            funcs = data.get('functions', [])
            if funcs:
                first_func = funcs[0]
                func_name = first_func.get('name', first_func.get('address', 'unknown'))
                print(f"Found function: {func_name}")
                print(f"Function details: {json.dumps(first_func, indent=2)[:300]}")
            else:
                print("No functions found")
        except Exception as e:
            print(f"Error parsing functions: {e}")
            print(result.stdout[:300])

print("\n" + "="*80)
print("Analysis complete")
print("="*80)
