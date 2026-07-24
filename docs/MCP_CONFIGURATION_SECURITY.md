# MCP Configuration Security Guide

## Overview

This guide explains how to configure the MCP (Model Context Protocol) client for AgentDecompile without hardcoding credentials or sensitive server details.

## Security Best Practices

**❌ NEVER hardcode credentials in your `mcp.json` configuration file**

Instead, use dynamic input prompts that request credentials at runtime.

## Configuration Approach

### Using Input Prompts (Recommended)

MCP supports dynamic input prompts using the `{input:input-id}` syntax. This allows you to:
- Keep credentials out of configuration files
- Prompt users securely at connection time
- Mark password inputs as sensitive

### Example: Secure Configuration

See [`mcp.example.json`](./mcp.example.json) for a complete secure configuration template.

#### Key Features:

1. **Dynamic Inputs Definition**:
   ```json
   "inputs": [
     {
       "id": "ghidra-username",
       "type": "promptString",
       "description": "Ghidra shared server username"
     },
     {
       "id": "ghidra-password",
       "type": "promptString",
       "description": "Ghidra shared server password",
       "password": true
     }
   ]
   ```

2. **Input References in Server Config**:
   ```json
   "agdec-http-mcp-shared": {
     "type": "http",
     "url": "http://{input:ad-http-host}:{input:ad-http-port}",
     "headers": {
       "X-Agent-Server-Password": "{input:ghidra-password}",
       "X-Agent-Server-Username": "{input:ghidra-username}"
     }
   }
   ```

3. **Environment Variable Passthrough**:
   ```json
   "agdec-stdio-mcp-shared": {
     "type": "stdio",
     "env": {
       "AGENTDECOMPILE_GHIDRA_SERVER_HOST": "{input:ad-http-ghidra-server-host}",
       "AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD": "{input:ghidra-password}",
       "AGENTDECOMPILE_GHIDRA_SERVER_USERNAME": "{input:ghidra-username}"
     }
   }
   ```

## Available Input Parameters

| Input ID | Description | Default | Required |
|----------|-------------|---------|----------|
| `ghidra-username` | Ghidra server username | - | Yes |
| `ghidra-password` | Ghidra server password | - | Yes |
| `ghidra-repository` | Repository name | `MyRepository` | No |
| `ad-http-host` | AgentDecompile HTTP host | `localhost` | No |
| `ad-http-port` | AgentDecompile HTTP port | `8080` | No |
| `ad-http-ghidra-server-host` | Ghidra server host | `localhost` | No |
| `ad-http-ghidra-server-port` | Ghidra server port | `13100` | No |

## Setup Instructions

### 1. Copy Example Configuration

```bash
cp docs/mcp.example.json ~/.config/mcp/mcp.json
```

*(Adjust path based on your MCP client location)*

### 2. Customize Defaults (Optional)

Edit the `inputs` section to set appropriate defaults for your environment:

```json
{
  "id": "ad-http-host",
  "type": "promptString",
  "description": "AgentDecompile HTTP server host",
  "default": "your-server.example.com"
}
```

### 3. Start MCP Client

The MCP client will prompt you for required inputs when connecting to AgentDecompile servers.

## Alternative: Environment Variables Only

If you prefer pure environment variable configuration without prompts, use the CLI directly:

```bash
export AGENT_DECOMPILE_GHIDRA_SERVER_HOST="your-host"
export AGENT_DECOMPILE_GHIDRA_SERVER_PORT="13100"
export AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME="your-username"
export AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD="your-password"
export AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY="your-repo"

agentdecompile-server --transport stdio
```

See [USAGE.md](../USAGE.md) for complete CLI documentation.

## Migration from Hardcoded Credentials

If you have an existing `mcp.json` with hardcoded credentials:

1. **Backup your current config**:
   ```bash
   cp mcp.json mcp.json.backup
   ```

2. **Replace hardcoded values** with `{input:...}` references:
   - IP addresses → `{input:ad-http-host}` or `{input:ad-http-ghidra-server-host}`
   - Usernames → `{input:ghidra-username}`
   - Passwords → `{input:ghidra-password}`
   - Repository names → `{input:ghidra-repository}`
   - Port numbers → `{input:ad-http-port}` or `{input:ad-http-ghidra-server-port}`

3. **Add input definitions** to the `inputs` array (see example above)

4. **Test the configuration** by reconnecting your MCP client

## Security Checklist

- [ ] No hardcoded passwords in `mcp.json`
- [ ] No hardcoded usernames in `mcp.json`
- [ ] No hardcoded IP addresses or hostnames in `mcp.json` (unless public/localhost)
- [ ] Password inputs marked with `"password": true`
- [ ] Configuration file not committed to version control
- [ ] Default values are generic (localhost, MyRepository, etc.)

## Related Documentation

- [MCP AgentDecompile Usage Guide](./MCP_AGENTDECOMPILE_USAGE.md)
- [General Usage Documentation](../USAGE.md)
- [Quick Start Import/Export Guide](./QUICKSTART_IMPORT_EXPORT.md)
