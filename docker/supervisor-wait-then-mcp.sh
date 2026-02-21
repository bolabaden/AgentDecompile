#!/usr/bin/env bash
# Waits for Ghidra server to bind, then starts AgentDecompile MCP so it can connect to Ghidra.
# Ensures MCP (headless) starts only after Ghidra server is up.
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
# Ghidra server default port (see https://github.com/NationalSecurityAgency/ghidra/blob/main/docker/README.md)
GHIDRA_SERVER_PORT="${GHIDRA_SERVER_PORT1:-13100}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
CONFIG_FILE="${AGENT_DECOMPILE_CONFIG_FILE:-}"

# Wait for Ghidra server so MCP can connect to shared repos. Portable: try nc then /dev/tcp then fixed sleep.
wait_for_ghidra() {
  local port="$1"
  local max="${2:-60}"
  local i=0
  # Prefer nc (Alpine often has netcat-openbsd or busybox nc)
  if command -v nc >/dev/null 2>&1; then
    while [ "$i" -lt "$max" ]; do
      if nc -z 127.0.0.1 "$port" 2>/dev/null; then return 0; fi
      i=$((i + 1)); sleep 1
    done
    return 1
  fi
  # Bash with net redirections
  if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then return 0; fi
  while [ "$i" -lt "$max" ]; do
    if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then return 0; fi
    i=$((i + 1)); sleep 1
  done
  return 1
}

if ! wait_for_ghidra "$GHIDRA_SERVER_PORT" 60 2>/dev/null; then
  echo "WARNING: Ghidra server port $GHIDRA_SERVER_PORT not ready after 60s; starting MCP anyway (will retry connect to Ghidra when opening projects)."
fi

if [[ -n "${CONFIG_FILE}" ]]; then
  exec "${GHIDRA_HOME}/support/launch.sh" fg jdk AgentDecompile "${MAXMEM}" "${VMARG_LIST}" \
    agentdecompile.headless.AgentDecompileHeadlessLauncher "${CONFIG_FILE}"
fi
exec "${GHIDRA_HOME}/support/launch.sh" fg jdk AgentDecompile "${MAXMEM}" "${VMARG_LIST}" \
  agentdecompile.headless.AgentDecompileHeadlessLauncher
