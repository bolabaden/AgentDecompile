#!/usr/bin/env bash
set -euo pipefail

MAXMEM="${MAXMEM:=2G}"
VMARG_LIST="${VMARG_LIST:=-Djava.awt.headless=true}"
CONFIG_FILE="${AGENT_DECOMPILE_CONFIG_FILE:-}"

PROJECT_DIR="${AGENT_DECOMPILE_PROJECT_DIR:=/projects}"
PROJECT_NAME="${AGENT_DECOMPILE_PROJECT_NAME:=agentdecompile}"
HOST="${AGENT_DECOMPILE_HOST:=0.0.0.0}"
PORT="${AGENT_DECOMPILE_PORT:=8080}"

mkdir -p "${PROJECT_DIR}" /work

echo "Starting AgentDecompile MCP server"
echo "  host: ${HOST}"
echo "  port: ${PORT}"
echo "  project: ${PROJECT_DIR}/${PROJECT_NAME}"

if [[ -n "${CONFIG_FILE}" ]]; then
  exec /ghidra/support/launch.sh fg jdk AgentDecompile "${MAXMEM}" "${VMARG_LIST}" \
    agentdecompile.headless.AgentDecompileHeadlessLauncher "${CONFIG_FILE}"
fi

exec /ghidra/support/launch.sh fg jdk AgentDecompile "${MAXMEM}" "${VMARG_LIST}" \
  agentdecompile.headless.AgentDecompileHeadlessLauncher
