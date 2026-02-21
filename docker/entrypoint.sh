#!/usr/bin/env bash
# AIO: supervisord runs ghidra-server, bsim-server, agentdecompile-mcp (headless).
# All three log with [program-name] prefix for readable interleaved output.
# MCP waits for Ghidra server so it can connect to shared repos.
set -euo pipefail

MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
export MAXMEM VMARG_LIST

CONFIG_FILE="${AGENT_DECOMPILE_CONFIG_FILE:-}"
PROJECT_DIR="${AGENT_DECOMPILE_PROJECT_DIR:=/projects}"
PROJECT_NAME="${AGENT_DECOMPILE_PROJECT_NAME:=agentdecompile}"
export AGENT_DECOMPILE_PROJECT_PATH="${AGENT_DECOMPILE_PROJECT_PATH:-${PROJECT_DIR}/${PROJECT_NAME}.gpr}"

GHIDRA_BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-${BSIM_DATADIR:-/ghidra/bsim_datadir}}"
GHIDRA_REPOS_DIR="${GHIDRA_REPOS_DIR:-/ghidra/repositories}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
export GHIDRA_BSIM_DATADIR GHIDRA_HOME

mkdir -p "${PROJECT_DIR}" /work "${GHIDRA_BSIM_DATADIR}" "${GHIDRA_REPOS_DIR}"

# Avoid "tail: can't open '.../ghidra_*/application.log': No such file or directory" if any
# script (e.g. from the Ghidra distro) runs tail -f on that path. Create a stub so tail succeeds.
mkdir -p /home/ghidra/.config/ghidra/ghidra_headless
touch /home/ghidra/.config/ghidra/ghidra_headless/application.log

# Canonical log line so logs are recognizable
echo "[supervisor] AIO starting: ghidra-server (1) -> bsim-server (2) -> agentdecompile-mcp (3); MCP waits for Ghidra then connects."

exec supervisord -n -c /ghidra/docker/supervisord.conf
