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
export AGENT_DECOMPILE_PROJECT_PATH="${AGENT_DECOMPILE_PROJECT_PATH:-}"

GHIDRA_BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-${BSIM_DATADIR:-/ghidra/bsim_datadir}}"
GHIDRA_REPOS_DIR="${GHIDRA_REPOS_DIR:-/ghidra/repositories}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
GHIDRA_IP="${GHIDRA_IP:-}"
export GHIDRA_BSIM_DATADIR GHIDRA_HOME

mkdir -p "${PROJECT_DIR}" /work "${GHIDRA_BSIM_DATADIR}" "${GHIDRA_REPOS_DIR}"

if [[ -n "${GHIDRA_IP}" ]]; then
	SERVER_CONF="${GHIDRA_HOME}/server/server.conf"
	if [[ -f "${SERVER_CONF}" ]]; then
		sed -i 's|^wrapper.app.parameter.1=.*|wrapper.app.parameter.1=-a0|' "${SERVER_CONF}"
		sed -i 's|^wrapper.app.parameter.2=.*|wrapper.app.parameter.2=-ip|' "${SERVER_CONF}"
		if grep -q '^wrapper.app.parameter.3=' "${SERVER_CONF}"; then
			sed -i "s|^wrapper.app.parameter.3=.*|wrapper.app.parameter.3=${GHIDRA_IP}|" "${SERVER_CONF}"
		else
			echo "wrapper.app.parameter.3=${GHIDRA_IP}" >> "${SERVER_CONF}"
		fi
		if grep -q '^wrapper.app.parameter.4=' "${SERVER_CONF}"; then
			sed -i 's|^wrapper.app.parameter.4=.*|wrapper.app.parameter.4=${ghidra.repositories.dir}|' "${SERVER_CONF}"
		else
			echo 'wrapper.app.parameter.4=${ghidra.repositories.dir}' >> "${SERVER_CONF}"
		fi
	fi
fi

# Avoid "tail: can't open '.../ghidra_*/application.log': No such file or directory" if any
# script (e.g. from the Ghidra distro) runs tail -f on that path. Create a stub so tail succeeds.
mkdir -p /home/ghidra/.config/ghidra/ghidra_headless
touch /home/ghidra/.config/ghidra/ghidra_headless/application.log

# Canonical log line so logs are recognizable
echo "[supervisor] AIO starting: ghidra-server (1) -> bsim-server (2) -> agentdecompile-mcp (3); MCP waits for Ghidra then connects."

exec supervisord -n -c /ghidra/docker/supervisord.conf
