#!/usr/bin/env bash
# AIO: supervisord runs ghidra-server, bsim-server, and agentdecompile-mcp (headless).
# Both log with [program-name] prefix for readable interleaved output.
# MCP waits for Ghidra + BSim so it can connect to shared services.
set -euo pipefail

MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
export MAXMEM VMARG_LIST

set_conf_value() {
	local key="$1"
	local value="$2"
	local conf_path="$3"

	if grep -q "^${key}=" "${conf_path}"; then
		sed -i "s|^${key}=.*|${key}=${value}|" "${conf_path}"
	else
		echo "${key}=${value}" >> "${conf_path}"
	fi
}

CONFIG_FILE="${AGENT_DECOMPILE_CONFIG_FILE:-}"
PROJECT_DIR="${AGENT_DECOMPILE_PROJECT_DIR:=/projects}"
PROJECT_NAME="${AGENT_DECOMPILE_PROJECT_NAME:=agentdecompile}"
export AGENT_DECOMPILE_PROJECT_PATH="${AGENT_DECOMPILE_PROJECT_PATH:-}"

GHIDRA_REPOS_DIR="${GHIDRA_REPOS_DIR:-/ghidra/repositories}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
GHIDRA_IP="${GHIDRA_IP:-}"
export GHIDRA_HOME

# Resolve GHIDRA_IP: explicit env → container interface IP → hostname fallback.
# Previous logic tried public-IP services (ipify, ifconfig.me) which is wrong for
# Docker networking — we need the container's own IP that peers can reach.
if [[ -z "${GHIDRA_IP}" ]]; then
	GHIDRA_IP="$(hostname -i 2>/dev/null | awk '{print $1}')" || true
	if [[ -z "${GHIDRA_IP}" ]]; then
		GHIDRA_IP="$(python3 -c 'import socket; print(socket.gethostbyname(socket.gethostname()))' 2>/dev/null)" || true
	fi
fi

mkdir -p "${PROJECT_DIR}" /work "${GHIDRA_REPOS_DIR}"

SERVER_CONF="${GHIDRA_HOME}/server/server.conf"
if [[ -f "${SERVER_CONF}" ]]; then
	# Keep container-specific wrapper settings without changing Ghidra's auth or port arguments.
	set_conf_value "wrapper.logfile" "/tmp/wrapper.log" "${SERVER_CONF}"
	set_conf_value "wrapper.startup.timeout" "300" "${SERVER_CONF}"

	# Inject -ip <address> into wrapper.app.parameter so the RMI registry advertises
	# a reachable address.  Without this, RMI stubs contain the container's internal
	# hostname (often a random container-id) which external clients cannot resolve.
	if [[ -n "${GHIDRA_IP}" ]]; then
		if ! grep -q '^wrapper\.app\.parameter\.[0-9]*=-ip$' "${SERVER_CONF}"; then
			echo "[supervisor] Injecting -ip ${GHIDRA_IP} into ${SERVER_CONF}"

			# Collect existing parameter values in order
			mapfile -t EXISTING_PARAMS < <(
				grep '^wrapper\.app\.parameter\.' "${SERVER_CONF}" \
					| sort -t. -k4 -n \
					| sed 's/^wrapper\.app\.parameter\.[0-9]*=//'
			)

			# Remove old parameter lines
			sed -i '/^wrapper\.app\.parameter\./d' "${SERVER_CONF}"

			# Rewrite: -ip <addr> first, then original parameters
			IDX=1
			echo "wrapper.app.parameter.${IDX}=-ip" >> "${SERVER_CONF}"
			IDX=$((IDX + 1))
			echo "wrapper.app.parameter.${IDX}=${GHIDRA_IP}" >> "${SERVER_CONF}"
			IDX=$((IDX + 1))

			for param in "${EXISTING_PARAMS[@]}"; do
				echo "wrapper.app.parameter.${IDX}=${param}" >> "${SERVER_CONF}"
				IDX=$((IDX + 1))
			done
		else
			# -ip already present – update the value in the next numbered parameter
			IP_NUM=$(grep '^wrapper\.app\.parameter\.[0-9]*=-ip$' "${SERVER_CONF}" \
						 | head -1 | sed 's/wrapper\.app\.parameter\.\([0-9]*\)=.*/\1/')
			NEXT=$((IP_NUM + 1))
			sed -i "s|^wrapper\.app\.parameter\.${NEXT}=.*|wrapper.app.parameter.${NEXT}=${GHIDRA_IP}|" "${SERVER_CONF}"
			echo "[supervisor] Updated existing -ip to ${GHIDRA_IP} in ${SERVER_CONF}"
		fi
	fi
fi

# Avoid "tail: can't open '.../ghidra_*/application.log': No such file or directory" if any
# script (e.g. from the Ghidra distro) runs tail -f on that path. Create a stub so tail succeeds.
mkdir -p /home/ghidra/.config/ghidra/ghidra_headless
touch /home/ghidra/.config/ghidra/ghidra_headless/application.log

# Canonical log line so logs are recognizable
echo "[supervisor] AIO starting: ghidra-server (1) -> bsim-server (2) -> agentdecompile-mcp (3); MCP waits for Ghidra + BSim then connects."

exec supervisord -n -c /ghidra/docker/supervisord.conf
