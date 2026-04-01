#!/usr/bin/env bash
# AIO: supervisord runs ghidra-server, bsim-server, and agentdecompile-mcp (headless).
# Both log with [program-name] prefix for readable interleaved output.
# MCP waits for Ghidra + BSim so it can connect to shared services.
#
# NOTE: The entrypoint auto-detects the RMI hostname for ghidra-server
# (same logic as entrypoint-ghidra.sh).  To override, either:
#   - Add -ip manually to volumes/ghidra/server.conf wrapper.app.parameter
#   - Set GHIDRA_IP=<addr> env var (explicit IP/hostname/FQDN)
#   - Set GHIDRA_IP=* to disable auto-detection (for --net host)
set -euo pipefail

MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
export MAXMEM VMARG_LIST

CONFIG_FILE="${AGENT_DECOMPILE_CONFIG_FILE:-}"
PROJECT_DIR="${AGENT_DECOMPILE_PROJECT_DIR:=/projects}"
PROJECT_NAME="${AGENT_DECOMPILE_PROJECT_NAME:=agentdecompile}"
export AGENT_DECOMPILE_PROJECT_PATH="${AGENT_DECOMPILE_PROJECT_PATH:-}"

GHIDRA_REPOS_DIR="${GHIDRA_REPOS_DIR:-/ghidra/repositories}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
export GHIDRA_HOME

mkdir -p "${PROJECT_DIR}" /work "${GHIDRA_REPOS_DIR}"

# Avoid "tail: can't open '.../ghidra_*/application.log': No such file or directory" if any
# script (e.g. from the Ghidra distro) runs tail -f on that path. Create a stub so tail succeeds.
mkdir -p /home/ghidra/.config/ghidra/ghidra_headless
touch /home/ghidra/.config/ghidra/ghidra_headless/application.log

# Canonical log line so logs are recognizable
echo "[supervisor] AIO starting: ghidra-server (1) -> bsim-server (2) -> agentdecompile-mcp (3); MCP waits for Ghidra + BSim then connects."

# ---- Auto-detect RMI hostname for Docker (same logic as entrypoint-ghidra.sh) ----
CONF="/ghidra/server/server.conf"
if [ -f "$CONF" ] && ! grep -qE '^\s*wrapper\.app\.parameter\.[0-9]+=-ip' "$CONF" 2>/dev/null; then
	RESOLVED_IP="${GHIDRA_IP:-}"
	if [[ -z "$RESOLVED_IP" ]]; then
		RESOLVED_IP=$(getent hosts host.docker.internal 2>/dev/null | awk '{print $1}' | head -1)
		if [[ -z "$RESOLVED_IP" ]]; then
			RESOLVED_IP=$(hostname -i 2>/dev/null | awk '{print $1}')
		fi
	fi
	if [[ -n "$RESOLVED_IP" && "$RESOLVED_IP" != "*" ]]; then
		sed -i '/^# AUTO-IP-BEGIN$/,/^# AUTO-IP-END$/d' "$CONF" 2>/dev/null || true
		REPO_NUM=$(grep -oP 'wrapper\.app\.parameter\.\K[0-9]+(?==\$\{ghidra\.repositories\.dir\})' "$CONF" | head -1)
		if [[ -n "$REPO_NUM" ]]; then
			sed -i "/^wrapper\.app\.parameter\.${REPO_NUM}=.*ghidra\.repositories\.dir.*/d" "$CONF"
			IP_NUM=$REPO_NUM
		else
			MAX_P=$(grep -oP 'wrapper\.app\.parameter\.\K[0-9]+' "$CONF" 2>/dev/null | sort -n | tail -1)
			IP_NUM=$(( ${MAX_P:-0} + 1 ))
		fi
		{
			echo "# AUTO-IP-BEGIN"
			echo "wrapper.app.parameter.${IP_NUM}=-ip"
			echo "wrapper.app.parameter.$(( IP_NUM + 1 ))=${RESOLVED_IP}"
			echo "wrapper.app.parameter.$(( IP_NUM + 2 ))=\${ghidra.repositories.dir}"
			echo "# AUTO-IP-END"
		} >> "$CONF"
		echo "[entrypoint] Auto-configured RMI hostname: ${RESOLVED_IP}"
	fi
fi

exec supervisord -n -c /ghidra/docker/supervisord.conf
