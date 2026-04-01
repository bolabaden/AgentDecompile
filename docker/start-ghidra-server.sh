#!/usr/bin/env bash
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

GHIDRA_REPOS_DIR="${GHIDRA_REPOS_DIR:-/ghidra/repositories}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
GHIDRA_IP="${GHIDRA_IP:-}"
export GHIDRA_HOME

if [[ -z "${GHIDRA_IP}" ]]; then
    GHIDRA_IP="$({
        python3 - <<'PY'
import socket
import urllib.request

for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
    try:
        with urllib.request.urlopen(url, timeout=2.5) as response:
            value = response.read().decode().strip()
            if value:
                print(value)
                break
    except Exception:
        pass
else:
    try:
        print(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
PY
    } | tr -d '\r')"
fi

mkdir -p "${GHIDRA_REPOS_DIR}"

SERVER_CONF="${GHIDRA_HOME}/server/server.conf"
if [[ -f "${SERVER_CONF}" ]]; then
    if [[ -n "${GHIDRA_IP}" ]]; then
        echo "GHIDRA_IP=${GHIDRA_IP} is set, but startup no longer rewrites wrapper.app.parameter.*; configure -ip directly in ${SERVER_CONF} if you need a non-default advertised address."
    fi

    # Keep container-specific wrapper settings without changing Ghidra's auth or port arguments.
    set_conf_value "wrapper.logfile" "/tmp/wrapper.log" "${SERVER_CONF}"
    set_conf_value "wrapper.startup.timeout" "300" "${SERVER_CONF}"
fi

exec /ghidra/server/ghidraSvr console
