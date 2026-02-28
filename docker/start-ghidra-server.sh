#!/usr/bin/env bash
set -euo pipefail

MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
export MAXMEM VMARG_LIST

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

if [[ -n "${GHIDRA_IP}" ]]; then
    echo "Using GHIDRA_IP=${GHIDRA_IP} for repository server remote address"
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

exec /ghidra/server/ghidraSvr console
