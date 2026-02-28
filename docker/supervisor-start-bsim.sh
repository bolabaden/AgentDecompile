#!/usr/bin/env bash
# Starts embedded BSim server (Ghidra BSimControl) and streams its logfile.
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-${GHIDRA_HOME}/bsim_datadir}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true -Xshare:off}}"

mkdir -p "${BSIM_DATADIR}"

"${GHIDRA_HOME}/support/launch.sh" fg jdk BSimControl "${MAXMEM}" "${VMARG_LIST}" \
  ghidra.features.bsim.query.BSimControlLaunchable start "${BSIM_DATADIR}"

while [ ! -f "${BSIM_DATADIR}/logfile" ]; do
  sleep 1
done

exec tail -F "${BSIM_DATADIR}/logfile"
