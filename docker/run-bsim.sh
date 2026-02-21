#!/usr/bin/env bash
# Runs BSim server; reads env (MAXMEM, VMARG_LIST, GHIDRA_BSIM_DATADIR) so supervisord.conf needs no env expansion.
set -euo pipefail
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
GHIDRA_BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-/ghidra/bsim_datadir}"

exec "${GHIDRA_HOME}/support/launch.sh" fg jdk BSimControl "${MAXMEM}" "${VMARG_LIST} -Xshare:off" \
  ghidra.features.bsim.query.BSimControlLaunchable start "${GHIDRA_BSIM_DATADIR}"
