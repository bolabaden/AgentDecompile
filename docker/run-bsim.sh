#!/usr/bin/env bash
# Runs BSim PostgreSQL server via Ghidra's BSimControlLaunchable.
# BSimControlLaunchable "start" handles initdb + pg_ctl start + lsh extension.
# Reads env: MAXMEM, VMARG_LIST, GHIDRA_BSIM_DATADIR.
set -euo pipefail
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
GHIDRA_BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-/ghidra/bsim_datadir}"

mkdir -p "${GHIDRA_BSIM_DATADIR}"

# Verify the PostgreSQL binary exists (compiled by make-postgres.sh during build)
PG_BIN="${GHIDRA_HOME}/Ghidra/Features/BSim/support/postgresql/bin"
if [ ! -d "${PG_BIN}" ]; then
  echo "ERROR: PostgreSQL binaries not found at ${PG_BIN}. BSim build may have failed."
  exit 1
fi

echo "Starting BSim server (datadir=${GHIDRA_BSIM_DATADIR})..."
exec "${GHIDRA_HOME}/support/launch.sh" fg jdk BSimControl "${MAXMEM}" "${VMARG_LIST} -Xshare:off" \
  ghidra.features.bsim.query.BSimControlLaunchable start "${GHIDRA_BSIM_DATADIR}"
