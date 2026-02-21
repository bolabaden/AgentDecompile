#!/usr/bin/env bash
# Runs BSim PostgreSQL server via Ghidra's BSimControlLaunchable.
# BSimControlLaunchable "start" handles initdb + pg_ctl start + lsh extension.
# make-postgres.sh installs to Ghidra/Features/BSim/build/os/<OSDIR>/postgresql (see make-postgres.sh).
set -euo pipefail
# BSim PostgreSQL is linked against LibreSSL (libssl.so.60, libcrypto.so.57); use libs copied from build stage
export LD_LIBRARY_PATH="/opt/bsim-libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true}}"
GHIDRA_BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-/ghidra/bsim_datadir}"
BSIM_ROOT="${GHIDRA_HOME}/Ghidra/Features/BSim"

mkdir -p "${GHIDRA_BSIM_DATADIR}"

# Path where make-postgres.sh installs PostgreSQL (same logic as make-postgres.sh)
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)  OSDIR="linux_x86_64" ;;
  aarch64) OSDIR="linux_arm_64" ;;
  *)       OSDIR="linux_${ARCH}" ;;
esac
PG_BIN="${BSIM_ROOT}/build/os/${OSDIR}/postgresql/bin"
if [ ! -d "${PG_BIN}" ] || [ ! -x "${PG_BIN}/postgres" ]; then
  echo "ERROR: PostgreSQL binaries not found at ${PG_BIN}. Run make-postgres.sh in the image build (BSim layer)."
  exit 1
fi

echo "Starting BSim server (datadir=${GHIDRA_BSIM_DATADIR})..."
exec "${GHIDRA_HOME}/support/launch.sh" fg jdk BSimControl "${MAXMEM}" "${VMARG_LIST} -Xshare:off" \
  ghidra.features.bsim.query.BSimControlLaunchable start "${GHIDRA_BSIM_DATADIR}"
