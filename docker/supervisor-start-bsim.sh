#!/usr/bin/env bash
# Starts embedded BSim server (Ghidra BSimControl) and streams its logfile.
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/ghidra}"
BSIM_DATADIR="${GHIDRA_BSIM_DATADIR:-${GHIDRA_HOME}/bsim_datadir}"
MAXMEM="${AGENT_DECOMPILE_MAXMEM:=${MAXMEM:=2G}}"
VMARG_LIST="${AGENT_DECOMPILE_VMARG_LIST:=${VMARG_LIST:=-Djava.awt.headless=true -Xshare:off}}"
BSIM_ROOT="${GHIDRA_HOME}/Ghidra/Features/BSim"

mkdir -p "${BSIM_DATADIR}"

# Resolve PostgreSQL bin path built by make-postgres.sh
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)  OSDIR="linux_x86_64" ;;
  aarch64) OSDIR="linux_arm_64" ;;
  *)       OSDIR="linux_${ARCH}" ;;
esac
PG_BIN="${BSIM_ROOT}/build/os/${OSDIR}/postgresql/bin"

if [ ! -d "${PG_BIN}" ] || [ ! -x "${PG_BIN}/pg_ctl" ]; then
  echo "ERROR: PostgreSQL binaries not found at ${PG_BIN}."
  exit 1
fi

# If postmaster.pid exists but process is gone, remove stale pid file so startup can recover.
if [ -f "${BSIM_DATADIR}/postmaster.pid" ]; then
  pid="$(head -n 1 "${BSIM_DATADIR}/postmaster.pid" 2>/dev/null || true)"
  if [ -n "${pid}" ] && ! kill -0 "${pid}" 2>/dev/null; then
    echo "Removing stale postmaster.pid (pid=${pid}) from ${BSIM_DATADIR}"
    rm -f "${BSIM_DATADIR}/postmaster.pid"
  fi
fi

if "${PG_BIN}/pg_ctl" -D "${BSIM_DATADIR}" status >/dev/null 2>&1; then
  echo "BSim PostgreSQL already running (datadir=${BSIM_DATADIR}); skipping duplicate start."
else
  "${GHIDRA_HOME}/support/launch.sh" fg jdk BSimControl "${MAXMEM}" "${VMARG_LIST}" \
    ghidra.features.bsim.query.BSimControlLaunchable start "${BSIM_DATADIR}"
fi

while [ ! -f "${BSIM_DATADIR}/logfile" ]; do
  sleep 1
done

exec tail -F "${BSIM_DATADIR}/logfile"
