#!/usr/bin/env bash
# Chain enrich-decompile then proof-scale smoke (background-friendly).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/bin:${PATH}"
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/.local/opt/ghidra/current}"
export WINEPREFIX="${WINEPREFIX:-${ROOT}/target/wine-smoke-prefix}"
export VC_ROOT="${VC_ROOT:-/run/media/brunner56/MyBook/Toolchains/msvc8.0-main}"

TARGET="${TARGET:-/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/swkotor/swkotor.exe}"
WORK="${WORK:-${ROOT}/target/agentdecompile-reconstruct/swkotor-parity}"
LOG="${LOG:-${WORK}/state/enrich-smoke-run.log}"
RUN_TAG="${RUN_TAG:-run-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1

echo "=== ${RUN_TAG} enrich-then-smoke start $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "TARGET=$TARGET"
echo "WORK=$WORK"
echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"

echo "--- phase 1: enrich-decompile ---"
set +e
uv run agentdecompile-reconstruct "$TARGET" \
  --work-dir "$WORK" \
  --resume \
  --stop-after enrich-decompile
ENRICH_RC=$?
set -e
echo "enrich-decompile exit=$ENRICH_RC $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ -f "${WORK}/facts/enrich-receipt.json" ]]; then
  echo "enrich-receipt status:"
  python3 -c "import json; print(json.load(open('${WORK}/facts/enrich-receipt.json')).get('status'))" || true
fi

if [[ $ENRICH_RC -ne 0 ]]; then
  echo "WARN: enrich-decompile failed (rc=$ENRICH_RC); continuing to smoke anyway"
fi

echo "--- phase 2: proof-scale smoke ---"
set +e
uv run python scripts/run-proof-scale-smoke.py
SMOKE_RC=$?
set -e
echo "smoke exit=$SMOKE_RC $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ -f "${WORK}/state/proof-campaign-loop.json" ]]; then
  echo "proof-campaign-loop:"
  python3 -c "import json; r=json.load(open('${WORK}/state/proof-campaign-loop.json')); print('status=', r.get('status'), 'numeratorDelta=', r.get('numeratorDelta'), 'campaignCount=', r.get('campaignCount'))" || true
fi

echo "=== ${RUN_TAG} enrich-then-smoke done enrich_rc=$ENRICH_RC smoke_rc=$SMOKE_RC ==="
exit $SMOKE_RC
