#!/usr/bin/env bash
# Fail if banned product-brand tokens appear outside allowed paths.
# Usage: scripts/check-anonymization.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Intentional mentions in strategy/plan/NOTICE are allowed via -g excludes.
PATTERN='mizuchi|Mizuchi|MIZUCHI|reconkit|ReconstructKit|RECONKIT'
ALLOW_GLOBS=(
  -g '!NOTICE*'
  -g '!**/NOTICE*'
  -g '!**/third_party/**'
  -g '!**/LICENSE*'
  -g '!docs/plans/**'
  -g '!STRATEGY.md'
  -g '!**/.git/**'
  -g '!**/node_modules/**'
  -g '!**/__pycache__/**'
  -g '!**/target/**'
  -g '!**/*.egg-info/**'
)

HITS="$(rg -n -i "$PATTERN" src scripts tests pyproject.toml README.md AGENTS.md USAGE.md \
  -g '!scripts/check-anonymization.sh' \
  -g '!tests/test_acquisition.py' \
  "${ALLOW_GLOBS[@]}" 2>/dev/null || true)"

if [[ -n "$HITS" ]]; then
  echo "Anonymization gate FAILED — banned brand tokens found:"
  echo "$HITS"
  exit 1
fi

echo "Anonymization gate OK"
