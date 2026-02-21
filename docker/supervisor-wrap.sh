#!/usr/bin/env bash
# Prefixes every line of command output with [tag] for readable interleaved logs.
# Usage: supervisor-wrap.sh <tag> <command> [args...]
set -euo pipefail
TAG="${1:?}"
shift
"$@" 2>&1 | while IFS= read -r line; do
  printf '[%s] %s\n' "$TAG" "$line"
done
exit "${PIPESTATUS[0]:-0}"
