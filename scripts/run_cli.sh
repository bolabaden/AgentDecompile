#!/usr/bin/env bash
# Run AgentDecompile Python CLI (foreground)
GHIDRA_PATH=${1:-$GHIDRA_INSTALL_DIR}
VENV_PY=${2:-.venv/bin/python}

if [ -n "$GHIDRA_PATH" ]; then
  export GHIDRA_INSTALL_DIR="$GHIDRA_PATH"
fi

exec "$VENV_PY" -m agentdecompile_cli --verbose
