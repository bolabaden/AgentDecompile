#!/usr/bin/env bash
# AgentDecompile MCP server entry point.
# All server options can be configured via environment variables (Docker-friendly).
# Any extra arguments passed to the container (via CMD / docker run args) are
# appended last and take the highest precedence.
#
# Environment variable reference (mirrors agentdecompile-server CLI flags):
#
#   Core server
#     AGENT_DECOMPILE_TRANSPORT       stdio | streamable-http | sse | http  (default: streamable-http)
#     AGENT_DECOMPILE_HOST            Bind host                             (default: 0.0.0.0)
#     AGENT_DECOMPILE_PORT            Bind port                             (default: 8080)
#     AGENT_DECOMPILE_VERBOSE         true/1 = verbose logs
#
#   Project / config
#     AGENT_DECOMPILE_PROJECT_PATH    Path to .gpr file or project directory
#     AGENT_DECOMPILE_PROJECT_NAME    Project name (ignored with .gpr)       (default: my_project)
#     AGENT_DECOMPILE_CONFIG_FILE     Path to AgentDecompile config file
#
#   Proxy / backend
#     AGENT_DECOMPILE_BACKEND_URL     Forward all MCP requests to a remote MCP server (proxy mode)
#     AGENT_DECOMPILE_MCP_SERVER_URL  Alias for AGENT_DECOMPILE_BACKEND_URL
#
#   Ghidra shared-project server
#     AGENT_DECOMPILE_GHIDRA_SERVER_HOST        Ghidra server host
#     AGENT_DECOMPILE_GHIDRA_SERVER_PORT        Ghidra server port         (default: 13100)
#     AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY  Repository name
#     AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME    Username
#     AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD    Password
#
#   HTTP auth
#     AGENT_DECOMPILE_REQUIRE_AUTH    true/1 = enforce; false/0 = disable; unset = auto
#
#   TLS (HTTPS)
#     AGENT_DECOMPILE_TLS_CERT        Path to PEM certificate file
#     AGENT_DECOMPILE_TLS_KEY         Path to PEM private key file
#
#   Analysis options
#     AGENT_DECOMPILE_FORCE_ANALYSIS       true/1 = re-analyse every binary
#     AGENT_DECOMPILE_VERBOSE_ANALYSIS     true/1 = verbose analysis log
#     AGENT_DECOMPILE_NO_SYMBOLS           true/1 = skip symbol loading
#     AGENT_DECOMPILE_SYMBOLS_PATH         Path to symbols directory
#     AGENT_DECOMPILE_SYM_FILE_PATH        Path to a single PDB symbol file
#     AGENT_DECOMPILE_GDT                  Colon-separated list of GDT files
#     AGENT_DECOMPILE_PROGRAM_OPTIONS      Path to JSON program-options file
#     AGENT_DECOMPILE_GZFS_PATH            GZF output path
#
#   Analysis performance
#     AGENT_DECOMPILE_MAX_WORKERS          Worker count for analysis (0 = CPU count)
#     AGENT_DECOMPILE_WAIT_FOR_ANALYSIS    true/1 = wait before serving
#     AGENT_DECOMPILE_THREADED             false/0 = disable threaded analysis
#
#   Project management (one-shot commands)
#     AGENT_DECOMPILE_LIST_PROJECT_BINARIES    true/1 = list programs and exit
#     AGENT_DECOMPILE_DELETE_PROJECT_BINARY    Program name to delete, then exit
#
#   Input binaries
#     AGENT_DECOMPILE_INPUT_PATHS   Colon-separated binary paths to import at startup
#
set -euo pipefail

# ── Core server ───────────────────────────────────────────────────────────────
ARGS=(
    -t "${AGENT_DECOMPILE_TRANSPORT:-streamable-http}"
    --host "${AGENT_DECOMPILE_HOST:-0.0.0.0}"
    --port "${AGENT_DECOMPILE_PORT:-8080}"
)

# ── Project / config ──────────────────────────────────────────────────────────
if [[ -n "${AGENT_DECOMPILE_PROJECT_PATH:-}" ]]; then
    ARGS+=(--project-path "${AGENT_DECOMPILE_PROJECT_PATH}")
fi

if [[ -n "${AGENT_DECOMPILE_PROJECT_NAME:-}" ]]; then
    ARGS+=(--project-name "${AGENT_DECOMPILE_PROJECT_NAME}")
fi

if [[ -n "${AGENT_DECOMPILE_CONFIG_FILE:-}" ]]; then
    ARGS+=(--config "${AGENT_DECOMPILE_CONFIG_FILE}")
fi

# ── Proxy / backend URL ───────────────────────────────────────────────────────
# Also read directly from env by server.py; CLI flags passed here are merged
# with server.py's own env-var reading (CMD args at the end override all).
if [[ -n "${AGENT_DECOMPILE_BACKEND_URL:-}" ]]; then
    ARGS+=(--backend-url "${AGENT_DECOMPILE_BACKEND_URL}")
elif [[ -n "${AGENT_DECOMPILE_MCP_SERVER_URL:-}" ]]; then
    ARGS+=(--mcp-server-url "${AGENT_DECOMPILE_MCP_SERVER_URL}")
fi

# ── Ghidra shared-project server ──────────────────────────────────────────────
if [[ -n "${AGENT_DECOMPILE_GHIDRA_SERVER_HOST:-}" ]]; then
    ARGS+=(--ghidra-server-host "${AGENT_DECOMPILE_GHIDRA_SERVER_HOST}")
fi

if [[ -n "${AGENT_DECOMPILE_GHIDRA_SERVER_PORT:-}" ]]; then
    ARGS+=(--ghidra-server-port "${AGENT_DECOMPILE_GHIDRA_SERVER_PORT}")
fi

if [[ -n "${AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY:-}" ]]; then
    ARGS+=(--ghidra-server-repository "${AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY}")
fi

# Credentials: pass as flags so server.py's credential sanitizer scrubs them
# from logs and process listings immediately after parsing.
if [[ -n "${AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME:-}" ]]; then
    ARGS+=(--ghidra-server-username "${AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME}")
fi

if [[ -n "${AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD:-}" ]]; then
    ARGS+=(--ghidra-server-password "${AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD}")
fi

# ── HTTP auth ─────────────────────────────────────────────────────────────────
if [[ "${AGENT_DECOMPILE_REQUIRE_AUTH:-}" == "true" || "${AGENT_DECOMPILE_REQUIRE_AUTH:-}" == "1" ]]; then
    ARGS+=(--require-auth)
elif [[ "${AGENT_DECOMPILE_REQUIRE_AUTH:-}" == "false" || "${AGENT_DECOMPILE_REQUIRE_AUTH:-}" == "0" ]]; then
    ARGS+=(--no-require-auth)
fi

# ── TLS (HTTPS) ───────────────────────────────────────────────────────────────
# Also read directly from env by server.py; pass as flags for completeness.
if [[ -n "${AGENT_DECOMPILE_TLS_CERT:-}" ]]; then
    ARGS+=(--tls-cert "${AGENT_DECOMPILE_TLS_CERT}")
fi

if [[ -n "${AGENT_DECOMPILE_TLS_KEY:-}" ]]; then
    ARGS+=(--tls-key "${AGENT_DECOMPILE_TLS_KEY}")
fi

# ── Logging ───────────────────────────────────────────────────────────────────
if [[ "${AGENT_DECOMPILE_VERBOSE:-}" == "true" || "${AGENT_DECOMPILE_VERBOSE:-}" == "1" ]]; then
    ARGS+=(--verbose)
fi

# ── Analysis options ──────────────────────────────────────────────────────────
if [[ "${AGENT_DECOMPILE_FORCE_ANALYSIS:-}" == "true" || "${AGENT_DECOMPILE_FORCE_ANALYSIS:-}" == "1" ]]; then
    ARGS+=(--force-analysis)
fi

if [[ "${AGENT_DECOMPILE_VERBOSE_ANALYSIS:-}" == "true" || "${AGENT_DECOMPILE_VERBOSE_ANALYSIS:-}" == "1" ]]; then
    ARGS+=(--verbose-analysis)
fi

if [[ "${AGENT_DECOMPILE_NO_SYMBOLS:-}" == "true" || "${AGENT_DECOMPILE_NO_SYMBOLS:-}" == "1" ]]; then
    ARGS+=(--no-symbols)
fi

if [[ -n "${AGENT_DECOMPILE_SYMBOLS_PATH:-}" ]]; then
    ARGS+=(--symbols-path "${AGENT_DECOMPILE_SYMBOLS_PATH}")
fi

if [[ -n "${AGENT_DECOMPILE_SYM_FILE_PATH:-}" ]]; then
    ARGS+=(--sym-file-path "${AGENT_DECOMPILE_SYM_FILE_PATH}")
fi

# AGENT_DECOMPILE_GDT: colon-separated list of GDT file paths
if [[ -n "${AGENT_DECOMPILE_GDT:-}" ]]; then
    IFS=':' read -ra _gdt_list <<< "${AGENT_DECOMPILE_GDT}"
    for _gdt in "${_gdt_list[@]}"; do
        [[ -n "${_gdt}" ]] && ARGS+=(--gdt "${_gdt}")
    done
fi

if [[ -n "${AGENT_DECOMPILE_PROGRAM_OPTIONS:-}" ]]; then
    ARGS+=(--program-options "${AGENT_DECOMPILE_PROGRAM_OPTIONS}")
fi

if [[ -n "${AGENT_DECOMPILE_GZFS_PATH:-}" ]]; then
    ARGS+=(--gzfs-path "${AGENT_DECOMPILE_GZFS_PATH}")
fi

# ── Analysis performance ──────────────────────────────────────────────────────
if [[ -n "${AGENT_DECOMPILE_MAX_WORKERS:-}" ]]; then
    ARGS+=(--max-workers "${AGENT_DECOMPILE_MAX_WORKERS}")
fi

if [[ "${AGENT_DECOMPILE_WAIT_FOR_ANALYSIS:-}" == "true" || "${AGENT_DECOMPILE_WAIT_FOR_ANALYSIS:-}" == "1" ]]; then
    ARGS+=(--wait-for-analysis)
fi

# AGENT_DECOMPILE_THREADED: false/0 = disable threaded analysis (default: enabled)
if [[ "${AGENT_DECOMPILE_THREADED:-}" == "false" || "${AGENT_DECOMPILE_THREADED:-}" == "0" ]]; then
    ARGS+=(--no-threaded)
fi

# ── Project management (one-shot commands) ────────────────────────────────────
if [[ "${AGENT_DECOMPILE_LIST_PROJECT_BINARIES:-}" == "true" || "${AGENT_DECOMPILE_LIST_PROJECT_BINARIES:-}" == "1" ]]; then
    ARGS+=(--list-project-binaries)
fi

if [[ -n "${AGENT_DECOMPILE_DELETE_PROJECT_BINARY:-}" ]]; then
    ARGS+=(--delete-project-binary "${AGENT_DECOMPILE_DELETE_PROJECT_BINARY}")
fi

# ── Input binary paths ────────────────────────────────────────────────────────
# AGENT_DECOMPILE_INPUT_PATHS: colon-separated list of binary paths to import at startup
if [[ -n "${AGENT_DECOMPILE_INPUT_PATHS:-}" ]]; then
    IFS=':' read -ra _input_list <<< "${AGENT_DECOMPILE_INPUT_PATHS}"
    for _input in "${_input_list[@]}"; do
        [[ -n "${_input}" ]] && ARGS+=("${_input}")
    done
fi

# Any extra arguments passed to the container (CMD / docker run args) are
# appended last and override env-derived flags of the same name.
exec /ghidra/venv/bin/agentdecompile-server "${ARGS[@]}" "$@"
