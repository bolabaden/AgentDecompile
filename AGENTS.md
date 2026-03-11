# AGENTS.md

See [README.md](README.md) for project overview, [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, and [src/CLAUDE.md](src/CLAUDE.md) for architecture details.

## Cursor Cloud specific instructions

### Environment

- **Python 3.10+** and **Java 21** (OpenJDK) are pre-installed in the VM.
- **Ghidra 12.0.4** is installed at `/opt/ghidra-install/ghidra_12.0.4_PUBLIC`. Set `GHIDRA_INSTALL_DIR` accordingly.
- **uv** package manager is at `~/.local/bin/uv`. Ensure `$HOME/.local/bin` is on `PATH`.
- **PyGhidra** is installed from Ghidra's bundled pypkg (not PyPI). The update script reinstalls it from `$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg`.
- **ruff** is installed for linting (not a project dependency, installed separately via `uv pip install ruff`).
- chromadb (semantic search) is optional and not installed; the server logs a warning but operates normally without it.

### Injected secrets (environment variables)

**agentdecompile-server** is always a local instance (PyGhidra/JVM); it does not use proxy URL env vars. For local server runs, **unset** Ghidra server credentials if you do not want HTTP Basic Auth on MCP requests:

```bash
unset AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME
unset AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD
unset AGENT_DECOMPILE_GHIDRA_SERVER_HOST
unset AGENT_DECOMPILE_GHIDRA_SERVER_PORT
unset AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY
```

To run in **proxy mode** (forward to a remote MCP backend), use **agentdecompile-proxy** and set `AGENT_DECOMPILE_MCP_SERVER_URL` or `AGENTDECOMPILE_MCP_SERVER_URL` (or pass `--backend-url`).

### Running the MCP server locally

```bash
export PATH="$HOME/.local/bin:$PATH"
export GHIDRA_INSTALL_DIR=/opt/ghidra-install/ghidra_12.0.4_PUBLIC
# Unset Ghidra server credentials if you do not want auth (see above)
uv run agentdecompile-server -t streamable-http --host 127.0.0.1 --port 8080 \
  --project-path /tmp/agentdecompile-projects /path/to/binary
```

The server takes ~3 seconds to initialize PyGhidra/JVM. Once running, use the CLI:

```bash
uv run agentdecompile-cli --server-url http://127.0.0.1:8080 tool-seq \
  '[{"name":"open-project","arguments":{"path":"/path/to/binary"}},
    {"name":"analyze-program","arguments":{"programPath":"binaryname"}},
    {"name":"list-functions","arguments":{"programPath":"binaryname","limit":10}}]'
```

### Session state caveat

Each CLI invocation creates a new MCP session. Programs loaded in one session are not available in the next. Use `tool-seq` to chain multiple tool calls (open, analyze, list, decompile) within a single session. Alternatively, pass binaries as positional arguments to `agentdecompile-server` so they are imported at startup.

### Lint, test, build

| Task | Command |
|------|---------|
| Lint | `uv run ruff check --no-fix src/ tests/` |
| Test (all) | `uv run pytest tests/ -v --timeout=180` |
| Test (unit only) | `uv run pytest -m unit -v` |
| Build | `uv build` |

Pre-existing lint violations (49 errors) and test failures (46 of ~1300) exist in the codebase; they are not caused by the development environment.

## Naming Conventions

When generating or suggesting names for symbols, variables, parameters, fields, types, or constants during reverse engineering work, apply these conventions consistently:

| Identifier kind | Convention | Example |
|---|---|---|
| Local variables | `camelCase` | `itemCount`, `saveBuffer` |
| Global variables | `camelCase` | `gameState`, `playerStats` |
| Function parameters | `camelCase` | `charIndex`, `saveFilePath` |
| Classes and types | `CapitalCase` (PascalCase) | `SaveGameHeader`, `ItemRecord` |
| Structure fields | `snake_case` | `save_version`, `char_name` |
| Enum constants | `COBRA_CASE` (SCREAMING_SNAKE) | `SAVE_SLOT_EMPTY`, `ITEM_TYPE_WEAPON` |

Apply these conventions in:
- Decompiled pseudocode variable and parameter names produced by `decompile-function` or `execute-script`
- Symbol rename suggestions from `rename-function`, `rename-variable`, `rename-data-label`
- Structure and field names in `create-structure` / `edit-structure` tool calls
- Enum members defined via `create-enum` / `edit-enum`
- Documentation, comments, and analysis summaries that reference named symbols

When a name is ambiguous or cannot be inferred, prefer the convention that matches the identifier category above rather than leaving it in a raw mangled/numbered form (e.g., prefer `slotIndex` over `local_8` for a loop counter).
