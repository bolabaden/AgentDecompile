# AgentDecompile — hero copy

Plain-language intro used on the [GitHub Pages site](https://bodecloud.github.io/AgentDecompile/) and at the top of [README.md](../README.md).

## Headline

**Connect AI to Ghidra**

## Subhead

Run an MCP server that talks to your Ghidra project. List functions, decompile code, rename symbols, and recover source you can rebuild.

## Three things it does

1. **Analyze with agents** — MCP tools read live Ghidra state (functions, xrefs, memory, decompilation) instead of guessing from file names.
2. **Recover rebuildable C** — The reconstruct pipeline only promotes functions that compile and pass objdiff with zero differences. Everything else stays in advisory folders with honest labels.
3. **Run your way** — Stdio for desktop MCP clients, HTTP at `/mcp` for scripts and remote use, optional browser UI when you start the server locally.

## One-line positioning

Binaries and messy reverse-engineering notes in; rebuildable source out, verified only where objdiff proves it.

## Where this copy appears

| Surface | Path |
|---------|------|
| GitHub Pages landing | [bodecloud.github.io/AgentDecompile](https://bodecloud.github.io/AgentDecompile/) |
| Repository README | [../README.md](../README.md) |
| Web UI hero | [../src/agentdecompile_cli/webui_assets/index.html](../src/agentdecompile_cli/webui_assets/index.html) |
