# AgentDecompile - Your AI Companion for Ghidra

> AI-powered code analysis and reverse engineering, directly inside Ghidra.

**AgentDecompile** bridges the gap between Ghidra and modern Artificial Intelligence. It allows you to chat with your binaries, automating the tedious parts of reverse engineering so you can focus on the logic that matters.

Built on the open standard [Model Context Protocol (MCP)](https://modelcontextprotocol.io), AgentDecompile turns Ghidra into an intelligent agent that can read, understand, and explain code for you.

## Why AgentDecompile?

Reverse engineering is hard. There are thousands of functions, cryptic variable names, and complex logic flows. AgentDecompile helps you make sense of it all by letting you ask plain English questions about your target code.

- **Ask Questions**: "Where is the main loop?", "Find all encryption functions", "What does this variable do?"
- **Automate Analysis**: Let the AI rename variables, comment functions, and map out code structures for you.
- **Smart Context**: Unlike generic chat bots, AgentDecompile actually sees your code. It reads the decompiled output, checks cross-references, and understands the program structure just like a human analyst would.

It's designed to be your pair programmer for assembly and decompiled code.

## What Can It Do?

You can ask AgentDecompile to perform complex tasks:

- **"Analyze this entire binary and summarize what it does."**
- **"Find where the user password is checked."**
- **"Rename all these variables to something meaningful."**
- **"Draw a diagram of this class structure."**
- **"Write a Python script to solve this CTF challenge."**

It works by giving the AI specific "tools" to interact with Ghidra—reading memory, listing functions, checking references—so it gets real, ground-truth data from your project.

## Installation

> **Note**: AgentDecompile requires Ghidra 12.0 or higher.

### Option 1: Release Installation (Recommended)
1. Download the latest release from the [Releases page](../../releases).
2. Open Ghidra.
3. Go to **File > Install Extensions**.
4. Click the **+** (Plus) sign and select the downloaded zip file.
5. Restart Ghidra.

### Option 2: Build from Source
If you want the absolute latest features:
`ash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle install
`

### Enabling the Extension
Once installed, you need to turn it on:
1. Open a binary in the **Code Browser**.
2. Go to **File > Configure**.
3. Click the **plug icon** (Configure All Plugins) in the top right.
4. Find **AgentDecompile** or **AgentDecompile Plugin** in the list and check the box.
5. Click **OK**.

## Usage

AgentDecompile works as an MCP server. This means you connect an AI client (like Claude Desktop, or an IDE extension) to it.

1. **Start Ghidra** and open your project.
2. The AgentDecompile server starts automatically in the background.
3. Configure your MCP client to connect to http://localhost:8080/mcp/message.

See the [Usage Guide](docs/USAGE.md) for detailed connection instructions.

## License

This project is licensed under the **Business Source License 1.1**. See [LICENSE](LICENSE) for details.
Free for personal, educational, and internal business use. 

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.
