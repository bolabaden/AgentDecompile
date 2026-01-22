# Development Guide

This guide covers setting up your development environment for AgentDecompile.

## Prerequisites

-   **Java 21**: We use Java 21 for modern features.
-   **Gradle 8.10+**: Use the system gradle (not wrapper).
-   **Ghidra 12.0+**: Required for the extension.
-   **Python 3.11+**: For the CLI bridge and tests.
-   **uv**: Python package manager.
-   **Git**: Version control.

## Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/bolabaden/AgentDecompile.git
    cd AgentDecompile
    ```

2.  **Environment Variables**:
    Create a `.env` file (optional, or set in shell):
    ```bash
    export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
    ```

3.  **Build**:
    ```bash
    gradle build
    ```

4.  **Install to Ghidra** (Local Dev):
    ```bash
    gradle install
    ```

## Project Structure

-   `src/main/java/agentdecompile`: Core Java source code.
-   `src/agentdecompile_cli`: Python CLI bridge.
-   `tests`: Python tests.
-   `src/test`: Java unit tests.
-   `src/test.slow`: Java integration tests.
