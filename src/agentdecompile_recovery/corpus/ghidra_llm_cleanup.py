"""LLM edit of Ghidra C that still fails after mechanical preparse.

This module re-exports the corpus ``llm_cleanup`` implementation so callers
that used the donor name keep working. Edit only. Compile decides keep/discard.
"""

from __future__ import annotations

from .llm_cleanup import (  # noqa: F401
    CLEANUP_PROMPT,
    DEFAULT_CLI,
    DEFAULT_TIMEOUT_SECONDS,
    resolve_mcp_server_url,
    CliResult,
    Runner,
    build_cli_command,
    build_get_function_command,
    cleanup_ghidra_c,
    extract_code_block,
    fetch_get_function_cli,
    render_cleanup_prompt,
    resolve_get_function_text,
)

DEFAULT_SERVER_URL = "http://127.0.0.1:8080/mcp"

__all__ = [
    "CLEANUP_PROMPT",
    "DEFAULT_CLI",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_SERVER_URL",
    "resolve_mcp_server_url",
    "CliResult",
    "Runner",
    "build_cli_command",
    "build_get_function_command",
    "cleanup_ghidra_c",
    "extract_code_block",
    "fetch_get_function_cli",
    "render_cleanup_prompt",
    "resolve_get_function_text",
]
