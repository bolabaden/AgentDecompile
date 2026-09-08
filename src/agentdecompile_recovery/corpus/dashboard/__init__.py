"""Corpus dashboard served from the AgentDecompile MCP HTTP app."""

from __future__ import annotations

from agentdecompile_recovery.corpus.dashboard.pages import page_index
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router

__all__ = ["create_dashboard_router", "page_index"]
