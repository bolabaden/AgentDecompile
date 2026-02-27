"""Backward-compatibility shim for the legacy dynamic_tool_executor module.

The authoritative implementation now lives in ``agentdecompile_cli.executor``.
This module preserves import compatibility while eliminating duplicate logic.
"""

from __future__ import annotations

from agentdecompile_cli.executor import DynamicToolExecutor, dynamic_executor

__all__ = ["DynamicToolExecutor", "dynamic_executor"]
