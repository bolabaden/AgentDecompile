"""MCP resource provider abstractions and manager.

ResourceProvider is the base for resources exposed via MCP resources/list and
resources/read. ResourceProviderManager registers providers (e.g. DebugInfoResource),
forwards program_opened/program_closed, and dispatches read_resource by URI.
Resources are used to expose debug/session info or static analysis results to
the client without going through a tool call.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp import types

    from agentdecompile_cli.launcher import ProgramInfo
    from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager

logger = logging.getLogger(__name__)


class ResourceProvider:
    """Base class for MCP resource providers."""

    def __init__(self, program_info: ProgramInfo | None = None):
        self.program_info: ProgramInfo | None = program_info
        self.tool_provider_manager: ToolProviderManager | None = None
        self.runtime_context: dict[str, Any] = {}

    def set_program_info(self, program_info: ProgramInfo) -> None:
        """Set the program info."""
        self.program_info = program_info

    def set_tool_provider_manager(self, tool_provider_manager: ToolProviderManager) -> None:
        """Set the tool-provider manager for cross-resource tool calls."""
        self.tool_provider_manager = tool_provider_manager

    def set_runtime_context(self, runtime_context: dict[str, Any]) -> None:
        """Set runtime metadata captured during server startup."""
        self.runtime_context = dict(runtime_context or {})

    def list_resources(self) -> list[types.Resource]:
        """Return list of resources provided by this provider."""
        return []

    async def read_resource(self, uri: str) -> str:
        """Read a resource by URI."""
        raise NotImplementedError(f"Resource {uri} not implemented")

    def program_opened(self, program_path: str) -> None:
        """Called when a program is opened."""

    def program_closed(self, program_path: str) -> None:
        """Called when a program is closed."""

    def cleanup(self) -> None:
        """Cleanup resources."""


class ResourceProviderManager:
    """Manages all MCP resource providers."""

    def __init__(self):
        self.providers: list[ResourceProvider] = []
        self.program_info: ProgramInfo | None = None
        self.tool_provider_manager: ToolProviderManager | None = None
        self.runtime_context: dict[str, Any] = {}

        # Initialize all resource providers
        self._init_providers()

    def _init_providers(self) -> None:
        """Register built-in resource providers: debug info, analysis dump, and tool-backed agentdecompile://<tool-name>."""
        from agentdecompile_cli.mcp_server.resources import DebugInfoResource
        from agentdecompile_cli.mcp_server.resources.analysis_dump import AnalysisDumpResource
        from agentdecompile_cli.mcp_server.resources.tool_resources import ToolOutputResource
        from agentdecompile_cli.mcp_server.resources.mermaid_flowchart import MermaidFlowchartResource

        self.providers = [
            DebugInfoResource(),
            AnalysisDumpResource(),
            ToolOutputResource(),
            MermaidFlowchartResource(),
        ]

        # Wire manager and runtime context into providers if already set (e.g. by server startup)
        if self.tool_provider_manager is not None:
            self._for_each_provider(lambda provider: provider.set_tool_provider_manager(self.tool_provider_manager))
        if self.runtime_context:
            self._for_each_provider(lambda provider: provider.set_runtime_context(self.runtime_context))

    def _for_each_provider(self, action: Callable[[ResourceProvider], None]) -> None:
        """Apply an action to each registered provider."""
        for provider in self.providers:
            action(provider)

    def set_program_info(self, program_info: ProgramInfo) -> None:
        """Set program info for all providers."""
        self.program_info = program_info
        self._for_each_provider(lambda provider: provider.set_program_info(program_info))

    def set_tool_provider_manager(self, tool_provider_manager: ToolProviderManager) -> None:
        """Set tool-provider manager for all resource providers."""
        self.tool_provider_manager = tool_provider_manager
        self._for_each_provider(lambda provider: provider.set_tool_provider_manager(tool_provider_manager))

    def set_runtime_context(self, runtime_context: dict[str, Any]) -> None:
        """Set startup/runtime context for all resource providers."""
        self.runtime_context = dict(runtime_context or {})
        self._for_each_provider(lambda provider: provider.set_runtime_context(self.runtime_context))

    def list_resources(self) -> list[types.Resource]:
        """List all resources from all providers."""
        resources: list[types.Resource] = []
        for provider in self.providers:
            resources.extend(provider.list_resources())
        return resources

    async def read_resource(
        self,
        uri: str,
        program_info: ProgramInfo | None = None,
    ) -> str:
        """Read a resource by URI.

        Attempts to read the resource from each registered provider.
        Logs which providers are tried and why they failed.
        """
        if program_info is not None and program_info is not self.program_info:
            self.set_program_info(program_info)

        logger.info("ResourceProviderManager: Attempting to read resource: %s", uri)
        logger.info(f"  Current program_info: {self.program_info}")
        logger.info(f"  Registered providers: {[p.__class__.__name__ for p in self.providers]}")
        attempted_providers: list[str] = []
        last_exception: Exception | None = None

        for provider in self.providers:
            provider_name = provider.__class__.__name__
            attempted_providers.append(provider_name)

            try:
                logger.info("  Trying provider: %s", provider_name)
                result: str = await provider.read_resource(uri)
                logger.info(f"  Provider {provider_name} succeeded, returned {len(result)} bytes")
                return result
            except NotImplementedError as e:
                logger.debug("  Provider %s does not handle this URI: %s", provider_name, e)
                continue
            except Exception as e:
                logger.error(f"  Provider {provider_name} raised exception: {e.__class__.__name__}: {e}", exc_info=True)
                last_exception = e
                continue

        error_msg = f"Unknown resource: {uri}. Attempted providers: {', '.join(attempted_providers)}"
        if last_exception is not None:
            error_msg += f". Last exception: {last_exception.__class__.__name__}: {last_exception}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    def program_opened(self, program_path: str) -> None:
        """Notify all providers that a program was opened."""
        self._for_each_provider(lambda provider: provider.program_opened(program_path))

    def program_closed(self, program_path: str) -> None:
        """Notify all providers that a program was closed."""
        self._for_each_provider(lambda provider: provider.program_closed(program_path))

    def cleanup(self) -> None:
        """Cleanup all providers."""
        self._for_each_provider(lambda provider: provider.cleanup())
