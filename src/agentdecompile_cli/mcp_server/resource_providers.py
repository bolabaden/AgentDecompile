"""MCP resource provider abstractions and manager."""

from __future__ import annotations

import logging

from collections.abc import Callable

from mcp import types

from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)


class ResourceProvider:
    """Base class for MCP resource providers."""

    def __init__(self, program_info: ProgramInfo | None = None):
        self.program_info: ProgramInfo | None = program_info

    def set_program_info(self, program_info: ProgramInfo) -> None:
        """Set the program info."""
        self.program_info = program_info

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

        # Initialize all resource providers
        self._init_providers()

    def _init_providers(self) -> None:
        """Initialize all resource providers."""
        from agentdecompile_cli.mcp_server.resources import (
            DebugInfoResource,
            ProgramListResource,
            StaticAnalysisResultsResource,
        )

        self.providers = [
            ProgramListResource(),
            StaticAnalysisResultsResource(),
            DebugInfoResource(),
        ]

    def _for_each_provider(self, action: Callable[[ResourceProvider], None]) -> None:
        """Apply an action to each registered provider."""
        for provider in self.providers:
            action(provider)

    def set_program_info(self, program_info: ProgramInfo) -> None:
        """Set program info for all providers."""
        self.program_info = program_info
        self._for_each_provider(lambda provider: provider.set_program_info(program_info))

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

        uri = str(uri)  # Normalize AnyUrl/pydantic objects to plain string

        logger.info(f"ResourceProviderManager: Attempting to read resource: {uri}")
        logger.info(f"  Current program_info: {self.program_info}")
        logger.info(f"  Registered providers: {[p.__class__.__name__ for p in self.providers]}")
        attempted_providers = []
        last_exception = None

        for provider in self.providers:
            provider_name = provider.__class__.__name__
            attempted_providers.append(provider_name)
            
            try:
                logger.info(f"  Trying provider: {provider_name}")
                result: str = await provider.read_resource(uri)
                logger.info(f"  Provider {provider_name} succeeded, returned {len(result)} bytes")
                return result
            except NotImplementedError as e:
                logger.debug(f"  Provider {provider_name} does not handle this URI: {e}")
                continue
            except Exception as e:
                logger.error(f"  Provider {provider_name} raised exception: {type(e).__name__}: {e}", exc_info=True)
                last_exception = e
                continue

        error_msg = f"Unknown resource: {uri}. Attempted providers: {', '.join(attempted_providers)}"
        if last_exception:
            error_msg += f". Last exception: {type(last_exception).__name__}: {last_exception}"
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
