"""MCP resource: agentdecompile://capabilities — tier routing and tool inventory."""

from __future__ import annotations

import json
import logging

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider
from agentdecompile_cli.mcp_utils.tool_reference import build_capabilities_payload
from agentdecompile_cli.registry import RESOURCE_URI_CAPABILITIES

logger = logging.getLogger(__name__)


class CapabilitiesResource(ResourceProvider):
    """Expose tiered RE routing and advertised MCP tools via resources/read."""

    def list_resources(self) -> list[types.Resource]:
        logger.debug("diag.enter %s", "mcp_server/resources/capabilities.py:CapabilitiesResource.list_resources")
        return [
            types.Resource(
                uri=AnyUrl(url=RESOURCE_URI_CAPABILITIES),
                name="capabilities",
                description=(
                    "AgentDecompile capability map: Tier 0–3 routing guidance, "
                    "analysis_tier per MCP tool, and active tool surface profile."
                ),
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        logger.debug("diag.enter %s", "mcp_server/resources/capabilities.py:CapabilitiesResource.read_resource")
        if uri != RESOURCE_URI_CAPABILITIES:
            raise NotImplementedError(f"Resource {uri} not implemented")
        payload = build_capabilities_payload()
        return json.dumps(payload, indent=2, sort_keys=True)
