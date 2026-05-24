"""Internal service registry utilities for lightweight dependency injection."""

from __future__ import annotations

import logging

from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class AgentDecompileInternalServiceRegistry:
    """Internal service registry for dependency injection."""

    _services: dict[type[Any], Any] = {}

    @staticmethod
    def _service_name(service_class: type[Any]) -> str:
        """Return a stable display name for a service class."""
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry._service_name")
        return getattr(service_class, "__name__", str(service_class))

    @staticmethod
    def register_service(service_class: type[T], service_instance: T) -> None:
        """Register a service instance.

        Args:
            service_class: The service interface/class type
            service_instance: The service implementation instance
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.register_service")
        AgentDecompileInternalServiceRegistry._services[service_class] = service_instance
        logger.debug("Registered service: %s", AgentDecompileInternalServiceRegistry._service_name(service_class))

    @staticmethod
    def unregister_service(service_class: type[T]) -> None:
        """Unregister a service.

        Args:
            service_class: The service interface/class type to unregister
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.unregister_service")
        services = AgentDecompileInternalServiceRegistry._services
        if service_class in services:
            del services[service_class]
            logger.debug("Unregistered service: %s", AgentDecompileInternalServiceRegistry._service_name(service_class))
        else:
            logger.warning("Service not registered: %s", AgentDecompileInternalServiceRegistry._service_name(service_class))

    @staticmethod
    def get_service(service_class: type[T]) -> T | None:
        """Get a registered service instance.

        Args:
            service_class: The service interface/class type

        Returns:
            The service instance, or None if not registered
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.get_service")
        return AgentDecompileInternalServiceRegistry._services.get(service_class)

    @staticmethod
    def has_service(service_class: type[T]) -> bool:
        """Check if a service is registered.

        Args:
            service_class: The service interface/class type

        Returns:
            True if the service is registered
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.has_service")
        return service_class in AgentDecompileInternalServiceRegistry._services

    @staticmethod
    def clear_all_services() -> None:
        """Clear all registered services (primarily for testing)."""
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.clear_all_services")
        AgentDecompileInternalServiceRegistry._services.clear()
        logger.debug("Cleared all services")

    @staticmethod
    def list_services() -> dict[str, str]:
        """List all registered services.

        Returns:
            Dictionary mapping service class names to service instance types
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.list_services")
        return {AgentDecompileInternalServiceRegistry._service_name(service_class): type(service_instance).__name__ for service_class, service_instance in AgentDecompileInternalServiceRegistry._services.items()}

    @staticmethod
    def get_service_count() -> int:
        """Get the number of registered services.

        Returns:
            Number of registered services
        """
        logger.debug("diag.enter %s", "mcp_utils/service_registry.py:AgentDecompileInternalServiceRegistry.get_service_count")
        return len(AgentDecompileInternalServiceRegistry._services)
