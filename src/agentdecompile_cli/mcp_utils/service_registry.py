"""Service registry utility for AgentDecompile Python implementation.

Provides service dependency injection, .
"""

from __future__ import annotations

import logging

from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class AgentDecompileInternalServiceRegistry:
    """Internal service registry for dependency injection."""

    _services: dict[type[Any], Any] = {}

    @staticmethod
    def register_service(service_class: type[T], service_instance: T) -> None:
        """Register a service instance.

        Args:
            service_class: The service interface/class type
            service_instance: The service implementation instance
        """
        AgentDecompileInternalServiceRegistry._services[service_class] = service_instance
        logger.debug(f"Registered service: {service_class.__name__}")

    @staticmethod
    def unregister_service(service_class: type[T]) -> None:
        """Unregister a service.

        Args:
            service_class: The service interface/class type to unregister
        """
        if service_class in AgentDecompileInternalServiceRegistry._services:
            del AgentDecompileInternalServiceRegistry._services[service_class]
            logger.debug(f"Unregistered service: {service_class.__name__}")
        else:
            logger.warning(f"Service not registered: {service_class.__name__}")

    @staticmethod
    def get_service(service_class: type[T]) -> T | None:
        """Get a registered service instance.

        Args:
            service_class: The service interface/class type

        Returns:
            The service instance, or None if not registered
        """
        return AgentDecompileInternalServiceRegistry._services.get(service_class)

    @staticmethod
    def has_service(service_class: type[T]) -> bool:
        """Check if a service is registered.

        Args:
            service_class: The service interface/class type

        Returns:
            True if the service is registered
        """
        return service_class in AgentDecompileInternalServiceRegistry._services

    @staticmethod
    def clear_all_services() -> None:
        """Clear all registered services (primarily for testing)."""
        AgentDecompileInternalServiceRegistry._services.clear()
        logger.debug("Cleared all services")

    @staticmethod
    def list_services() -> dict[str, str]:
        """List all registered services.

        Returns:
            Dictionary mapping service class names to service instance types
        """
        return {service_class.__name__: type(service_instance).__name__ for service_class, service_instance in AgentDecompileInternalServiceRegistry._services.items()}

    @staticmethod
    def get_service_count() -> int:
        """Get the number of registered services.

        Returns:
            Number of registered services
        """
        return len(AgentDecompileInternalServiceRegistry._services)
