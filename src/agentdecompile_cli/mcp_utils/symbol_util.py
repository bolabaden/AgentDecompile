"""Symbol utility functions for AgentDecompile Python implementation.

Provides symbol validation and filtering, .
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.program.model.address import Address as GhidraAddress  # pyright: ignore[reportMissingImports]
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )

    # Type alias for convenience
    Symbol = GhidraSymbol

# Default symbol name patterns that Ghidra generates
DEFAULT_SYMBOL_PATTERNS = [
    r"^FUN_[0-9a-fA-F]+$",  # Functions: FUN_00401000
    r"^LAB_[0-9a-fA-F]+$",  # Labels: LAB_00401005
    r"^SUB_[0-9a-fA-F]+$",  # Subroutines: SUB_00401010
    r"^DAT_[0-9a-fA-F]+$",  # Data: DAT_00402000
    r"^EXT_[0-9a-fA-F]+$",  # External references: EXT_00403000
    r"^PTR_[0-9a-fA-F]+$",  # Pointers: PTR_00404000
    r"^ARRAY_[0-9a-fA-F]+$",  # Arrays: ARRAY_00405000
    r"^STRUCT_[0-9a-fA-F]+$",  # Structs: STRUCT_00406000
    r"^UNION_[0-9a-fA-F]+$",  # Unions: UNION_00407000
    r"^ENUM_[0-9a-fA-F]+$",  # Enums: ENUM_00408000
]


class SymbolUtil:
    """Utility functions for symbol validation and filtering."""

    @staticmethod
    def is_default_symbol_name(symbol_name: str) -> bool:
        """Check if a symbol name is a Ghidra-generated default name.

        Args:
        ----
            symbol_name: The symbol name to check

        Returns:
        -------
            True if this is a default Ghidra symbol name
        """
        if symbol_name is None:
            return False

        import re

        symbol_name = symbol_name.strip()

        for pattern in DEFAULT_SYMBOL_PATTERNS:
            if re.match(pattern, symbol_name):
                return True

        return False

    @staticmethod
    def filter_default_symbol_names(symbols: list[GhidraSymbol]) -> list[GhidraSymbol]:
        """Filter out symbols with default Ghidra-generated names.

        Args:
        ----
            symbols: List of symbols to filter

        Returns:
        -------
            List of symbols with user-defined names only
        """
        if symbols is None:
            return []

        return [sym for sym in symbols if not SymbolUtil.is_default_symbol_name(sym.getName(True))]

    @staticmethod
    def get_symbol_type_name(symbol: GhidraSymbol) -> str:
        """Get a human-readable name for a symbol's type.

        Args:
        ----
            symbol: The symbol to get the type name for

        Returns:
        -------
            Human-readable type name
        """
        if symbol is None:
            return "unknown"

        symbol_type = symbol.getSymbolType()
        if symbol_type is None:
            return "unknown"

        # Map common symbol types to readable names
        type_mapping: dict[str, str] = {
            "FUNCTION": "function",
            "LABEL": "label",
            "GLOBAL": "global",
            "LOCAL": "local",
            "PARAMETER": "parameter",
            "EXTERNAL": "external",
        }

        type_str = str(symbol_type)
        return type_mapping.get(type_str, type_str.lower())

    @staticmethod
    def get_symbol_namespace_path(symbol: GhidraSymbol) -> str:
        """Get the full namespace path for a symbol.

        Args:
        ----
            symbol: The symbol to get the namespace path for

        Returns:
        -------
            Full namespace path as a string
        """
        if symbol is None:
            return ""

        namespace = symbol.getParentNamespace()
        if namespace is None:
            return ""

        # Build the namespace path
        path_parts = []
        current = namespace

        while current is not None:
            name = current.getName(True)
            if name and name != "Global":
                path_parts.insert(0, name)
            current = current.getParentNamespace()

        return "::".join(path_parts) if path_parts else ""

    @staticmethod
    def symbols_have_same_address(symbol1: GhidraSymbol, symbol2: GhidraSymbol) -> bool:
        """Check if two symbols refer to the same address.

        Args:
        ----
            symbol1: First symbol
            symbol2: Second symbol

        Returns:
        -------
            True if both symbols have the same address
        """
        if symbol1 is None or symbol2 is None:
            return False

        addr1 = symbol1.getAddress()
        addr2 = symbol2.getAddress()

        return addr1 is not None and addr2 is not None and addr1.equals(addr2)

    @staticmethod
    def get_symbols_at_address(
        symbols: list[GhidraSymbol],
        address: GhidraAddress,
    ) -> list[GhidraSymbol]:
        """Get all symbols at a specific address.

        Args:
        ----
            symbols: List of symbols to search
            address: The address to match

        Returns:
        -------
            List of symbols at the given address
        """
        if symbols is None or address is None:
            return []

        return [sym for sym in symbols if sym.getAddress() and sym.getAddress().equals(address)]

    @staticmethod
    def sort_symbols_by_relevance(symbols: list[GhidraSymbol], search_term: str = "") -> list[GhidraSymbol]:
        """Sort symbols by relevance (user-defined names first, then by name similarity).

        Args:
        ----
            symbols: List of symbols to sort
            search_term: Optional search term for similarity ranking

        Returns:
        -------
            Sorted list of symbols
        """
        if symbols is None:
            return []

        def symbol_sort_key(symbol: GhidraSymbol) -> tuple:
            name = symbol.getName(True) or ""

            # Primary sort: user-defined names before default names
            is_default = SymbolUtil.is_default_symbol_name(name)

            # Secondary sort: by name length (shorter names often more relevant)
            name_length = len(name)

            # Tertiary sort: alphabetical
            name_lower = name.lower()

            return (is_default, name_length, name_lower)

        return sorted(symbols, key=symbol_sort_key)

    @staticmethod
    def group_symbols_by_namespace(symbols: list[GhidraSymbol]) -> dict[str, list[GhidraSymbol]]:
        """Group symbols by their namespace.

        Args:
        ----
            symbols: List of symbols to group

        Returns:
        -------
            Dictionary mapping namespace paths to lists of symbols
        """
        if symbols is None:
            return {}

        grouped: dict[str, list[GhidraSymbol]] = {}
        for symbol in symbols:
            namespace = SymbolUtil.get_symbol_namespace_path(symbol)
            if namespace not in grouped:
                grouped[namespace] = []
            grouped[namespace].append(symbol)

        return grouped
