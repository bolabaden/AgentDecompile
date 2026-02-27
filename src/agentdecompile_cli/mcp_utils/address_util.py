"""Address utility functions for AgentDecompile Python implementation.

Provides consistent address formatting and parsing, .
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        Address as GhidraAddress,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingTypeStubs, reportMissingImports, reportMissingModuleSource]
        Data as GhidraData,
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )

    # Type alias for convenience
    Symbol = GhidraSymbol


class AddressUtil:
    """Utility functions for working with Ghidra addresses."""

    @staticmethod
    def format_address(address: GhidraAddress | None) -> str | None:
        """Format an address for JSON output with consistent "0x" prefix.

        This is the standard format used across all AgentDecompile tool providers.

        Args:
            address: The Ghidra address to format

        Returns:
            A hex string representation with "0x" prefix, or None if address is None
        """
        if address is None:
            return None
        return address.toString("0x")

    @staticmethod
    def parse_address(program: GhidraProgram, address_string: str) -> GhidraAddress | None:
        """Parse an address string that may or may not have a "0x" prefix.

        This handles user input that might come in either format.

        Args:
            program: The Ghidra program (provides address factory)
            address_string: The address string to parse (with or without "0x")

        Returns:
            The parsed GhidraAddress object, or None if parsing fails
        """
        if address_string is None or not address_string.strip():
            return None

        # Remove "0x" prefix if present
        clean_address = address_string.strip()
        if clean_address.lower().startswith("0x"):
            clean_address = clean_address[2:]

        try:
            # Get the default address space and parse the address
            default_space = program.getAddressFactory().getDefaultAddressSpace()
            return default_space.getAddress(int(clean_address, 16))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def is_valid_address(program: GhidraProgram, address_string: str) -> bool:
        """Check if an address string is valid (parseable).

        Args:
            program: The Ghidra program to get the address space from
            address_string: The address string to validate

        Returns:
            True if the address string can be parsed, False otherwise
        """
        return AddressUtil.parse_address(program, address_string) is not None

    @staticmethod
    def resolve_address_or_symbol(program: GhidraProgram, address_or_symbol: str) -> GhidraAddress | None:
        """Resolve an address or symbol string to an GhidraAddress object.

        This method first attempts to find a symbol with the given name,
        and if not found, falls back to parsing it as an address.

        Args:
            program: The Ghidra program to search in
            address_or_symbol: The address string (with or without "0x") or symbol name

        Returns:
            The resolved GhidraAddress object, or None if neither symbol nor address is valid
        """
        if address_or_symbol is None or not address_or_symbol.strip():
            return None

        input_str = address_or_symbol.strip()

        # First, try to find it as a symbol
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getLabelOrFunctionSymbols(input_str, None)

        if symbols and len(symbols) > 0:
            return symbols[0].getAddress()

        # If not found as a symbol, try to parse as an address
        return AddressUtil.parse_address(program, input_str)

    @staticmethod
    def get_containing_function(program: GhidraProgram, address: GhidraAddress) -> GhidraFunction | None:
        """Get the function containing the given address.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            The containing function, or None if the address is not within a function
        """
        if program is None or address is None:
            return None

        return program.getFunctionManager().getFunctionContaining(address)

    @staticmethod
    def get_containing_data(program: GhidraProgram, address: GhidraAddress) -> GhidraData | None:
        """Get the data item containing or starting at the given address.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            The data at or containing the address, or None if no data exists there
        """
        if program is None or address is None:
            return None

        listing = program.getListing()

        # First try to get data at the exact address
        data = listing.getDataAt(address)
        if data is not None:
            return data

        # If not found, try to get data containing the address
        return listing.getDataContaining(address)

    @staticmethod
    def is_undefined_function_address(program: GhidraProgram, address_or_symbol: str) -> bool:
        """Check if an address could be an undefined function location.

        An address is considered an undefined function location if:
        - It's not inside a defined function
        - It's in executable memory
        - There's a valid instruction at that address

        Args:
            program: The Ghidra program
            address_or_symbol: The address string or symbol name to check

        Returns:
            True if this appears to be an undefined function location
        """
        if program is None or address_or_symbol is None or not address_or_symbol.strip():
            return False

        address = AddressUtil.resolve_address_or_symbol(program, address_or_symbol)
        if address is None:
            return False

        return AddressUtil._is_undefined_function_address(program, address)

    @staticmethod
    def _is_undefined_function_address(program: GhidraProgram, address: GhidraAddress) -> bool:
        """Check if an address could be an undefined function location.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            True if this appears to be an undefined function location
        """
        if program is None or address is None:
            return False

        # Check if address is already in a defined function
        if program.getFunctionManager().getFunctionContaining(address) is not None:
            return False

        # Check if address is in executable memory
        block = program.getMemory().getBlock(address)
        if block is None or not block.isExecute():
            return False

        # Check if there's a valid instruction at this address
        instr = program.getListing().getInstructionAt(address)
        return instr is not None
