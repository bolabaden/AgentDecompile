"""Address utility helpers for Ghidra addresses and symbols.

Single pipeline for address handling: all user-supplied address strings (e.g. from
function/addressOrSymbol parameters) should be parsed or resolved via AddressUtil so
that 0x-prefixed strings are interpreted as hex and others as decimal. Used by tool
providers, wrappers (find_function, read_bytes, _lookup_symbols), decompile_tool,
callgraph_tool, and script namespace (toAddr/getAddress). Format addresses for JSON
via AddressUtil.format_address for consistency.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Address as GhidraAddress,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Data as GhidraData,
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )
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

        If the string is prefixed by 0x or 0X, the remainder is parsed as base 16.
        Otherwise the whole string is parsed as base 10.

        Args:
            program: The Ghidra program (provides address factory)
            address_string: The address string to parse (with or without "0x")

        Returns:
            The parsed GhidraAddress object, or None if parsing fails
        """
        if address_string is None or not address_string.strip():
            return None

        s = address_string.strip()
        if s.lower().startswith("0x"):
            clean = s[2:].lstrip()
            base = 16
        else:
            clean = s
            base = 10

        if not clean:
            return None

        try:
            default_space = program.getAddressFactory().getDefaultAddressSpace()
            return default_space.getAddress(int(clean, base))
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

        # If input looks like a numeric address (0x-prefix or decimal digits), try parsing first.
        # Ghidra's symbol APIs can throw when given "0x48b17c" (e.g. int() in base 10).
        if input_str.lower().startswith("0x") or (
            input_str and input_str.isascii() and (input_str.isdigit() or (input_str.startswith("-") and input_str[1:].isdigit()))
        ):
            addr = AddressUtil.parse_address(program, input_str)
            if addr is not None:
                return addr

        # Try to find it as a symbol
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getLabelOrFunctionSymbols(input_str, None)

        if symbols and len(symbols) > 0:
            return symbols[0].getAddress()

        # Broaden search: symbol may live in a non-global namespace.
        # Keep this lazy to avoid materializing the entire symbol stream.
        try:
            scoped_symbols = symbol_table.getSymbols(input_str)
            if hasattr(scoped_symbols, "hasNext") and scoped_symbols.hasNext():
                return scoped_symbols.next().getAddress()

            for scoped_symbol in scoped_symbols:
                return scoped_symbol.getAddress()
        except Exception:
            pass

        # If not found as a symbol, try to parse as an address
        return AddressUtil.parse_address(program, input_str)

    @staticmethod
    def resolve_iat_to_thunk(program: GhidraProgram, address: GhidraAddress) -> GhidraAddress | None:
        """If the given address is an IAT slot (data holding a pointer to a thunk/external), return that thunk address.

        Used so list-cross-references and get-call-graph accept both IAT addresses (e.g. 0x48f1fc)
        and thunk addresses (e.g. CreateFileA @ 0x004011fc). When the user passes an IAT address,
        we resolve to the thunk so queries use the same logical target.

        Args:
            program: The Ghidra program
            address: The address that might be an IAT slot

        Returns:
            The thunk/external address the IAT points to, or None if not an IAT slot
        """
        if program is None or address is None:
            return None
        ref_mgr = program.getReferenceManager()
        fm = program.getFunctionManager()
        # Refs FROM this address: for an IAT slot, Ghidra typically has a memory ref from the data to the thunk.
        refs_from = ref_mgr.getReferencesFrom(address)
        try:
            for ref in refs_from:
                to_addr = ref.getToAddress()
                if to_addr is None:
                    continue
                func = fm.getFunctionAt(to_addr) or fm.getFunctionContaining(to_addr)
                if func is not None:
                    return func.getEntryPoint()
        except Exception:
            pass
        return None

    @staticmethod
    def resolve_address_or_symbol_prefer_thunk(program: GhidraProgram, address_or_symbol: str) -> GhidraAddress | None:
        """Resolve address or symbol; if the result is an IAT slot, return the thunk address instead.

        Enables list-cross-references and get-call-graph to support both thunk addresses
        (e.g. CreateFileA @ 0x004011fc) and IAT addresses (e.g. 0x48f1fc) by normalizing IAT to thunk.
        """
        addr = AddressUtil.resolve_address_or_symbol(program, address_or_symbol)
        if addr is None:
            return None
        thunk = AddressUtil.resolve_iat_to_thunk(program, addr)
        return thunk if thunk is not None else addr

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
