"""Memory utility helpers for safe reads and block inspection.

Used by inspect-memory/read-bytes and other providers to: read bytes at an
address with bounds checking (contains), convert Java byte arrays to Python
bytes, and format hex dumps. MemoryUtil.read_memory_bytes is the safe entry
point when the provider cannot assume getBytes/getByte always succeeds.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Address as GhidraAddress,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Program as GhidraProgram,
    )
    from ghidra.program.model.mem import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        MemoryBlock as GhidraMemoryBlock,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )
    Symbol = GhidraSymbol

logger = logging.getLogger(__name__)


class MemoryUtil:
    """Utility functions for safe memory access operations."""

    @staticmethod
    def read_memory_bytes(program: GhidraProgram, address: GhidraAddress, length: int) -> bytes | None:
        """Read memory bytes safely with error handling.

        Args:
            program: The Ghidra program
            address: The address to read from
            length: Number of bytes to read

        Returns:
            The bytes read, or None if reading fails
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.read_memory_bytes")
        if program is None or address is None or length <= 0:
            return None

        try:
            memory = program.getMemory()
            if not memory.contains(address):
                return None

            # Ghidra getBytes expects a Java byte[]; create one via jpype, then convert result to Python bytes
            import jpype

            JByte = jpype.JClass("java.lang.Byte")
            buf = JByte[length]  # type: ignore

            n = memory.getBytes(address, buf)
            if n <= 0:
                return b""

            # Convert Java signed bytes to Python bytes
            return bytes(b & 0xFF for b in buf[:n])
        except Exception as e:
            logger.debug("Failed to read memory at %s: %s", address, e)
            return None

    @staticmethod
    def format_hex_string(data: bytes, bytes_per_line: int = 16) -> str:
        """Format bytes as a hex string with proper formatting.

        Args:
            data: The bytes to format
            bytes_per_line: Number of bytes per line

        Returns:
            Formatted hex string
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.format_hex_string")
        if not data:
            return ""

        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i : i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            lines.append(hex_part)

        return "\n".join(lines)

    @staticmethod
    def byte_array_to_int_list(data: bytes) -> list[int]:
        """Convert bytes to a list of integers for JSON serialization.

        Args:
            data: The bytes to convert

        Returns:
            List of integers (0-255)
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.byte_array_to_int_list")
        return list(data)

    @staticmethod
    def find_block_by_name(program: GhidraProgram, block_name: str) -> GhidraMemoryBlock | None:
        """Find a memory block by name.

        Args:
            program: The Ghidra program
            block_name: Name of the memory block to find

        Returns:
            The memory block, or None if not found
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.find_block_by_name")
        if program is None or block_name is None:
            return None

        memory = program.getMemory()
        for block in memory.getBlocks():
            if block.getName() == block_name:
                return block

        return None

    @staticmethod
    def get_block_containing(program: GhidraProgram, address: GhidraAddress) -> GhidraMemoryBlock | None:
        """Get the memory block containing the given address.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            The memory block containing the address, or None
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.get_block_containing")
        if program is None or address is None:
            return None

        memory = program.getMemory()
        return memory.getBlock(address)

    @staticmethod
    def process_memory_in_chunks(
        program: GhidraProgram,
        start_address: GhidraAddress,
        total_length: int,
        chunk_size: int,
        processor: Callable[[bytes], None],
    ) -> None:
        """Process large memory regions in chunks to avoid memory issues.

        Args:
            program: The Ghidra program
            start_address: Starting address
            total_length: Total bytes to process
            chunk_size: Size of each chunk
            processor: Function to call for each chunk
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.process_memory_in_chunks")
        if program is None or start_address is None or total_length <= 0 or chunk_size <= 0:
            return

        current_address = start_address
        remaining = total_length

        while remaining > 0:
            # Calculate how much to read in this chunk
            to_read = min(chunk_size, remaining)

            # Read the chunk
            chunk = MemoryUtil.read_memory_bytes(program, current_address, to_read)
            if chunk is None:
                logger.warning("Failed to read memory chunk at %s", current_address)
                break

            if not chunk:
                logger.warning("Stopping chunked memory processing at %s due to empty read", current_address)
                break

            # Process the chunk
            try:
                processor(chunk)
            except Exception as e:
                logger.error("Error processing memory chunk at %s: %s", current_address, e)
                break

            # Move to next chunk
            try:
                current_address = current_address.add(len(chunk))
                remaining -= len(chunk)
            except Exception as e:
                logger.error("Error calculating next address: %s", e)
                break

    @staticmethod
    def is_address_in_executable_memory(program: GhidraProgram, address: GhidraAddress) -> bool:
        """Check if an address is in executable memory.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            True if the address is in executable memory
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.is_address_in_executable_memory")
        block = MemoryUtil.get_block_containing(program, address)
        return block is not None and block.isExecute()

    @staticmethod
    def is_address_in_writable_memory(program: GhidraProgram, address: GhidraAddress) -> bool:
        """Check if an address is in writable memory.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            True if the address is in writable memory
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.is_address_in_writable_memory")
        block = MemoryUtil.get_block_containing(program, address)
        return block is not None and block.isWrite()

    @staticmethod
    def get_memory_block_info(program: GhidraProgram, address: GhidraAddress) -> dict | None:
        """Get information about the memory block containing an address.

        Args:
            program: The Ghidra program
            address: The address to check

        Returns:
            Dictionary with block information, or None if not in any block
        """
        logger.debug("diag.enter %s", "mcp_utils/memory_util.py:MemoryUtil.get_memory_block_info")
        block = MemoryUtil.get_block_containing(program, address)
        if block is None:
            return None

        return {
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "readable": block.isRead(),
            "writable": block.isWrite(),
            "executable": block.isExecute(),
            "initialized": block.isInitialized(),
        }
