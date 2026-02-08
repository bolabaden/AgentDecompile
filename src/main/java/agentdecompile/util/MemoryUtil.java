/* ###
 * IP: AgentDecompile
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package agentdecompile.util;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Utility functions for working with Ghidra memory.
 * <p>
 * Ghidra Memory API references:
 * <ul>
 *   <li>{@link ghidra.program.model.mem.Memory} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html">Memory API</a></li>
 *   <li>{@link ghidra.program.model.mem.MemoryBlock} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html">MemoryBlock API</a></li>
 *   <li>{@link ghidra.program.model.mem.MemoryAccessException} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryAccessException.html">MemoryAccessException API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/package-summary.html">ghidra.program.model.mem package</a>.
 * </p>
 */
public class MemoryUtil {

    /**
     * Format a byte array as a hex string
     * @param bytes The byte array
     * @return A hex string representation
     */
    public static String formatHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder hexBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexBuilder.append(String.format("%02X ", b & 0xFF));
        }
        return hexBuilder.toString().trim();
    }

    /**
     * Format a byte array as an ASCII string (non-printable chars shown as '.')
     * @param bytes The byte array
     * @return An ASCII string representation
     */
    public static String formatAsciiString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder asciiBuilder = new StringBuilder();
        for (byte b : bytes) {
            char c = (char) (b & 0xFF);
            if (c >= 32 && c <= 126) {
                asciiBuilder.append(c);
            } else {
                asciiBuilder.append('.');
            }
        }
        return asciiBuilder.toString();
    }

    /**
     * Convert a byte array to a list of integer values (0-255)
     * @param bytes The byte array
     * @return List of integer values
     */
    public static List<Integer> byteArrayToIntList(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return List.of();
        }

        List<Integer> result = new ArrayList<>(bytes.length);
        for (byte b : bytes) {
            result.add(b & 0xFF);
        }
        return result;
    }

    /**
     * Read memory bytes safely
     * @param program The Ghidra program
     * @param address Starting address
     * @param length Number of bytes to read
     * @return Byte array or null if an error occurred
     */
    public static byte[] readMemoryBytes(Program program, Address address, int length) {
        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        byte[] bytes = new byte[length];

        try {
            // Ghidra API: Memory.getBytes(Address, byte[]) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBytes(ghidra.program.model.address.Address,byte[])
            int read = memory.getBytes(address, bytes);
            if (read != length) {
                byte[] actualBytes = new byte[read];
                System.arraycopy(bytes, 0, actualBytes, 0, read);
                return actualBytes;
            }
            return bytes;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    /**
     * Find a memory block by name
     * @param program The Ghidra program
     * @param blockName Name of the block to find
     * @return The memory block or null if not found
     */
    public static MemoryBlock findBlockByName(Program program, String blockName) {
        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        // Ghidra API: Memory.getBlocks() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBlocks()
        for (MemoryBlock block : memory.getBlocks()) {
            // Ghidra API: MemoryBlock.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html#getName()
            if (block.getName().equals(blockName)) {
                return block;
            }
        }
        return null;
    }

    /**
     * Find the memory block containing the given address
     * @param program The Ghidra program
     * @param address The address to look up
     * @return The memory block or null if not found
     */
    public static MemoryBlock getBlockContaining(Program program, Address address) {
        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        // Ghidra API: Memory.getBlock(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBlock(ghidra.program.model.address.Address)
        return memory.getBlock(address);
    }

    /**
     * Process memory bytes in chunks to avoid large memory allocations
     * @param program The Ghidra program
     * @param startAddress Starting address
     * @param length Total number of bytes to process
     * @param chunkSize Maximum chunk size
     * @param processor Consumer function that processes each chunk
     */
    public static void processMemoryInChunks(
            Program program,
            Address startAddress,
            long length,
            int chunkSize,
            Consumer<byte[]> processor) {

        // Ghidra API: Program.getMemory() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        Memory memory = program.getMemory();
        Address currentAddress = startAddress;
        long remaining = length;

        while (remaining > 0) {
            int currentChunkSize = (int) Math.min(remaining, chunkSize);
            byte[] buffer = new byte[currentChunkSize];

            try {
                // Ghidra API: Memory.getBytes(Address, byte[]) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html#getBytes(ghidra.program.model.address.Address,byte[])
                int read = memory.getBytes(currentAddress, buffer);
                if (read > 0) {
                    processor.accept(buffer);
                    // Ghidra API: Address.add(long) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#add(long)
                    currentAddress = currentAddress.add(read);
                    remaining -= read;
                } else {
                    break; // Could not read any bytes
                }
            } catch (MemoryAccessException e) {
                break; // Memory access error
            }
        }
    }
}
