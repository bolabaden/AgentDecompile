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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.List;

/**
 * Utility functions for working with Ghidra addresses.
 * Provides consistent address formatting across all AgentDecompile tools.
 * <p>
 * Ghidra API references:
 * <ul>
 *   <li>{@link ghidra.program.model.address.Address} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html">Address API</a></li>
 *   <li>{@link ghidra.program.model.address.AddressSpace} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html">AddressSpace API</a></li>
 *   <li>{@link ghidra.program.model.listing.Program} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a></li>
 *   <li>{@link ghidra.program.model.symbol.SymbolTable} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html">SymbolTable API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class AddressUtil {

    /**
     * Format an address for JSON output with consistent "0x" prefix.
     * This is the standard format used across all AgentDecompile tool providers.
     *
     * @param address The Ghidra address to format (see {@link Address#toString(String)})
     * @return A hex string representation with "0x" prefix
     * @see <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html">Address API</a>
     */
    public static String formatAddress(Address address) {
        if (address == null) {
            return null;
        }
        // Format the address with a consistent "0x" prefix
        // Ghidra API: Address.toString(String) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html#toString(java.lang.String)
        return address.toString("0x");
    }

    /**
     * Parse an address string that may or may not have a "0x" prefix.
     * This handles user input that might come in either format.
     *
     * @param program The Ghidra program (provides {@link Program#getAddressFactory()} for address creation)
     * @param addressString The address string to parse (with or without "0x")
     * @return The parsed Address object, or null if parsing fails
     * @see <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html#getAddress(long)">AddressSpace.getAddress</a>
     */
    public static Address parseAddress(Program program, String addressString) {
        if (addressString == null || addressString.trim().isEmpty()) {
            return null;
        }

        // Remove "0x" prefix if present
        String cleanAddress = addressString.trim();
        if (cleanAddress.toLowerCase().startsWith("0x")) {
            cleanAddress = cleanAddress.substring(2);
        }

        try {
            // Ghidra API: Program.getAddressFactory(), AddressFactory.getDefaultAddressSpace() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getAddressFactory()
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            // Ghidra API: AddressSpace.getAddress(long) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html#getAddress(long)
            return defaultSpace.getAddress(Long.parseUnsignedLong(cleanAddress, 16));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Check if an address string is valid (parseable).
     *
     * @param program The Ghidra program to get the address space from
     * @param addressString The address string to validate
     * @return true if the address string can be parsed, false otherwise
     */
    public static boolean isValidAddress(Program program, String addressString) {
        return parseAddress(program, addressString) != null;
    }

    /**
     * Resolve an address or symbol string to an Address object.
     * This method first attempts to find a symbol with the given name,
     * and if not found, falls back to parsing it as an address.
     *
     * @param program The Ghidra program to search in
     * @param addressOrSymbol The address string (with or without "0x") or symbol name
     * @return The resolved Address object, or null if neither symbol nor address is valid
     */
    public static Address resolveAddressOrSymbol(Program program, String addressOrSymbol) {
        if (addressOrSymbol == null || addressOrSymbol.trim().isEmpty()) {
            return null;
        }

        String input = addressOrSymbol.trim();

        // First, try to find it as a symbol
        // Ghidra API: Program.getSymbolTable() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getSymbolTable()
        SymbolTable symbolTable = program.getSymbolTable();
        // Ghidra API: SymbolTable.getLabelOrFunctionSymbols(String, AddressSetView) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html#getLabelOrFunctionSymbols(java.lang.String,ghidra.program.model.address.AddressSetView)
        List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(input, null);

        if (!symbols.isEmpty()) {
            // Ghidra API: Symbol.getAddress() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html#getAddress()
            return symbols.get(0).getAddress();
        }

        // If not found as a symbol, try to parse as an address
        return parseAddress(program, input);
    }

    /**
     * Get the function containing the given address.
     *
     * @param program The Ghidra program
     * @param address The address to check
     * @return The containing function, or null if the address is not within a function
     */
    public static Function getContainingFunction(Program program, Address address) {
        if (program == null || address == null) {
            return null;
        }

        // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
        return program.getFunctionManager().getFunctionContaining(address);
    }

    /**
     * Get the data item containing or starting at the given address.
     *
     * @param program The Ghidra program
     * @param address The address to check
     * @return The data at or containing the address, or null if no data exists there
     */
    public static Data getContainingData(Program program, Address address) {
        if (program == null || address == null) {
            return null;
        }

        // Ghidra API: Program.getListing() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getListing()
        Listing listing = program.getListing();

        // Ghidra API: Listing.getDataAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getDataAt(ghidra.program.model.address.Address)
        Data data = listing.getDataAt(address);
        if (data != null) {
            return data;
        }

        // Ghidra API: Listing.getDataContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getDataContaining(ghidra.program.model.address.Address)
        return listing.getDataContaining(address);
    }

    /**
     * Check if an address could be an undefined function location.
     * An address is considered an undefined function location if:
     * - It's not inside a defined function
     * - It's in executable memory
     * - There's a valid instruction at that address
     *
     * This is useful for providing helpful error messages when users try to
     * modify variables at an address that has code but no defined function.
     *
     * @param program The Ghidra program
     * @param addressOrSymbol The address string or symbol name to check
     * @return true if this appears to be an undefined function location
     */
    public static boolean isUndefinedFunctionAddress(Program program, String addressOrSymbol) {
        if (program == null || addressOrSymbol == null || addressOrSymbol.trim().isEmpty()) {
            return false;
        }

        Address address = resolveAddressOrSymbol(program, addressOrSymbol);
        if (address == null) {
            return false;
        }

        return isUndefinedFunctionAddress(program, address);
    }

    /**
     * Check if an address could be an undefined function location.
     * An address is considered an undefined function location if:
     * - It's not inside a defined function
     * - It's in executable memory
     * - There's a valid instruction at that address
     *
     * @param program The Ghidra program
     * @param address The address to check
     * @return true if this appears to be an undefined function location
     */
    public static boolean isUndefinedFunctionAddress(Program program, Address address) {
        if (program == null || address == null) {
            return false;
        }

        // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionContaining(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
        if (program.getFunctionManager().getFunctionContaining(address) != null) {
            return false;
        }

        // Ghidra API: Program.getMemory(), Memory.getBlock(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getMemory()
        MemoryBlock block = program.getMemory().getBlock(address);
        // Ghidra API: MemoryBlock.isExecute() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html#isExecute()
        if (block == null || !block.isExecute()) {
            return false;
        }

        // Ghidra API: Program.getListing(), Listing.getInstructionAt(Address) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html#getInstructionAt(ghidra.program.model.address.Address)
        Instruction instr = program.getListing().getInstructionAt(address);
        return instr != null;
    }
}