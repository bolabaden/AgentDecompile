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

import java.util.regex.Pattern;

/**
 * Utility methods for working with Ghidra symbols.
 * <p>
 * Used to detect default Ghidra-generated symbol names (FUN_, LAB_, DAT_, etc.).
 * Ghidra API: {@link ghidra.program.model.symbol.Symbol} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html">Symbol API</a>,
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SymbolTable.html">SymbolTable API</a>.
 * </p>
 */
public class SymbolUtil {
    // Regular expressions for Ghidra's default naming patterns
    private static final Pattern DEFAULT_NAME_PATTERN = Pattern.compile(
        "^(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY)_[0-9a-fA-F]+$"
    );

    /**
     * Check if a symbol name appears to be a default Ghidra-generated name
     * @param name The symbol name to check
     * @return True if the name follows Ghidra's default naming patterns
     */
    public static boolean isDefaultSymbolName(String name) {
        if (name == null) {
            return false;
        }

        return DEFAULT_NAME_PATTERN.matcher(name).matches();
    }
}
