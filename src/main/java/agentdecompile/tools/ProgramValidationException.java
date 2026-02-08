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
package agentdecompile.tools;

/**
 * Exception thrown when program validation fails.
 * This exception is used to indicate various program-related errors such as:
 * - Program not found
 * - Program is in an invalid state (e.g., closed)
 * - Invalid program path provided
 * <p>
 * Used with {@link ghidra.program.model.listing.Program} lookup/validation.
 * See <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a>.
 * </p>
 */
public class ProgramValidationException extends RuntimeException {
    
    public ProgramValidationException(String message) {
        super(message);
    }
    
    public ProgramValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}