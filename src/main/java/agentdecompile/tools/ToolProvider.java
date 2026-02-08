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

import ghidra.program.model.listing.Program;

/**
 * Interface for MCP tool providers.
 * Tool providers are responsible for registering and managing
 * MCP tools that allow interactive operations with Ghidra data.
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Program} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a>.
 * MCP Java SDK: <a href="https://github.com/modelcontextprotocol/java-sdk">MCP Java SDK</a>,
 * <a href="https://modelcontextprotocol.info/docs/sdk/java/mcp-server/">MCP Java Server</a>.
 * </p>
 */
public interface ToolProvider {
    /**
     * Register all tools with the MCP server
     */
    void registerTools();

    /**
     * Notify the provider that a program has been opened
     * @param program The program that was opened
     */
    void programOpened(Program program);

    /**
     * Notify the provider that a program has been closed
     * @param program The program that was closed
     */
    void programClosed(Program program);

    /**
     * Clean up any resources or state
     */
    void cleanup();
}
