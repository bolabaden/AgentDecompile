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
package agentdecompile.resources;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Base implementation of the ResourceProvider interface.
 * Provides common functionality for all resource providers.
 * <p>
 * MCP SDK: {@link io.modelcontextprotocol.server.McpSyncServer} -
 * <a href="https://github.com/modelcontextprotocol/java-sdk">MCP Java SDK</a>,
 * <a href="https://modelcontextprotocol.info/docs/sdk/java/mcp-server/">MCP Java Server</a>.
 * Ghidra API: {@link ghidra.program.model.listing.Program} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a>.
 * </p>
 */
public abstract class AbstractResourceProvider implements ResourceProvider {
    protected final McpSyncServer server;

    /**
     * Constructor
     * @param server The MCP server to register resources with
     */
    public AbstractResourceProvider(McpSyncServer server) {
        this.server = server;
    }

    @Override
    public void programOpened(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void programClosed(Program program) {
        // Default implementation does nothing
    }

    @Override
    public void cleanup() {
        // Default implementation does nothing
    }

    /**
     * Log an error message
     * @param message The message to log
     */
    protected void logError(String message) {
        // Ghidra API: Msg.error(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object)
        Msg.error(this, message);
    }

    /**
     * Log an error message with an exception
     * @param message The message to log
     * @param e The exception that caused the error
     */
    protected void logError(String message, Exception e) {
        // Ghidra API: Msg.error(Object, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
        Msg.error(this, message, e);
    }

    /**
     * Log an informational message
     * @param message The message to log
     */
    protected void logInfo(String message) {
        // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
        Msg.info(this, message);
    }
}
