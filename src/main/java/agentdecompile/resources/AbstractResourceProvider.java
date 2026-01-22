/* ###
 * IP: AgentDecompile
 *
 * Licensed under the Business Source License 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Licensor: bolabaden
 * Software: AgentDecompile
 * Change Date: 2030-01-01
 * Change License: Apache License, Version 2.0
 *
 * Under this License, you are granted the right to copy, modify,
 * create derivative works, redistribute, and make non‑production
 * use of the Licensed Work. The Licensor may provide an Additional
 * Use Grant permitting limited production use.
 *
 * On the Change Date, the Licensed Work will be made available
 * under the Change License identified above.
 *
 * The License Grant does not permit any use of the Licensed Work
 * beyond what is expressly allowed.
 *
 * If you violate any term of this License, your rights under it
 * terminate immediately.
 *
 * THE LICENSED WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE LICENSED WORK OR THE
 * USE OR OTHER DEALINGS IN THE LICENSED WORK.
 */
package agentdecompile.resources;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Base implementation of the ResourceProvider interface.
 * Provides common functionality for all resource providers.
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
        Msg.error(this, message);
    }

    /**
     * Log an error message with an exception
     * @param message The message to log
     * @param e The exception that caused the error
     */
    protected void logError(String message, Exception e) {
        Msg.error(this, message, e);
    }

    /**
     * Log an informational message
     * @param message The message to log
     */
    protected void logInfo(String message) {
        Msg.info(this, message);
    }
}
