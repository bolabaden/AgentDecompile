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
package agentdecompile.plugin;

import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import agentdecompile.services.AgentDecompileMcpService;
import agentdecompile.ui.AgentDecompileProvider;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * AgentDecompile (Agent Decompile) tool plugin for Ghidra.
 * This tool-level plugin connects to the application-level MCP server
 * and handles program lifecycle events for this specific tool.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "AgentDecompile",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Agent Decompile (Tool)",
    description = "Tool-level AgentDecompile plugin that connects to the application-level MCP server"
)
public class AgentDecompilePlugin extends ProgramPlugin {
    private AgentDecompileProvider provider;
    private AgentDecompileMcpService mcpService;

    /**
     * Plugin constructor.
     * @param tool The plugin tool that this plugin is added to.
     */
    public AgentDecompilePlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "AgentDecompile Tool Plugin initializing...");

        // Register this plugin in the service registry so components can access it
        AgentDecompileInternalServiceRegistry.registerService(AgentDecompilePlugin.class, this);
    }

    @Override
    public void init() {
        super.init();

        // Get the MCP service from the application plugin
        mcpService = tool.getService(AgentDecompileMcpService.class);

        // Fallback for testing environments where ApplicationLevelPlugin isn't available
        if (mcpService == null) {
            mcpService = AgentDecompileInternalServiceRegistry.getService(AgentDecompileMcpService.class);
        }

        if (mcpService == null) {
            Msg.error(this, "AgentDecompileMcpService not available - AgentDecompileApplicationPlugin may not be loaded and no fallback service found");
            return;
        }

        // Register this tool with the MCP server
        mcpService.registerTool(tool);

        // Create the UI provider for status monitoring and configuration (only if GUI is available)
        try {
            if (!java.awt.GraphicsEnvironment.isHeadless()) {
                provider = new AgentDecompileProvider(this, getName());
                tool.addComponentProvider(provider, false);
                Msg.info(this, "AgentDecompile UI provider created successfully");
            } else {
                Msg.info(this, "Skipping UI provider creation in headless environment");
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to create UI provider, continuing without GUI: " + e.getMessage());
            provider = null;
        }

        Msg.info(this, "AgentDecompile Tool Plugin initialization complete - connected to application-level MCP server");
    }

    @Override
    protected void programOpened(Program program) {
        Msg.debug(this, "Program opened: " + program.getName());
        // Notify the program manager to handle cache management
        AgentDecompileProgramManager.programOpened(program);

        // Notify the MCP service about the program opening in this tool
        if (mcpService != null) {
            mcpService.programOpened(program, tool);
        }
    }

    @Override
    protected void programClosed(Program program) {
        Msg.info(this, "Program closed: " + program.getName());
        // Notify the program manager to clear stale cache
        AgentDecompileProgramManager.programClosed(program);

        // Notify the MCP service about the program closing in this tool
        if (mcpService != null) {
            mcpService.programClosed(program, tool);
        }
    }

    @Override
    protected void cleanup() {
        // Remove the UI provider
        if (provider != null) {
            tool.removeComponentProvider(provider);
        }

        // Unregister this tool from the MCP service
        if (mcpService != null) {
            mcpService.unregisterTool(tool);
        }

        // Only clear tool-specific services, not the application-level ones
        AgentDecompileInternalServiceRegistry.unregisterService(AgentDecompilePlugin.class);

        super.cleanup();
    }

    /**
     * Get all currently open programs in any Ghidra tool
     * @return List of open programs
     */
    public List<Program> getOpenPrograms() {
        return AgentDecompileProgramManager.getOpenPrograms();
    }

    /**
     * Get the MCP service instance
     * @return The MCP service, or null if not available
     */
    public AgentDecompileMcpService getMcpService() {
        return mcpService;
    }
}
