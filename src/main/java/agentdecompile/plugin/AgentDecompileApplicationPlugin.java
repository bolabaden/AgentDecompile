/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agentdecompile.plugin;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.ShutdownHookRegistry;
import ghidra.framework.ShutdownPriority;
import ghidra.util.Msg;

import agentdecompile.server.McpServerManager;
import agentdecompile.services.AgentDecompileMcpService;
import agentdecompile.ui.CaptureDebugAction;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Application-level AgentDecompile plugin that manages the MCP server at Ghidra application level.
 * This plugin persists across tool sessions and ensures the MCP server remains
 * running even when individual analysis tools are closed and reopened.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "AgentDecompile",
    category = PluginCategoryNames.COMMON,
    shortDescription = "AgentDecompile Application Manager",
    description = "Manages the AgentDecompile MCP server at the Ghidra application level",
    servicesProvided = { AgentDecompileMcpService.class },
    servicesRequired = { FrontEndService.class }
)
public class AgentDecompileApplicationPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener {
    private McpServerManager serverManager;
    private FrontEndService frontEndService;
    private Project currentProject;
    private CaptureDebugAction captureDebugAction;

    /**
     * Plugin constructor.
     * @param tool The FrontEndTool that this plugin is added to
     */
    public AgentDecompileApplicationPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "AgentDecompile Application Plugin initializing...");
    }

    @Override
    protected void init() {
        super.init();

        // Initialize the MCP server manager
        serverManager = new McpServerManager(tool);

        // Register the service
        registerServiceProvided(AgentDecompileMcpService.class, serverManager);

        // Make server manager available via service registry for backward compatibility
        AgentDecompileInternalServiceRegistry.registerService(McpServerManager.class, serverManager);
        AgentDecompileInternalServiceRegistry.registerService(AgentDecompileMcpService.class, serverManager);

        // Start the MCP server
        serverManager.startServer();

        // Register for project events using FrontEndService
        frontEndService = tool.getService(FrontEndService.class);
        if (frontEndService != null) {
            frontEndService.addProjectListener(this);
        }

        // Check if there's already an active project
        Project activeProject = tool.getProjectManager().getActiveProject();
        if (activeProject != null) {
            projectOpened(activeProject);
        }

        // Register shutdown hook for clean server shutdown
        ShutdownHookRegistry.addShutdownHook(
            () -> {
                if (serverManager != null) {
                    serverManager.shutdown();
                }
            },
            ShutdownPriority.FIRST.after()
        );

        // Register debug capture menu action
        captureDebugAction = new CaptureDebugAction(getName(), tool);
        tool.addAction(captureDebugAction);

        Msg.info(this, "AgentDecompile Application Plugin initialization complete - MCP server running at application level");
    }

    @Override
    protected void dispose() {
        Msg.info(this, "AgentDecompile Application Plugin disposing...");

        // Remove debug capture action
        if (captureDebugAction != null) {
            tool.removeAction(captureDebugAction);
            captureDebugAction = null;
        }

        // Remove project listener
        if (frontEndService != null) {
            frontEndService.removeProjectListener(this);
            frontEndService = null;
        }

        // Clean up any active project state
        Project activeProject = tool.getProjectManager().getActiveProject();
        if (activeProject != null) {
            projectClosed(activeProject);
        }

        // Shutdown the MCP server
        if (serverManager != null) {
            serverManager.shutdown();
            serverManager = null;
        }

        // Clear service registry
        AgentDecompileInternalServiceRegistry.clearAllServices();

        super.dispose();
        Msg.info(this, "AgentDecompile Application Plugin disposed");
    }

    @Override
    public void projectOpened(Project project) {
        this.currentProject = project;
        Msg.debug(this, "Project opened: " + project.getName());
        // The MCP server doesn't need to restart - it continues serving across projects
    }

    @Override
    public void projectClosed(Project project) {
        if (this.currentProject == project) {
            this.currentProject = null;
        }
        Msg.info(this, "Project closed: " + project.getName());
        // The MCP server continues running even when projects are closed
    }

    /**
     * Get the current project
     * @return The currently open project, or null if no project is open
     */
    public Project getCurrentProject() {
        return currentProject;
    }

    /**
     * Get the MCP server manager
     * @return The server manager instance
     */
    public AgentDecompileMcpService getMcpService() {
        return serverManager;
    }
}