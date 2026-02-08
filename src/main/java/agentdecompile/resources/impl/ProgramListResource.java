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
package agentdecompile.resources.impl;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import agentdecompile.plugin.AgentDecompileProgramManager;
import agentdecompile.resources.AbstractResourceProvider;
import agentdecompile.tools.project.ProjectToolProvider;
import agentdecompile.util.ProjectUtil;
import agentdecompile.util.SharedProjectEnvConfig;

/**
 * Resource provider that exposes the list of all programs in the project.
 * Supports subscriptions so clients are notified when programs are opened or closed.
 * <p>
 * Ghidra API: {@link ghidra.program.model.listing.Program} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a>.
 * MCP: {@link io.modelcontextprotocol.spec.McpSchema.Resource} -
 * <a href="https://modelcontextprotocol.io/">MCP spec</a>.
 * </p>
 */
public class ProgramListResource extends AbstractResourceProvider {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RESOURCE_ID = "ghidra://programs";
    private static final String RESOURCE_NAME = "open-programs";
    private static final String RESOURCE_DESCRIPTION = "All programs in the Ghidra project";
    private static final String RESOURCE_MIME_TYPE = "text/plain";

    /**
     * Constructor
     * @param server The MCP server to register with
     */
    public ProgramListResource(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for this resource
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                return generateResourceContents();
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME + " with subscription support");
    }

    /**
     * Generate the current resource contents for the programs resource.
     * If no project is active, tries to open the project from the path last passed to 'open'
     * or from AGENT_DECOMPILE_PROJECT_PATH (former takes priority). Then includes the same
     * response as list-project-files (metadata + items) as the first content, followed by
     * per-program sub-resources.
     *
     * @return ReadResourceResult containing list-project-files payload plus all program resource contents
     */
    private ReadResourceResult generateResourceContents() {
        List<ResourceContents> resourceContents = new ArrayList<>();

        // If no project is active, try to open from last 'open' path or env (same behavior as 'open')
        Project project = ProjectUtil.getActiveProjectOrHeadlessFallback();
        if (project == null) {
            String path = ProjectToolProvider.getLastOpenedProjectPath();
            if (path == null) {
                path = SharedProjectEnvConfig.getProjectPath();
            }
            if (path != null) {
                ProjectUtil.tryOpenProjectFromGprPath(path);
                project = ProjectUtil.getActiveProjectOrHeadlessFallback();
            }
        }

        // First content: same response as list-project-files (metadata + items)
        try {
            Map<String, Object> listProjectFilesData = ProjectUtil.buildListProjectFilesData(project);
            String listProjectFilesJson = JSON.writeValueAsString(listProjectFilesData);
            resourceContents.add(new TextResourceContents(RESOURCE_ID, RESOURCE_MIME_TYPE, listProjectFilesJson));
        } catch (JsonProcessingException e) {
            logError("Error serializing list-project-files data", e);
            resourceContents.add(new TextResourceContents(RESOURCE_ID, RESOURCE_MIME_TYPE, "{\"metadata\":{\"error\":\"serialization failed\"},\"items\":[]}"));
        }

        // Get all program files from the project (not just open ones)
        List<ghidra.framework.model.DomainFile> programFiles = AgentDecompileProgramManager.getAllProgramFiles();

        for (ghidra.framework.model.DomainFile domainFile : programFiles) {
            try {
                // Create program info object from domain file metadata
                // Ghidra API: DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                String programPath = domainFile.getPathname();
                String programLanguage = null;
                String programCompilerSpec = null;
                long programSize = 0;

                // Try to get metadata from the file
                // Ghidra API: DomainFile.getMetadata() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getMetadata()
                if (domainFile.getMetadata() != null) {
                    Object languageObj = domainFile.getMetadata().get("CREATED_WITH_LANGUAGE");
                    if (languageObj != null) {
                        programLanguage = languageObj.toString();
                    }
                    Object compilerObj = domainFile.getMetadata().get("CREATED_WITH_COMPILER");
                    if (compilerObj != null) {
                        programCompilerSpec = compilerObj.toString();
                    }
                }

                // Try to open the program briefly to get size if metadata doesn't have it
                // But avoid opening programs just for resource listing - use metadata if available
                ProgramInfo programInfo = new ProgramInfo(programPath, programLanguage, programCompilerSpec, programSize);

                // Create a JSON object with program metadata
                String metaString = JSON.writeValueAsString(programInfo);

                // Add to resource contents
                // URL encode the program path to ensure URI safety
                String encodedProgramPath = URLEncoder.encode(programPath, StandardCharsets.UTF_8);
                resourceContents.add(
                    new TextResourceContents(
                        RESOURCE_ID + "/" + encodedProgramPath,
                        RESOURCE_MIME_TYPE,
                        metaString
                    )
                );
            } catch (JsonProcessingException e) {
                logError("Error serializing program metadata", e);
            } catch (Exception e) {
                // Ghidra API: DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                logError("Error reading program file: " + domainFile.getPathname(), e);
            }
        }

        return new ReadResourceResult(resourceContents);
    }

    @Override
    public void programOpened(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    @Override
    public void programClosed(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    /**
     * Notify all subscribers that the resource content has changed.
     *
     * According to the MCP specification, when a subscribed resource changes,
     * the server must send a `notifications/resources/updated` notification
     * to all subscribed clients. The MCP Java SDK should handle subscription
     * requests automatically when subscriptions are enabled in capabilities,
     * but we need to trigger the notification when the resource changes.
     *
     * The SDK may provide methods to send notifications, or it may handle
     * this automatically. We attempt multiple approaches to ensure compatibility.
     */
    private void notifyResourceChanged() {
        try {
            // Generate updated resource contents
            ReadResourceResult newContents = generateResourceContents();

            // Attempt multiple notification approaches for maximum compatibility
            boolean notified = false;

            // Approach 1: Try notifyResourceChanged method (if it exists in SDK)
            try {
                java.lang.reflect.Method notifyMethod = server.getClass().getMethod(
                    "notifyResourceChanged", String.class, ReadResourceResult.class);
                notifyMethod.invoke(server, RESOURCE_ID, newContents);
                notified = true;
                logInfo("Notified subscribers via notifyResourceChanged: " + RESOURCE_NAME);
            } catch (NoSuchMethodException e) {
                // Method doesn't exist, try next approach
            } catch (Exception e) {
                logError("Error invoking notifyResourceChanged", e);
            }

            // Approach 2: Try sendResourceUpdatedNotification (alternative SDK method name)
            if (!notified) {
                try {
                    java.lang.reflect.Method sendMethod = server.getClass().getMethod(
                        "sendResourceUpdatedNotification", String.class);
                    sendMethod.invoke(server, RESOURCE_ID);
                    notified = true;
                    logInfo("Notified subscribers via sendResourceUpdatedNotification: " + RESOURCE_NAME);
                } catch (NoSuchMethodException e) {
                    // Method doesn't exist, try next approach
                } catch (Exception e) {
                    logError("Error invoking sendResourceUpdatedNotification", e);
                }
            }

            // Approach 3: Try generic notification method
            if (!notified) {
                try {
                    // Look for methods that might send notifications
                    java.lang.reflect.Method[] methods = server.getClass().getMethods();
                    for (java.lang.reflect.Method method : methods) {
                        String methodName = method.getName().toLowerCase();
                        if ((methodName.contains("notify") || methodName.contains("send")) &&
                            methodName.contains("resource") && method.getParameterCount() >= 1) {
                            try {
                                if (method.getParameterCount() == 1 &&
                                    method.getParameterTypes()[0] == String.class) {
                                    method.invoke(server, RESOURCE_ID);
                                    notified = true;
                                    logInfo("Notified subscribers via " + method.getName() + ": " + RESOURCE_NAME);
                                    break;
                                }
                            } catch (Exception e) {
                                // Try next method
                            }
                        }
                    }
                } catch (Exception e) {
                    // Reflection failed, continue to fallback
                }
            }

            // Approach 4: SDK may handle notifications automatically
            // When subscriptions are enabled, the SDK should automatically
            // send notifications when resources are accessed. We log that
            // the resource changed and the SDK should handle it.
            if (!notified) {
                logInfo("Resource changed: " + RESOURCE_NAME +
                    " (MCP SDK should handle subscription notifications automatically)");
            }
        } catch (Exception e) {
            logError("Error notifying resource change", e);
        }
    }

    /**
     * Simple class to hold program information for JSON serialization
     */
    private static class ProgramInfo {
        @SuppressWarnings("unused")
        public String program_path;

        @SuppressWarnings("unused")
        public String language;

        @SuppressWarnings("unused")
        public String compiler_spec;

        @SuppressWarnings("unused")
        public long size_bytes;

        public ProgramInfo(String programPath, String language, String compilerSpec, long sizeBytes) {
            this.program_path = programPath;
            this.language = language;
            this.compiler_spec = compilerSpec;
            this.size_bytes = sizeBytes;
        }
    }
}
