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
package agentdecompile.debug;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;

import agentdecompile.plugin.ConfigManager;
import agentdecompile.plugin.AgentDecompileProgramManager;
import agentdecompile.server.McpServerManager;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Collects debug information from the system, Ghidra, and AgentDecompile for troubleshooting.
 * Returns Maps suitable for JSON serialization.
 * <p>
 * Ghidra API: {@link ghidra.framework.Application}, {@link ghidra.program.model.listing.Program},
 * {@link ghidra.util.extensions.ExtensionUtils} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/Application.html">Application API</a>.
 * </p>
 */
public class DebugInfoCollector {

    /**
     * Collect all debug information into a single map.
     * @param userMessage Optional user-provided message describing the issue
     * @return Map containing all collected debug information
     */
    public Map<String, Object> collectAll(String userMessage) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("captureTimestamp", Instant.now().toString());
        info.put("userMessage", userMessage != null ? userMessage : "(No message provided)");
        info.put("system", collectSystemInfo());
        info.put("ghidra", collectGhidraInfo());
        info.put("agentdecompile", collectAgentDecompileInfo());
        info.put("mcpServer", collectMcpServerInfo());
        info.put("programs", collectOpenPrograms());
        return info;
    }

    /**
     * Collect system information (Java, OS).
     */
    public Map<String, Object> collectSystemInfo() {
        Map<String, Object> system = new LinkedHashMap<>();
        system.put("javaVersion", System.getProperty("java.version"));
        system.put("javaVendor", System.getProperty("java.vendor"));
        system.put("osName", System.getProperty("os.name"));
        system.put("osVersion", System.getProperty("os.version"));
        system.put("osArch", System.getProperty("os.arch"));
        return system;
    }

    /**
     * Collect Ghidra information (version, extensions).
     */
    public Map<String, Object> collectGhidraInfo() {
        Map<String, Object> ghidra = new LinkedHashMap<>();

        try {
            // Ghidra API: Application.getApplicationVersion() - https://ghidra.re/ghidra_docs/api/ghidra/framework/Application.html#getApplicationVersion()
            ghidra.put("version", Application.getApplicationVersion());
        } catch (Exception e) {
            ghidra.put("version", "Error: " + e.getMessage());
        }

        // Collect installed extensions
        List<Map<String, Object>> extensions = new ArrayList<>();
        try {
            // Ghidra API: ExtensionUtils.getInstalledExtensions() - https://ghidra.re/ghidra_docs/api/ghidra/util/extensions/ExtensionUtils.html#getInstalledExtensions()
            Set<ExtensionDetails> installedExtensions = ExtensionUtils.getInstalledExtensions();
            for (ExtensionDetails ext : installedExtensions) {
                Map<String, Object> extInfo = new LinkedHashMap<>();
                extInfo.put("name", ext.getName());
                extInfo.put("version", ext.getVersion());
                extInfo.put("author", ext.getAuthor());
                extInfo.put("description", ext.getDescription());
                extensions.add(extInfo);
            }
        } catch (Exception e) {
            Map<String, Object> errorInfo = new LinkedHashMap<>();
            errorInfo.put("error", "Failed to get extensions: " + e.getMessage());
            extensions.add(errorInfo);
        }
        ghidra.put("extensions", extensions);

        return ghidra;
    }

    /**
     * Collect AgentDecompile configuration and status.
     */
    public Map<String, Object> collectAgentDecompileInfo() {
        Map<String, Object> agentdecompile = new LinkedHashMap<>();
        agentdecompile.put("version", getAgentDecompileVersion());

        // Get configuration
        ConfigManager config = AgentDecompileInternalServiceRegistry.getService(ConfigManager.class);
        if (config != null) {
            Map<String, Object> configInfo = new LinkedHashMap<>();
            configInfo.put("serverEnabled", config.isServerEnabled());
            configInfo.put("serverPort", config.getServerPort());
            configInfo.put("serverHost", config.getServerHost());
            configInfo.put("debugMode", config.isDebugMode());
            configInfo.put("apiKeyEnabled", config.isApiKeyEnabled());
            configInfo.put("decompilerTimeoutSeconds", config.getDecompilerTimeoutSeconds());
            configInfo.put("maxDecompilerSearchFunctions", config.getMaxDecompilerSearchFunctions());
            agentdecompile.put("config", configInfo);
        } else {
            agentdecompile.put("config", "ConfigManager not available");
        }

        return agentdecompile;
    }

    /**
     * Collect MCP server status and registered tools.
     */
    public Map<String, Object> collectMcpServerInfo() {
        Map<String, Object> mcpServer = new LinkedHashMap<>();

        McpServerManager serverManager = AgentDecompileInternalServiceRegistry.getService(McpServerManager.class);
        if (serverManager != null) {
            mcpServer.put("running", serverManager.isServerRunning());
            mcpServer.put("port", serverManager.getServerPort());
            mcpServer.put("host", serverManager.getServerHost());
            mcpServer.put("headlessMode", serverManager.isHeadlessMode());

            // Get registered tool provider names
            List<String> toolProviderNames = new ArrayList<>();
            List<String> toolProviders = serverManager.getToolProviders();
            if (toolProviders != null) {
                toolProviderNames.addAll(toolProviders);
            }
            mcpServer.put("toolProviders", toolProviderNames);

            // Get registered PluginTools count
            mcpServer.put("registeredToolsCount", serverManager.getRegisteredToolsCount());
        } else {
            mcpServer.put("error", "McpServerManager not available");
        }

        return mcpServer;
    }

    /**
     * Collect information about open programs.
     */
    public List<Map<String, Object>> collectOpenPrograms() {
        List<Map<String, Object>> programs = new ArrayList<>();

        try {
            for (Program program : AgentDecompileProgramManager.getOpenPrograms()) {
                Map<String, Object> progInfo = new LinkedHashMap<>();
                // Ghidra API: Program.getDomainFile(), DomainFile.getPathname(), getName(), getLanguage(), getCompilerSpec() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                progInfo.put("path", program.getDomainFile().getPathname());
                progInfo.put("name", program.getName());
                progInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                progInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                // Ghidra API: Program.getFunctionManager(), FunctionManager.getFunctionCount(), getSymbolTable(), SymbolTable.getNumSymbols() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getFunctionManager()
                progInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                progInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programs.add(progInfo);
            }
        } catch (Exception e) {
            Map<String, Object> errorInfo = new LinkedHashMap<>();
            errorInfo.put("error", "Failed to get programs: " + e.getMessage());
            programs.add(errorInfo);
        }

        return programs;
    }

    /**
     * Get the AgentDecompile extension version from the installed extension metadata.
     * Falls back to "dev" if the extension is not found (e.g., running from source).
     */
    private String getAgentDecompileVersion() {
        try {
            // Ghidra API: ExtensionUtils.getInstalledExtensions() - https://ghidra.re/ghidra_docs/api/ghidra/util/extensions/ExtensionUtils.html#getInstalledExtensions()
            Set<ExtensionDetails> installedExtensions = ExtensionUtils.getInstalledExtensions();
            for (ExtensionDetails ext : installedExtensions) {
                // Ghidra API: ExtensionDetails.getName(), getVersion() - https://ghidra.re/ghidra_docs/api/ghidra/util/extensions/ExtensionDetails.html#getName()
                if ("AgentDecompile".equals(ext.getName())) {
                    String version = ext.getVersion();
                    // Return version if available and not the placeholder
                    if (version != null && !version.isEmpty() && !version.contains("@")) {
                        return version;
                    }
                }
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return "dev";
    }
}
