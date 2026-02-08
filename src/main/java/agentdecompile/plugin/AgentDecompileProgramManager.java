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
package agentdecompile.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.task.ProgramOpener;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import agentdecompile.util.AgentDecompileInternalServiceRegistry;

/**
 * Manages access to open programs in Ghidra.
 * This is a singleton service that can be accessed throughout the application.
 * <p>
 * Ghidra API references:
 * <ul>
 *   <li>{@link ghidra.program.model.listing.Program} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a></li>
 *   <li>{@link ghidra.framework.model.Project} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html">Project API</a></li>
 *   <li>{@link ghidra.framework.model.DomainFile} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html">DomainFile API</a></li>
 *   <li>{@link ghidra.app.util.task.ProgramOpener} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/util/task/ProgramOpener.html">ProgramOpener API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class AgentDecompileProgramManager {
    // Cache of opened programs by path to avoid repeatedly opening the same program
    private static final Map<String, Program> programCache = new HashMap<>();

    // Registry of directly opened programs (mainly for test environments)
    private static final Map<String, Program> registeredPrograms = new HashMap<>();

    // Stable consumer used for cached program opens/releases
    private static final Object CACHE_CONSUMER = new Object();

    /**
     * Get all currently open programs in any Ghidra tool.
     * If no programs are open, automatically opens all programs from the project.
     * @return List of open programs (never empty if programs exist in project)
     */
    public static List<Program> getOpenPrograms() {
        List<Program> openPrograms = new ArrayList<>();

        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "No active project found");
            return getCachedAndRegisteredPrograms();
        }

        // Ghidra API: Project.getToolManager() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getToolManager()
        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            // Ghidra API: ToolManager.getRunningTools() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html#getRunningTools()
            PluginTool[] runningTools = toolManager.getRunningTools();
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Found " + runningTools.length + " running tools");

            for (PluginTool tool : runningTools) {
                // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    // Ghidra API: ProgramManager.getAllOpenPrograms() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html#getAllOpenPrograms()
                    Program[] programs = programManager.getAllOpenPrograms();
                    // Ghidra API: Msg.debug(Class, String), PluginTool.getName() - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AgentDecompileProgramManager.class, "Tool " + tool.getName() + " has " + programs.length + " open programs");
                    for (Program program : programs) {
                        // Ghidra API: Program.isClosed(), getName(), getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getName(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                            // Ghidra API: Msg.debug(Class, String), Program.getName(), Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                            Msg.debug(AgentDecompileProgramManager.class, "Added program: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    // Ghidra API: Msg.debug(Class, String), PluginTool.getName() - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AgentDecompileProgramManager.class, "Tool " + tool.getName() + " has no ProgramManager service");
                }
            }
        } else {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "No tool manager found");
        }

        // If no tools were found (common in test environments),
        // try to get programs directly from the AgentDecompilePlugin's tool
        if (openPrograms.isEmpty()) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "No programs found via ToolManager, trying AgentDecompilePlugin tool");
            AgentDecompilePlugin agentdecompilePlugin = AgentDecompileInternalServiceRegistry.getService(AgentDecompilePlugin.class);
            if (agentdecompilePlugin != null && agentdecompilePlugin.getTool() != null) {
                // Ghidra API: PluginTool getTool() - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html
                PluginTool tool = agentdecompilePlugin.getTool();
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin tool has " + programs.length + " open programs");
                    for (Program program : programs) {
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                            // Ghidra API: Msg.debug(Class, String), Program.getName(), Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                            Msg.debug(AgentDecompileProgramManager.class, "Added program from AgentDecompilePlugin: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin tool has no ProgramManager service");
                }
            } else {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin not found or has no tool");
            }
        }

        // Also include programs from cache and registered programs (for programs opened via getProgramByPath)
        List<Program> cachedAndRegistered = getCachedAndRegisteredPrograms();
        for (Program program : cachedAndRegistered) {
            if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                openPrograms.add(program);
                // Ghidra API: Msg.debug(Class, String), Program.getName(), Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(AgentDecompileProgramManager.class, "Added cached/registered program: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
            }
        }

        // If still no programs are open, automatically open all programs from the project
        if (openPrograms.isEmpty()) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "No programs currently open, auto-opening programs from project");
            List<String> projectProgramPaths = collectProgramPathsFromProject(project);
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Found " + projectProgramPaths.size() + " programs in project");

            for (String programPath : projectProgramPaths) {
                try {
                    Program program = getProgramByPath(programPath);
                    if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                        openPrograms.add(program);
                        // Ghidra API: Msg.info(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
                        Msg.info(AgentDecompileProgramManager.class, "Auto-opened program from project: " + programPath);
                    }
                } catch (Exception e) {
                    // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                    Msg.debug(AgentDecompileProgramManager.class, "Failed to auto-open program " + programPath + ": " + e.getMessage());
                }
            }
        }

        // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
        Msg.debug(AgentDecompileProgramManager.class, "Total open programs found: " + openPrograms.size());
        return openPrograms;
    }

    /**
     * Get all currently open programs without auto-opening programs from project.
     * This is used by getProgramByPath to check if a specific program is already open
     * before attempting to open it from the project.
     * @return List of currently open programs (without auto-opening)
     */
    private static List<Program> getOpenProgramsWithoutAutoOpen() {
        List<Program> openPrograms = new ArrayList<>();

        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "No active project found");
            return getCachedAndRegisteredPrograms();
        }

        // Ghidra API: Project.getToolManager() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getToolManager()
        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            // Ghidra API: ToolManager.getRunningTools() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html#getRunningTools()
            PluginTool[] runningTools = toolManager.getRunningTools();
            for (PluginTool tool : runningTools) {
                // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    // Ghidra API: ProgramManager.getAllOpenPrograms() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html#getAllOpenPrograms()
                    Program[] programs = programManager.getAllOpenPrograms();
                    for (Program program : programs) {
                        // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                        }
                    }
                }
            }
        }

        if (openPrograms.isEmpty()) {
            AgentDecompilePlugin agentdecompilePlugin = AgentDecompileInternalServiceRegistry.getService(AgentDecompilePlugin.class);
            if (agentdecompilePlugin != null && agentdecompilePlugin.getTool() != null) {
                // Ghidra API: AgentDecompilePlugin.getTool() - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html
                PluginTool tool = agentdecompilePlugin.getTool();
                // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    // Ghidra API: ProgramManager.getAllOpenPrograms() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html#getAllOpenPrograms()
                    Program[] programs = programManager.getAllOpenPrograms();
                    for (Program program : programs) {
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                        }
                    }
                }
            }
        }

        // Also include programs from cache and registered programs
        List<Program> cachedAndRegistered = getCachedAndRegisteredPrograms();
        for (Program program : cachedAndRegistered) {
            if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                openPrograms.add(program);
            }
        }

        return openPrograms;
    }

    /**
     * Get programs from cache and registered programs that are still valid.
     * @return List of valid cached/registered programs
     */
    private static List<Program> getCachedAndRegisteredPrograms() {
        List<Program> programs = new ArrayList<>();

        for (Program program : programCache.values()) {
            // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
            if (program != null && !program.isClosed()) {
                programs.add(program);
            }
        }

        for (Program program : registeredPrograms.values()) {
            if (program != null && !program.isClosed() && !programs.contains(program)) {
                programs.add(program);
            }
        }

        return programs;
    }

    /**
     * Collect all program paths from the project recursively.
     * @param project The active project
     * @return List of program paths found in the project
     */
    private static List<String> collectProgramPathsFromProject(Project project) {
        List<String> paths = new ArrayList<>();
        if (project == null) {
            return paths;
        }

        try {
            // Ghidra API: Project.getProjectData(), ProjectData.getRootFolder() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getProjectData(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getRootFolder()
            DomainFolder rootFolder = project.getProjectData().getRootFolder();
            collectProgramPathsRecursive(rootFolder, paths);
        } catch (Exception e) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Error collecting program paths from project: " + e.getMessage());
        }

        return paths;
    }

    /**
     * Recursively collect program paths from a domain folder.
     * @param folder The folder to search
     * @param paths The list to add paths to
     */
    private static void collectProgramPathsRecursive(DomainFolder folder, List<String> paths) {
        if (folder == null) {
            return;
        }

        // Add programs in this folder
        // Ghidra API: DomainFolder.getFiles() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html#getFiles()
        for (DomainFile file : folder.getFiles()) {
            // Ghidra API: DomainFile.getContentType() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getContentType()
            if ("Program".equals(file.getContentType())) {
                // Ghidra API: DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                paths.add(file.getPathname());
            }
        }

        // Ghidra API: DomainFolder.getFolders() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html#getFolders()
        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramPathsRecursive(subfolder, paths);
        }
    }

    /**
     * Get all program domain files from the project.
     * @return List of DomainFile objects for all programs in the project
     */
    public static List<DomainFile> getAllProgramFiles() {
        List<DomainFile> programFiles = new ArrayList<>();
        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return programFiles;
        }

        try {
            // Ghidra API: Project.getProjectData(), ProjectData.getRootFolder() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getProjectData(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getRootFolder()
            DomainFolder rootFolder = project.getProjectData().getRootFolder();
            collectProgramFilesRecursive(rootFolder, programFiles);
        } catch (Exception e) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Error collecting program files from project: " + e.getMessage());
        }

        return programFiles;
    }

    /**
     * Recursively collect program domain files from a domain folder.
     * @param folder The folder to search
     * @param programFiles The list to add domain files to
     */
    private static void collectProgramFilesRecursive(DomainFolder folder, List<DomainFile> programFiles) {
        if (folder == null) {
            return;
        }

        // Ghidra API: DomainFolder.getFiles() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html#getFiles()
        for (DomainFile file : folder.getFiles()) {
            // Ghidra API: DomainFile.getContentType() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getContentType()
            if ("Program".equals(file.getContentType())) {
                programFiles.add(file);
            }
        }

        // Ghidra API: DomainFolder.getFolders() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html#getFolders()
        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramFilesRecursive(subfolder, programFiles);
        }
    }

    /**
     * Register a program directly with the manager. This is useful in test environments
     * or when programs are opened outside of the normal Ghidra tool system.
     * @param program The program to register
     */
    public static void registerProgram(Program program) {
        if (program != null && !program.isClosed()) {
            // Ghidra API: Program.getDomainFile() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.put(programPath, program);
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Registered program: " + programPath);
        }
    }

    /**
     * Unregister a program from the manager.
     * @param program The program to unregister
     */
    public static void unregisterProgram(Program program) {
        if (program != null) {
            // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Unregistered program: " + programPath);
        }
    }

    /**
     * Clear stale cache entries when a program is closed.
     * This should be called when a program is closed to prevent stale references.
     * @param program The program that was closed
     */
    public static void programClosed(Program program) {
        if (program != null) {
            // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Program closed, cleared cache: " + programPath);
        }
    }

    /**
     * Handle when a program is opened.
     * This ensures proper cache management and can be used to refresh stale entries.
     * @param program The program that was opened
     */
    public static void programOpened(Program program) {
        // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
        if (program != null && !program.isClosed()) {
            // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String programPath = program.getDomainFile().getPathname();
            programCache.remove(programPath);
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Program opened, cleared stale cache: " + programPath);
        }
    }

    /**
     * Get the canonical domain path for a program
     * @param program The program to get the canonical path for
     * @return The canonical domain path
     */
    public static String getCanonicalProgramPath(Program program) {
        // Ghidra API: Program.getDomainFile() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
        return program.getDomainFile().getPathname();
    }

    /**
     * Ensure a program is checked out if it's under version control.
     * This prevents the "Versioned File not Checked Out" dialog when making changes.
     * @param program The program to check out
     * @param programPath The path of the program (for logging)
     */
    private static void ensureCheckedOut(Program program, String programPath) {
        if (program == null) {
            return;
        }

        // Ghidra API: Program.getDomainFile() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile()
        DomainFile domainFile = program.getDomainFile();
        // Ghidra API: DomainFile.isVersioned(), isCheckedOut(), isReadOnly() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isVersioned(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isCheckedOut(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#isReadOnly()
        Msg.debug(AgentDecompileProgramManager.class,
            "Program state - versioned: " + domainFile.isVersioned() +
            ", checked out: " + domainFile.isCheckedOut() +
            ", read-only: " + domainFile.isReadOnly());

        if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
            try {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(AgentDecompileProgramManager.class,
                    "Attempting auto-checkout for: " + programPath);
                // Ghidra API: DomainFile.checkout(boolean, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#checkout(boolean,ghidra.util.task.TaskMonitor)
                boolean success = domainFile.checkout(false, TaskMonitor.DUMMY);
                if (success) {
                    // Ghidra API: Msg.info(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
                    Msg.info(AgentDecompileProgramManager.class,
                        "Auto-checked out versioned program: " + programPath);
                } else {
                    // Ghidra API: Msg.warn(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
                    Msg.warn(AgentDecompileProgramManager.class,
                        "Failed to auto-checkout versioned program: " + programPath +
                        " (may be checked out exclusively by another user)");
                }
            } catch (CancelledException | IOException e) {
                // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
                Msg.error(AgentDecompileProgramManager.class,
                    "Could not auto-checkout program " + programPath + ": " + e.getMessage(), e);
                // Continue anyway - program is still usable in read-only mode
            }
        }
    }

    /**
     * Get a program by its path
     * @param programPath Path to the program
     * @return Program object or null if not found
     */
    public static Program getProgramByPath(String programPath) {
        if (programPath == null) {
            return null;
        }

        // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
        Msg.debug(AgentDecompileProgramManager.class, "Looking for program with path: " + programPath);

        if (registeredPrograms.containsKey(programPath)) {
            Program registeredProgram = registeredPrograms.get(programPath);
            // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
            if (!registeredProgram.isClosed()) {
                Msg.debug(AgentDecompileProgramManager.class, "Found program in registry: " + programPath);
                ensureCheckedOut(registeredProgram, programPath);
                return registeredProgram;
            } else {
                // Remove invalid programs from registry
                registeredPrograms.remove(programPath);
            }
        }

        // Check cache next
        if (programCache.containsKey(programPath)) {
            Program cachedProgram = programCache.get(programPath);
            if (!cachedProgram.isClosed()) {
                Msg.debug(AgentDecompileProgramManager.class, "Found program in cache: " + programPath);
                ensureCheckedOut(cachedProgram, programPath);
                return cachedProgram;
            } else {
                // Remove invalid programs from cache
                programCache.remove(programPath);
            }
        }

        List<Program> openPrograms = getOpenProgramsWithoutAutoOpen();
        Msg.debug(AgentDecompileProgramManager.class, "Checking " + openPrograms.size() + " currently open programs");

        for (Program program : openPrograms) {
            // Check the Ghidra project path first (most common case)
            // Ghidra API: Program.getDomainFile() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String domainPath = program.getDomainFile().getPathname();
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class, "Comparing '" + programPath + "' with domain path '" + domainPath + "'");
            if (domainPath.equals(programPath)) {
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(AgentDecompileProgramManager.class, "Found program by domain path: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }

            // Also check executable path and name for backward compatibility
            // Ghidra API: Program.getExecutablePath(), getName() (DomainObject) - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getExecutablePath(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getName()
            String executablePath = program.getExecutablePath();
            String programName = program.getName();
            Msg.debug(AgentDecompileProgramManager.class, "Also checking executable path '" + executablePath + "' and name '" + programName + "'");
            if (executablePath.equals(programPath) || programName.equals(programPath)) {
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(AgentDecompileProgramManager.class, "Found program by executable path or name: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }
        }

        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            // Ghidra API: Msg.warn(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
            Msg.warn(AgentDecompileProgramManager.class, "No active project");
            return null;
        }

        // Handle paths that may include folders (e.g., "/imported/program.exe")
        DomainFile domainFile = null;

        if (programPath.startsWith("/")) {
            // Remove leading slash for processing
            String relativePath = programPath.substring(1);
            int lastSlash = relativePath.lastIndexOf('/');

            if (lastSlash > 0) {
                // Path contains folders - need to get the folder first, then the file
                String folderPath = "/" + relativePath.substring(0, lastSlash);
                String fileName = relativePath.substring(lastSlash + 1);

                // Ghidra API: ProjectData.getFolder(String), DomainFolder.getFile(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getFolder(java.lang.String)
                // Ghidra API: ProjectData.getFolder(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getFolder(java.lang.String)
                DomainFolder folder = project.getProjectData().getFolder(folderPath);
                if (folder != null) {
                    // Ghidra API: DomainFolder.getFile(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFolder.html#getFile(java.lang.String)
                    domainFile = folder.getFile(fileName);
                }
            } else {
                // Ghidra API: ProjectData.getRootFolder(), DomainFolder.getFile(String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getRootFolder()
                domainFile = project.getProjectData().getRootFolder().getFile(relativePath);
            }
        } else {
            domainFile = project.getProjectData().getRootFolder().getFile(programPath);
        }

        if (domainFile == null) {
            // Ghidra API: Msg.warn(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
            Msg.warn(AgentDecompileProgramManager.class, "Could not find program: " + programPath);
            return null;
        }

        // Open the program programmatically to avoid upgrade dialogs
        // Use getDomainObject with TaskMonitor.DUMMY to handle upgrades automatically
        // This approach bypasses GUI dialogs and handles upgrades in the background
        Program program = null;
        try {
            // Open the program using getDomainObject - this handles upgrades automatically
            // Parameters: consumer, readOnly, okToUpgrade, monitor
            // Use the class itself as the consumer to ensure a stable, non-null reference
            // false for readOnly means open for update
            // false for okToUpgrade means don't show upgrade dialogs (upgrades happen automatically)
            // Ghidra API: DomainFile.getDomainObject(DomainObjectConsumer, boolean, boolean, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getDomainObject(ghidra.framework.model.DomainObjectConsumer,boolean,boolean,ghidra.util.task.TaskMonitor)
            DomainObject domainObject = domainFile.getDomainObject(CACHE_CONSUMER, false, false, TaskMonitor.DUMMY);

            if (domainObject instanceof Program prog1) {
                program = prog1;
            } else {
                // Ghidra API: Msg.warn(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
                Msg.warn(AgentDecompileProgramManager.class, "Domain object is not a Program: " + programPath);
                if (domainObject != null) {
                    // Ghidra API: DomainObject.release(DomainObjectConsumer) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#release(ghidra.framework.model.DomainObjectConsumer)
                    domainObject.release(CACHE_CONSUMER);
                }
            }
        } catch (CancelledException | VersionException | IOException e) {
            // Ghidra API: Msg.error(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object,java.lang.Throwable)
            Msg.error(AgentDecompileProgramManager.class, "Failed to open program " + programPath + ": " + e.getMessage(), e);
            try {
                // Ghidra API: ProgramOpener.openProgram(ProgramLocator, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/util/task/ProgramOpener.html#openProgram(ghidra.app.plugin.core.progmgr.ProgramLocator,ghidra.util.task.TaskMonitor)
                ProgramOpener programOpener = new ProgramOpener(CACHE_CONSUMER);
                ProgramLocator locator = new ProgramLocator(domainFile);
                program = programOpener.openProgram(locator, TaskMonitor.DUMMY);
            } catch (Exception fallbackException) {
                Msg.error(AgentDecompileProgramManager.class, "Fallback ProgramOpener also failed: " + fallbackException.getMessage(), fallbackException);
            }
        }

        if (program != null) {
            // Ensure the program is checked out if versioned
            ensureCheckedOut(program, programPath);

            // Use canonical domain path as cache key for consistency
            String canonicalPath = getCanonicalProgramPath(program);
            programCache.put(canonicalPath, program);
        }

        return program;
    }

    /**
     * Check if a program is currently held in the cache as a consumer
     * @param program The program to check
     * @return true if the program is in the cache
     */
    public static boolean isProgramCached(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }
        // Ghidra API: Program.isClosed() (above) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
        String canonicalPath = getCanonicalProgramPath(program);
        return programCache.containsKey(canonicalPath) &&
               programCache.get(canonicalPath) == program;
    }

    /**
     * Release a program from the cache, removing it as a consumer.
     * This is needed before version control operations which require no active consumers.
     * @param program The program to release from cache
     * @return true if the program was in the cache and released, false otherwise
     */
    public static boolean releaseProgramFromCache(Program program) {
        // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
        if (program == null || program.isClosed()) {
            return false;
        }

        String canonicalPath = getCanonicalProgramPath(program);
        Program cachedProgram = programCache.remove(canonicalPath);

        if (cachedProgram != null && cachedProgram == program) {
            // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
            Msg.debug(AgentDecompileProgramManager.class,
                "Releasing program from cache: " + canonicalPath);
            try {
                // Ghidra API: Program.release(DomainObjectConsumer) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#release(ghidra.framework.model.DomainObjectConsumer)
                program.release(CACHE_CONSUMER);
            } catch (Exception e) {
                // Ghidra API: Msg.warn(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object,java.lang.Throwable)
                Msg.warn(AgentDecompileProgramManager.class,
                    "Failed to release cached program consumer for " + canonicalPath + ": " + e.getMessage(), e);
            }
            return true;
        }

        return false;
    }

    /**
     * Re-open a program and add it back to the cache after it was released.
     * This restores the cache state after operations that required releasing the program.
     * @param programPath The path to the program to re-open
     * @return The re-opened program, or null if it could not be opened
     */
    public static Program reopenProgramToCache(String programPath) {
        if (programPath == null) {
            return null;
        }

        // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
        Msg.debug(AgentDecompileProgramManager.class,
            "Re-opening program to cache: " + programPath);

        programCache.remove(programPath);

        // Use getProgramByPath which will open and cache the program
        return getProgramByPath(programPath);
    }

    /**
     * Clean up and release any resources
     */
    public static void cleanup() {
        // Close any programs we opened
        for (Program program : programCache.values()) {
            if (program != null && !program.isClosed()) {
                try {
                    // Ghidra API: Program.release(DomainObjectConsumer) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#release(ghidra.framework.model.DomainObjectConsumer)
                    program.release(CACHE_CONSUMER);
                } catch (Exception e) {
                    // Ghidra API: Msg.warn(Class, String, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object,java.lang.Throwable)
                    Msg.warn(AgentDecompileProgramManager.class,
                        "Failed to release cached program during cleanup: " + e.getMessage(), e);
                }
            }
        }
        programCache.clear();

        // Clear registered programs (but don't release them as we didn't open them)
        registeredPrograms.clear();
    }
}
