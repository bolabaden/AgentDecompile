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

        // First try to get programs from the tool manager
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.debug(AgentDecompileProgramManager.class, "No active project found");
            // Still check cache and registered programs even without a project
            return getCachedAndRegisteredPrograms();
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            PluginTool[] runningTools = toolManager.getRunningTools();
            Msg.debug(AgentDecompileProgramManager.class, "Found " + runningTools.length + " running tools");

            for (PluginTool tool : runningTools) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    Msg.debug(AgentDecompileProgramManager.class, "Tool " + tool.getName() + " has " + programs.length + " open programs");
                    for (Program program : programs) {
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                            Msg.debug(AgentDecompileProgramManager.class, "Added program: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    Msg.debug(AgentDecompileProgramManager.class, "Tool " + tool.getName() + " has no ProgramManager service");
                }
            }
        } else {
            Msg.debug(AgentDecompileProgramManager.class, "No tool manager found");
        }

        // If no tools were found (common in test environments),
        // try to get programs directly from the AgentDecompilePlugin's tool
        if (openPrograms.isEmpty()) {
            Msg.debug(AgentDecompileProgramManager.class, "No programs found via ToolManager, trying AgentDecompilePlugin tool");
            AgentDecompilePlugin agentdecompilePlugin = AgentDecompileInternalServiceRegistry.getService(AgentDecompilePlugin.class);
            if (agentdecompilePlugin != null && agentdecompilePlugin.getTool() != null) {
                PluginTool tool = agentdecompilePlugin.getTool();
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin tool has " + programs.length + " open programs");
                    for (Program program : programs) {
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                            Msg.debug(AgentDecompileProgramManager.class, "Added program from AgentDecompilePlugin: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
                        }
                    }
                } else {
                    Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin tool has no ProgramManager service");
                }
            } else {
                Msg.debug(AgentDecompileProgramManager.class, "AgentDecompilePlugin not found or has no tool");
            }
        }

        // Also include programs from cache and registered programs (for programs opened via getProgramByPath)
        List<Program> cachedAndRegistered = getCachedAndRegisteredPrograms();
        for (Program program : cachedAndRegistered) {
            if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                openPrograms.add(program);
                Msg.debug(AgentDecompileProgramManager.class, "Added cached/registered program: " + program.getName() + " with domain path: " + program.getDomainFile().getPathname());
            }
        }

        // If still no programs are open, automatically open all programs from the project
        if (openPrograms.isEmpty()) {
            Msg.debug(AgentDecompileProgramManager.class, "No programs currently open, auto-opening programs from project");
            List<String> projectProgramPaths = collectProgramPathsFromProject(project);
            Msg.debug(AgentDecompileProgramManager.class, "Found " + projectProgramPaths.size() + " programs in project");

            for (String programPath : projectProgramPaths) {
                try {
                    Program program = getProgramByPath(programPath);
                    if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                        openPrograms.add(program);
                        Msg.info(AgentDecompileProgramManager.class, "Auto-opened program from project: " + programPath);
                    }
                } catch (Exception e) {
                    Msg.debug(AgentDecompileProgramManager.class, "Failed to auto-open program " + programPath + ": " + e.getMessage());
                }
            }
        }

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

        // First try to get programs from the tool manager
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            Msg.debug(AgentDecompileProgramManager.class, "No active project found");
            return getCachedAndRegisteredPrograms();
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager != null) {
            PluginTool[] runningTools = toolManager.getRunningTools();
            for (PluginTool tool : runningTools) {
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
                    Program[] programs = programManager.getAllOpenPrograms();
                    for (Program program : programs) {
                        if (program != null && !program.isClosed() && !openPrograms.contains(program)) {
                            openPrograms.add(program);
                        }
                    }
                }
            }
        }

        // Try AgentDecompilePlugin's tool as fallback
        if (openPrograms.isEmpty()) {
            AgentDecompilePlugin agentdecompilePlugin = AgentDecompileInternalServiceRegistry.getService(AgentDecompilePlugin.class);
            if (agentdecompilePlugin != null && agentdecompilePlugin.getTool() != null) {
                PluginTool tool = agentdecompilePlugin.getTool();
                ProgramManager programManager = tool.getService(ProgramManager.class);
                if (programManager != null) {
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

        // Add valid programs from cache
        for (Program program : programCache.values()) {
            if (program != null && !program.isClosed()) {
                programs.add(program);
            }
        }

        // Add valid registered programs
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
            DomainFolder rootFolder = project.getProjectData().getRootFolder();
            collectProgramPathsRecursive(rootFolder, paths);
        } catch (Exception e) {
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
        for (DomainFile file : folder.getFiles()) {
            if ("Program".equals(file.getContentType())) {
                paths.add(file.getPathname());
            }
        }

        // Recurse into subfolders
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
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return programFiles;
        }

        try {
            DomainFolder rootFolder = project.getProjectData().getRootFolder();
            collectProgramFilesRecursive(rootFolder, programFiles);
        } catch (Exception e) {
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

        // Add programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if ("Program".equals(file.getContentType())) {
                programFiles.add(file);
            }
        }

        // Recurse into subfolders
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
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.put(programPath, program);
            Msg.debug(AgentDecompileProgramManager.class, "Registered program: " + programPath);
        }
    }

    /**
     * Unregister a program from the manager.
     * @param program The program to unregister
     */
    public static void unregisterProgram(Program program) {
        if (program != null) {
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
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
            String programPath = program.getDomainFile().getPathname();
            registeredPrograms.remove(programPath);
            programCache.remove(programPath);
            Msg.debug(AgentDecompileProgramManager.class, "Program closed, cleared cache: " + programPath);
        }
    }

    /**
     * Handle when a program is opened.
     * This ensures proper cache management and can be used to refresh stale entries.
     * @param program The program that was opened
     */
    public static void programOpened(Program program) {
        if (program != null && !program.isClosed()) {
            String programPath = program.getDomainFile().getPathname();
            // Clear any stale cache entry and let normal lookup repopulate
            programCache.remove(programPath);
            Msg.debug(AgentDecompileProgramManager.class, "Program opened, cleared stale cache: " + programPath);
        }
    }

    /**
     * Get the canonical domain path for a program
     * @param program The program to get the canonical path for
     * @return The canonical domain path
     */
    public static String getCanonicalProgramPath(Program program) {
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

        DomainFile domainFile = program.getDomainFile();
        Msg.debug(AgentDecompileProgramManager.class,
            "Program state - versioned: " + domainFile.isVersioned() +
            ", checked out: " + domainFile.isCheckedOut() +
            ", read-only: " + domainFile.isReadOnly());

        if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
            try {
                // Attempt non-exclusive checkout
                Msg.debug(AgentDecompileProgramManager.class,
                    "Attempting auto-checkout for: " + programPath);
                boolean success = domainFile.checkout(false, TaskMonitor.DUMMY);
                if (success) {
                    Msg.info(AgentDecompileProgramManager.class,
                        "Auto-checked out versioned program: " + programPath);
                } else {
                    Msg.warn(AgentDecompileProgramManager.class,
                        "Failed to auto-checkout versioned program: " + programPath +
                        " (may be checked out exclusively by another user)");
                }
            } catch (CancelledException | IOException e) {
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

        Msg.debug(AgentDecompileProgramManager.class, "Looking for program with path: " + programPath);

        // Check registered programs first (for test environments)
        if (registeredPrograms.containsKey(programPath)) {
            Program registeredProgram = registeredPrograms.get(programPath);
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
            // Ensure the program is still valid
            if (!cachedProgram.isClosed()) {
                Msg.debug(AgentDecompileProgramManager.class, "Found program in cache: " + programPath);
                ensureCheckedOut(cachedProgram, programPath);
                return cachedProgram;
            } else {
                // Remove invalid programs from cache
                programCache.remove(programPath);
            }
        }

        // First try to find among currently open programs (without auto-opening all)
        List<Program> openPrograms = getOpenProgramsWithoutAutoOpen();
        Msg.debug(AgentDecompileProgramManager.class, "Checking " + openPrograms.size() + " currently open programs");

        for (Program program : openPrograms) {
            // Check the Ghidra project path first (most common case)
            String domainPath = program.getDomainFile().getPathname();
            Msg.debug(AgentDecompileProgramManager.class, "Comparing '" + programPath + "' with domain path '" + domainPath + "'");
            if (domainPath.equals(programPath)) {
                // Use canonical domain path as cache key for consistency
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(AgentDecompileProgramManager.class, "Found program by domain path: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }

            // Also check executable path and name for backward compatibility
            String executablePath = program.getExecutablePath();
            String programName = program.getName();
            Msg.debug(AgentDecompileProgramManager.class, "Also checking executable path '" + executablePath + "' and name '" + programName + "'");
            if (executablePath.equals(programPath) || programName.equals(programPath)) {
                // Use canonical domain path as cache key for consistency
                String canonicalPath = getCanonicalProgramPath(program);
                programCache.put(canonicalPath, program);
                Msg.debug(AgentDecompileProgramManager.class, "Found program by executable path or name: " + programPath);
                ensureCheckedOut(program, programPath);
                return program;
            }
        }

        // Get the DomainFile for the program path
        Project project = AppInfo.getActiveProject();
        if (project == null) {
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

                DomainFolder folder = project.getProjectData().getFolder(folderPath);
                if (folder != null) {
                    domainFile = folder.getFile(fileName);
                }
            } else {
                // No folders, file is directly in root
                domainFile = project.getProjectData().getRootFolder().getFile(relativePath);
            }
        } else {
            // Handle paths without leading slash
            domainFile = project.getProjectData().getRootFolder().getFile(programPath);
        }

        if (domainFile == null) {
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
            DomainObject domainObject = domainFile.getDomainObject(CACHE_CONSUMER, false, false, TaskMonitor.DUMMY);

            if (domainObject instanceof Program prog1) {
                program = prog1;
            } else {
                Msg.warn(AgentDecompileProgramManager.class, "Domain object is not a Program: " + programPath);
                if (domainObject != null) {
                    domainObject.release(CACHE_CONSUMER);
                }
            }
        } catch (CancelledException | VersionException | IOException e) {
            Msg.error(AgentDecompileProgramManager.class, "Failed to open program " + programPath + ": " + e.getMessage(), e);
            // Fall back to ProgramOpener if getDomainObject fails
            try {
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
        if (program == null || program.isClosed()) {
            return false;
        }

        String canonicalPath = getCanonicalProgramPath(program);
        Program cachedProgram = programCache.remove(canonicalPath);

        if (cachedProgram != null && cachedProgram == program) {
            Msg.debug(AgentDecompileProgramManager.class,
                "Releasing program from cache: " + canonicalPath);
            try {
                program.release(CACHE_CONSUMER);
            } catch (Exception e) {
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

        Msg.debug(AgentDecompileProgramManager.class,
            "Re-opening program to cache: " + programPath);

        // Clear any existing cache entry first
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
                    program.release(CACHE_CONSUMER);
                } catch (Exception e) {
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
