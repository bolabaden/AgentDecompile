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
package agentdecompile.util;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import agentdecompile.plugin.AgentDecompileProgramManager;
import agentdecompile.tools.ProgramValidationException;

/**
 * Utility class for consistent program lookup across all AgentDecompile tools.
 * Provides helpful error messages with suggestions when programs cannot be found.
 * <p>
 * Ghidra API references:
 * <ul>
 *   <li>{@link ghidra.framework.main.AppInfo} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html">AppInfo API</a></li>
 *   <li>{@link ghidra.framework.model.Project} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html">Project API</a></li>
 *   <li>{@link ghidra.framework.model.ToolManager} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html">ToolManager API</a></li>
 *   <li>{@link ghidra.app.services.ProgramManager} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html">ProgramManager API</a></li>
 *   <li>{@link ghidra.program.model.listing.Program} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html">Program API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class ProgramLookupUtil {

    /**
     * Get the current program from the active Code Browser tool (GUI mode only).
     * This matches GhidraMCP's behavior of getting the "current" program from the GUI.
     *
     * @return The current program from the active Code Browser, or null if not available
     */
    public static Program getCurrentProgramFromGUI() {
        Project project = ProjectUtil.getActiveProjectOrHeadlessFallback();
        if (project == null) {
            return null;
        }

        // Ghidra API: Project.getToolManager() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getToolManager()
        ToolManager toolManager = project.getToolManager();
        if (toolManager == null) {
            return null;
        }

        // Ghidra API: ToolManager.getRunningTools() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolManager.html#getRunningTools()
        PluginTool[] runningTools = toolManager.getRunningTools();
        for (PluginTool runningTool : runningTools) {
            // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
            ProgramManager programManager = runningTool.getService(ProgramManager.class);
            if (programManager != null) {
                // Ghidra API: ProgramManager.getCurrentProgram() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html#getCurrentProgram()
                Program currentProgram = programManager.getCurrentProgram();
                // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
                if (currentProgram != null && !currentProgram.isClosed()) {
                    return currentProgram;
                }
            }
        }

        return null;
    }

    /**
     * Get a validated program by its path with helpful error messages.
     * This method first attempts to find the program using AgentDecompileProgramManager,
     * and if that fails, provides a helpful error message with available programs.
     * <p>
     * If multiple programs are available and no path is specified, this method will
     * return the first available program instead of throwing an exception, to provide
     * a "best effort" experience.
     *
     * @param programPath The path to the program (e.g., "/Hatchery.exe"), or null to use current program from GUI
     * @return A valid Program object
     * @throws ProgramValidationException if no programs are available
     */
    public static Program getValidatedProgram(String programPath) throws ProgramValidationException {
        // Use the list-based resolution
        List<Program> programs = resolvePrograms(programPath);
        
        if (programs.isEmpty()) {
            throw new ProgramValidationException("No programs are available in the current project");
        }
        
        // If multiple programs are found but we need one, return the first one
        // This avoids "Program path is required" errors
        if (programs.size() > 1) {
            Program first = programs.get(0);
            Msg.info(ProgramLookupUtil.class, "Multiple programs available, auto-selecting first: " + first.getName());
            return first;
        }
        
        return programs.get(0);
    }

    /**
     * Resolve valid programs based on the provided path (or lack thereof).
     * <p>
     * If path is provided: Returns list containing that specific program.
     * If path is null/empty:
     * 1. If GUI active program exists, returns [activeProgram]
     * 2. If open programs exist, returns all open programs
     * 3. If project has programs, returns all project programs (opened)
     * 
     * @param programPath The path to the program, or null/empty
     * @return List of matching programs (never null, but may be empty)
     * @throws ProgramValidationException if a specific path was requested but not found
     */
    public static List<Program> resolvePrograms(String programPath) throws ProgramValidationException {
        // If programPath is null or empty, try to resolve "all applicable"
        if (programPath == null || programPath.trim().isEmpty()) {
            // 1. Try active GUI program
            Program currentProgram = getCurrentProgramFromGUI();
            if (currentProgram != null) {
                // If we are in GUI mode and have an active program, user likely intends to act on it
                List<Program> result = new ArrayList<>();
                result.add(currentProgram);
                return result;
            }
            
            // 2. Get all open programs
            List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
            if (!openPrograms.isEmpty()) {
                return openPrograms;
            }
            
            // 3. If no open programs, check available paths
            List<String> availableProgramPaths = getAvailableProgramPaths();
            if (!availableProgramPaths.isEmpty()) {
                // Return all available programs (opening them)
                List<Program> result = new ArrayList<>();
                for (String path : availableProgramPaths) {
                    Program p = AgentDecompileProgramManager.getProgramByPath(path);
                    if (p != null && !p.isClosed()) {
                        result.add(p);
                    }
                }
                return result;
            }
            
            return new ArrayList<>();
        }

        // Normalize the program path
        String normalizedPath = programPath.trim();

        // Try the standard lookup
        Program program = AgentDecompileProgramManager.getProgramByPath(normalizedPath);
        if (program != null && !program.isClosed()) {
            List<Program> result = new ArrayList<>();
            result.add(program);
            return result;
        }

        // Try fallback lookup (exact match with normalization)
        List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
        Program matchedProgram = findExactMatchWithNormalization(normalizedPath, openPrograms);
        if (matchedProgram != null && !matchedProgram.isClosed()) {
            List<Program> result = new ArrayList<>();
            result.add(matchedProgram);
            return result;
        }

        // If not found, build error message
        List<String> availableProgramPaths = getAvailableProgramPaths();
        String errorMessage = buildErrorMessageWithSuggestions(normalizedPath, availableProgramPaths);
        throw new ProgramValidationException(errorMessage);
    }

    /**
     * Attempt to find an exact match using normalized path comparison.
     * This handles cases where the standard lookup fails but the path should match.
     * Searches directly through Program objects instead of re-looking up by path.
     *
     * @param requestedPath The normalized requested path
     * @param openPrograms List of currently open Program objects
     * @return The matched program, or null if no exact match found
     */
    private static Program findExactMatchWithNormalization(String requestedPath, List<Program> openPrograms) {
        // Try various normalization strategies to find an exact match
        for (Program program : openPrograms) {
            // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
            if (program == null || program.isClosed()) {
                continue;
            }

            // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
            String domainPath = program.getDomainFile().getPathname();
            // Ghidra API: Program.getExecutablePath() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getExecutablePath()
            String executablePath = program.getExecutablePath();
            // Ghidra API: Program.getName() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getName()
            String programName = program.getName();

            // Check domain path match (always non-null)
            if (pathsMatch(requestedPath, domainPath)) {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(ProgramLookupUtil.class, "Found exact match with normalization (domain path): '" + 
                         requestedPath + "' matched '" + domainPath + "'");
                return program;
            }
            
            // Check executable path match (may be null)
            if (executablePath != null && pathsMatch(requestedPath, executablePath)) {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(ProgramLookupUtil.class, "Found exact match with normalization (executable path): '" + 
                         requestedPath + "' matched '" + executablePath + "'");
                return program;
            }
            
            // Check program name match (may be null)
            if (programName != null && pathsMatch(requestedPath, programName)) {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(ProgramLookupUtil.class, "Found exact match with normalization (program name): '" + 
                         requestedPath + "' matched '" + programName + "'");
                return program;
            }
        }
        return null;
    }

    /**
     * Check if two paths match after normalization.
     * Handles leading/trailing slashes, case sensitivity, and whitespace.
     *
     * @param path1 First path
     * @param path2 Second path
     * @return true if paths match after normalization
     */
    private static boolean pathsMatch(String path1, String path2) {
        if (path1 == null || path2 == null) {
            return false;
        }
        
        // Normalize both paths
        String normalized1 = normalizePath(path1);
        String normalized2 = normalizePath(path2);
        
        // Check exact match after normalization
        if (normalized1.equals(normalized2)) {
            return true;
        }
        
        // Also check case-insensitive match (some systems may have case differences)
        if (normalized1.equalsIgnoreCase(normalized2)) {
            return true;
        }
        
        // Check if one is the filename of the other (case-insensitive)
        String fileName1 = getFileName(normalized1);
        String fileName2 = getFileName(normalized2);
        if (fileName1.equalsIgnoreCase(fileName2)) {
            return true;
        }
        
        return false;
    }

    /**
     * Normalize a path for comparison.
     * Handles both forward slashes (Unix) and backslashes (Windows).
     *
     * @param path The path to normalize
     * @return Normalized path
     */
    private static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.trim();
        // Remove trailing slashes (both forward and backslash for cross-platform support)
        while ((normalized.endsWith("/") || normalized.endsWith("\\")) && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    /**
     * Build an error message with suggestions for available programs.
     *
     * @param requestedPath The path that was requested but not found
     * @param availablePrograms List of available program paths (already fetched)
     * @return A helpful error message with suggestions
     */
    private static String buildErrorMessageWithSuggestions(String requestedPath, List<String> availablePrograms) {
        StringBuilder message = new StringBuilder();
        message.append("Program not found: ").append(requestedPath);

        if (!availablePrograms.isEmpty()) {
            // FIX 2 continued: Filter out suggestions that are exact matches to avoid
            // the confusing "not found X, did you mean X?" message
            List<String> filteredSuggestions = findSimilarPrograms(requestedPath, availablePrograms)
                .stream()
                .filter(suggestion -> !pathsMatch(requestedPath, suggestion))
                .collect(Collectors.toList());

            if (!filteredSuggestions.isEmpty()) {
                message.append("\n\nDid you mean one of these?");
                for (String suggestion : filteredSuggestions) {
                    message.append("\n  - ").append(suggestion);
                }
            } else {
                message.append("\n\nAvailable programs:");
                for (String available : availablePrograms) {
                    message.append("\n  - ").append(available);
                }
            }
        } else {
            message.append("\n\nNo programs are currently available. ");
            message.append("Please open a program in Ghidra or check your project.");
        }

        return message.toString();
    }

    /**
     * Get a list of all available program paths.
     * This includes both open programs and programs in the project.
     *
     * @return List of available program paths
     */
    private static List<String> getAvailableProgramPaths() {
        List<String> paths = new ArrayList<>();

        // First add all open programs
        List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
        for (Program prog : openPrograms) {
            // Ghidra API: Program.isClosed() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#isClosed()
            if (prog != null && !prog.isClosed()) {
                // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                paths.add(prog.getDomainFile().getPathname());
            }
        }

        Project project = ProjectUtil.getActiveProjectOrHeadlessFallback();
        if (project != null) {
            try {
                // Ghidra API: Project.getProjectData(), ProjectData.getRootFolder() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getProjectData(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html#getRootFolder()
                DomainFolder rootFolder = project.getProjectData().getRootFolder();
                collectProgramPaths(rootFolder, paths);
            } catch (Exception e) {
                // Ghidra API: Msg.debug(Class, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
                Msg.debug(ProgramLookupUtil.class, "Error collecting project programs: " + e.getMessage());
            }
        }

        // Remove duplicates and sort
        return paths.stream()
            .distinct()
            .sorted()
            .collect(Collectors.toList());
    }

    /**
     * Recursively collect program paths from a domain folder.
     *
     * @param folder The folder to search
     * @param paths The list to add paths to
     */
    private static void collectProgramPaths(DomainFolder folder, List<String> paths) {
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
            collectProgramPaths(subfolder, paths);
        }
    }

    /**
     * Find programs with similar names to the requested path.
     *
     * @param requestedPath The path that was requested
     * @param availablePrograms List of available program paths
     * @return List of similar program paths (up to 3)
     */
    private static List<String> findSimilarPrograms(String requestedPath, List<String> availablePrograms) {
        List<String> suggestions = new ArrayList<>();

        // Normalize the requested path for comparison
        String normalizedRequest = requestedPath.toLowerCase();
        // Remove leading slash if present
        if (normalizedRequest.startsWith("/")) {
            normalizedRequest = normalizedRequest.substring(1);
        }

        // Look for programs that contain the requested name
        for (String available : availablePrograms) {
            String normalizedAvailable = available.toLowerCase();

            // Check if the available program contains the requested name
            if (normalizedAvailable.contains(normalizedRequest) ||
                normalizedRequest.contains(getFileName(normalizedAvailable))) {
                suggestions.add(available);
                if (suggestions.size() >= 3) {
                    break;
                }
            }
        }

        // If no contains matches, look for programs with similar file names
        if (suggestions.isEmpty()) {
            String requestedFileName = getFileName(normalizedRequest);
            for (String available : availablePrograms) {
                String availableFileName = getFileName(available.toLowerCase());
                if (availableFileName.contains(requestedFileName) ||
                    requestedFileName.contains(availableFileName)) {
                    suggestions.add(available);
                    if (suggestions.size() >= 3) {
                        break;
                    }
                }
            }
        }

        return suggestions;
    }

    /**
     * Extract the file name from a path.
     *
     * @param path The full path
     * @return The file name portion
     */
    private static String getFileName(String path) {
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < path.length() - 1) {
            return path.substring(lastSlash + 1);
        }
        // If path is "/" or ends with "/", return empty string
        if ("/".equals(path) || path.endsWith("/")) {
            return "";
        }
        return path;
    }
}
