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
 */
public class ProgramLookupUtil {

    /**
     * Get the current program from the active Code Browser tool (GUI mode only).
     * This matches GhidraMCP's behavior of getting the "current" program from the GUI.
     *
     * @return The current program from the active Code Browser, or null if not available
     */
    public static Program getCurrentProgramFromGUI() {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            return null;
        }

        ToolManager toolManager = project.getToolManager();
        if (toolManager == null) {
            return null;
        }

        // Find a Code Browser tool with ProgramManager service
        PluginTool[] runningTools = toolManager.getRunningTools();
        for (PluginTool runningTool : runningTools) {
            ProgramManager programManager = runningTool.getService(ProgramManager.class);
            if (programManager != null) {
                Program currentProgram = programManager.getCurrentProgram();
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
     *
     * @param programPath The path to the program (e.g., "/Hatchery.exe"), or null to use current program from GUI
     * @return A valid Program object
     * @throws ProgramValidationException if the program cannot be found or is invalid
     */
    public static Program getValidatedProgram(String programPath) throws ProgramValidationException {
        // If programPath is null or empty, try to get current program from GUI (like GhidraMCP)
        if (programPath == null || programPath.trim().isEmpty()) {
            Program currentProgram = getCurrentProgramFromGUI();
            if (currentProgram != null) {
                return currentProgram;
            }
            throw new ProgramValidationException("Program path is required when no program is currently active in the Code Browser");
        }

        // Normalize the program path (trim whitespace)
        String normalizedPath = programPath.trim();

        // First try the standard lookup with normalized path
        Program program = AgentDecompileProgramManager.getProgramByPath(normalizedPath);
        if (program != null && !program.isClosed()) {
            return program;
        }

        // Get list of available programs directly as Program objects for reliable fallback logic
        // This avoids the issue where path-based lookup fails even though the program is available
        List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
        List<String> availableProgramPaths = getAvailableProgramPaths();

        // FIX 1: If only one program exists in the project or is loaded, use it regardless of input
        // This handles the common case where there's only one program and any input should work
        if (openPrograms.size() == 1) {
            Program singleProgram = openPrograms.get(0);
            if (singleProgram != null && !singleProgram.isClosed()) {
                String singleProgramPath = singleProgram.getDomainFile().getPathname();
                Msg.info(ProgramLookupUtil.class, "Only one program available, using '" + singleProgramPath + 
                         "' instead of requested '" + normalizedPath + "'");
                return singleProgram;
            }
        }
        
        // Also check if there's only one program path available in the project
        // (handles cases where open programs list is empty but project has one program)
        if (openPrograms.isEmpty() && availableProgramPaths.size() == 1) {
            String singleProgramPath = availableProgramPaths.get(0);
            Program singleProgram = AgentDecompileProgramManager.getProgramByPath(singleProgramPath);
            if (singleProgram != null && !singleProgram.isClosed()) {
                Msg.info(ProgramLookupUtil.class, "Only one program available in project, using '" + singleProgramPath + 
                         "' instead of requested '" + normalizedPath + "'");
                return singleProgram;
            }
        }

        // FIX 2: Check if the requested path matches any available program when normalized
        // This handles cases where the path lookup fails but the path appears in suggestions
        // (e.g., due to subtle differences in how paths are stored vs requested)
        // Search directly through Program objects to avoid re-lookup failures
        Program matchedProgram = findExactMatchWithNormalization(normalizedPath, openPrograms);
        if (matchedProgram != null && !matchedProgram.isClosed()) {
            return matchedProgram;
        }

        // If not found, build a helpful error message with suggestions
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
            if (program == null || program.isClosed()) {
                continue;
            }
            
            String domainPath = program.getDomainFile().getPathname();
            String executablePath = program.getExecutablePath();
            String programName = program.getName();
            
            // Check domain path match (always non-null)
            if (pathsMatch(requestedPath, domainPath)) {
                Msg.debug(ProgramLookupUtil.class, "Found exact match with normalization (domain path): '" + 
                         requestedPath + "' matched '" + domainPath + "'");
                return program;
            }
            
            // Check executable path match (may be null)
            if (executablePath != null && pathsMatch(requestedPath, executablePath)) {
                Msg.debug(ProgramLookupUtil.class, "Found exact match with normalization (executable path): '" + 
                         requestedPath + "' matched '" + executablePath + "'");
                return program;
            }
            
            // Check program name match (may be null)
            if (programName != null && pathsMatch(requestedPath, programName)) {
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
            if (prog != null && !prog.isClosed()) {
                paths.add(prog.getDomainFile().getPathname());
            }
        }

        // Then add programs from the project if available
        Project project = AppInfo.getActiveProject();
        if (project != null) {
            try {
                DomainFolder rootFolder = project.getProjectData().getRootFolder();
                collectProgramPaths(rootFolder, paths);
            } catch (Exception e) {
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
        // Add programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if ("Program".equals(file.getContentType())) {
                paths.add(file.getPathname());
            }
        }

        // Recurse into subfolders
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
        return path;
    }
}
