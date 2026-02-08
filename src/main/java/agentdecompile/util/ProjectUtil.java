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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.base.project.GhidraProject;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.LockException;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.NotFoundException;

/**
 * Utility class for unified project handling across AgentDecompile components.
 * <p>
 * Provides consistent project opening/creation logic for both headless launcher
 * and tool providers, ensuring no conflicts or divergent behavior.
 * </p>
 * <p>
 * Ghidra API: {@link ghidra.base.project.GhidraProject} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html">GhidraProject API</a>,
 * {@link ghidra.framework.model.Project} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html">Project API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class ProjectUtil {

    /**
     * Result of a project open operation
     */
    public static class ProjectOpenResult {
        private final Project project;
        private final GhidraProject ghidraProject;
        private final boolean wasAlreadyOpen;
        private final boolean wasCreated;

        private ProjectOpenResult(Project project, GhidraProject ghidraProject, boolean wasAlreadyOpen, boolean wasCreated) {
            this.project = project;
            this.ghidraProject = ghidraProject;
            this.wasAlreadyOpen = wasAlreadyOpen;
            this.wasCreated = wasCreated;
        }

        /**
         * Get the Project instance (may be from active project if locked)
         * @return The Project instance, or null if operation failed
         */
        public Project getProject() {
            return project;
        }

        /**
         * Get the GhidraProject instance (null if project was already open)
         * @return The GhidraProject instance, or null if project was already open
         */
        public GhidraProject getGhidraProject() {
            return ghidraProject;
        }

        /**
         * Check if project was already open (locked, but active project matched)
         * @return True if project was already open
         */
        public boolean wasAlreadyOpen() {
            return wasAlreadyOpen;
        }

        /**
         * Check if project was newly created
         * @return True if project was created, false if it existed
         */
        public boolean wasCreated() {
            return wasCreated;
        }
    }

    /**
     * Create or open a Ghidra project with unified handling.
     * <p>
     * This method provides consistent behavior for:
     * - Creating new projects
     * - Opening existing projects
     * - Handling locked projects (using active project if it matches)
     * - Providing clear error messages
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param enableUpgrade Whether to enable automatic project upgrades (default: true)
     * @param logContext Object for logging context (can be null)
     * @return ProjectOpenResult containing the project and status information
     * @throws IOException if project creation/opening fails and cannot be recovered
     */
    public static ProjectOpenResult createOrOpenProject(
            File projectDir,
            String projectName,
            boolean enableUpgrade,
            Object logContext) throws IOException {
        return createOrOpenProject(projectDir, projectName, enableUpgrade, logContext, false);
    }

    /**
     * Create or open a Ghidra project with unified handling.
     * <p>
     * This method provides consistent behavior for:
     * - Creating new projects
     * - Opening existing projects
     * - Handling locked projects (using active project if it matches)
     * - Force ignoring lock files if requested
     * - Providing clear error messages
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param enableUpgrade Whether to enable automatic project upgrades (default: true)
     * @param logContext Object for logging context (can be null)
     * @param forceIgnoreLock Whether to forcibly delete lock files before opening (default: false)
     * @return ProjectOpenResult containing the project and status information
     * @throws IOException if project creation/opening fails and cannot be recovered
     */
    public static ProjectOpenResult createOrOpenProject(
            File projectDir,
            String projectName,
            boolean enableUpgrade,
            Object logContext,
            boolean forceIgnoreLock) throws IOException {

        // Ensure project directory exists
        if (!projectDir.exists()) {
            if (!projectDir.mkdirs()) {
                throw new IOException("Failed to create project directory: " + projectDir.getAbsolutePath());
            }
        }

        String projectLocationPath = projectDir.getAbsolutePath();
        // Ghidra API: ProjectLocator(String, String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#%3Cinit%3E(java.lang.String,java.lang.String)
        ProjectLocator locator = new ProjectLocator(projectLocationPath, projectName);

        // If forceIgnoreLock is true, delete lock files before attempting to open
        if (forceIgnoreLock) {
            deleteLockFiles(projectDir, projectName, logContext);
        }

        // Check if project already exists
        // Ghidra API: ProjectLocator.getMarkerFile(), getProjectDir() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getMarkerFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getProjectDir()
        boolean projectExists = locator.getMarkerFile().exists() && locator.getProjectDir().exists();

        if (projectExists) {
            // Try to open existing project
            logInfo(logContext, "Opening existing project: " + projectName + " at " + projectLocationPath);
            try {
                // Ghidra API: GhidraProject.openProject(String, String, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html#openProject(java.lang.String,java.lang.String,boolean)
                GhidraProject ghidraProject = GhidraProject.openProject(projectLocationPath, projectName, enableUpgrade);
                // Ghidra API: GhidraProject.getProject() - https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html#getProject()
                Project project = ghidraProject.getProject();
                return new ProjectOpenResult(project, ghidraProject, false, false);
            } catch (LockException e) {
                // Project is locked - check if it's already open as the active project
                return handleLockedProject(projectLocationPath, projectName, logContext, e);
            } catch (NotOwnerException | NotFoundException | IOException e) {
                // Check if this is an authentication error
                String errorMsg = e.getMessage();
                if (errorMsg != null && (errorMsg.contains("authentication")
                        || errorMsg.contains("password")
                        || errorMsg.contains("login")
                        || errorMsg.contains("unauthorized")
                        || errorMsg.contains("Access denied")
                        || errorMsg.contains("Invalid credentials"))) {
                    throw new IOException(
                        "Authentication failed for shared project. " +
                        "Error: " + errorMsg + ". " +
                        "Please verify your username and password are correct.",
                        e
                    );
                }
                // Re-throw as IOException
                throw new IOException("Failed to open project: " + projectName, e);
            }
        } else {
            // Create new project
            logInfo(logContext, "Creating new project: " + projectName + " at " + projectLocationPath);
            try {
                // Ghidra API: GhidraProject.createProject(String, String, boolean) - https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html#createProject(java.lang.String,java.lang.String,boolean)
                GhidraProject ghidraProject = GhidraProject.createProject(projectLocationPath, projectName, false);
                // Ghidra API: GhidraProject.getProject() - https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html#getProject()
                Project project = ghidraProject.getProject();
                return new ProjectOpenResult(project, ghidraProject, false, true);
            } catch (IOException e) {
                throw new IOException("Failed to create project: " + projectName, e);
            }
        }
    }

    /**
     * Handle a locked project by checking if the active project matches.
     *
     * @param requestedProjectDir The directory of the requested project
     * @param requestedProjectName The name of the requested project
     * @param logContext Object for logging context (can be null)
     * @param lockException The LockException that was thrown
     * @return ProjectOpenResult with active project if it matches, or throws IOException
     * @throws IOException if active project doesn't match or no active project exists
     */
    private static ProjectOpenResult handleLockedProject(
            String requestedProjectDir,
            String requestedProjectName,
            Object logContext,
            LockException lockException) throws IOException {

        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project activeProject = AppInfo.getActiveProject();
        if (activeProject != null) {
            // Verify the active project matches the requested one
            // Ghidra API: Project.getProjectLocator(), ProjectLocator.getProjectDir() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getProjectLocator(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getProjectDir()
            String activeProjectDir = activeProject.getProjectLocator().getProjectDir().getAbsolutePath();
            String requestedDirAbsolute = new File(requestedProjectDir).getAbsolutePath();

            if (activeProjectDir.equals(requestedDirAbsolute) || activeProject.getName().equals(requestedProjectName)) {
                // Active project matches - use it
                // Ghidra API: Project.getName() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getName()
                String logMsg = "Project is locked (already open), using active project: " + activeProject.getName();
                logInfo(logContext, logMsg);
                // Return null for ghidraProject since we're using the active project
                return new ProjectOpenResult(activeProject, null, true, false);
            } else {
                // Active project doesn't match
                throw new IOException(
                    "Project '" + requestedProjectName + "' is locked by another process. " +
                    "Active project is '" + activeProject.getName() + "' at '" + activeProjectDir + "'. " +
                    "Ghidra projects can only be opened by one process at a time to prevent data corruption. " +
                    "\n\nOptions:\n" +
                    "1. Close the other project and try again\n" +
                    "2. For shared projects: Use Ghidra Server for true simultaneous access (recommended)\n" +
                    "3. Workaround: Set AGENT_DECOMPILE_FORCE_IGNORE_LOCK=true (RISKY - can cause data corruption if multiple processes write simultaneously)\n" +
                    "\nNote: AgentDecompile does not create locks - this is Ghidra's built-in protection mechanism.",
                    lockException
                );
            }
            } else {
                // No active project available
                throw new IOException(
                    "Project '" + requestedProjectName + "' is locked and cannot be opened. " +
                    "Ghidra projects can only be opened by one process at a time to prevent data corruption. " +
                    "The project may be open in another Ghidra instance or AgentDecompile CLI process. " +
                    "\n\nOptions:\n" +
                    "1. Close the project in the other process (Ghidra GUI or another AgentDecompile CLI instance)\n" +
                    "2. For shared projects: Use Ghidra Server for true simultaneous access (recommended)\n" +
                    "3. Workaround: Set AGENT_DECOMPILE_FORCE_IGNORE_LOCK=true (RISKY - can cause data corruption if multiple processes write simultaneously)\n" +
                    "\nNote: AgentDecompile does not create locks - this is Ghidra's built-in protection mechanism.",
                    lockException
                );
            }
    }

    /**
     * Verify that a project exists at the given location.
     *
     * @param projectDir The directory where the project should be stored
     * @param projectName The name of the project
     * @return True if the project exists (marker file and project directory both exist)
     */
    public static boolean projectExists(File projectDir, String projectName) {
        // Ghidra API: ProjectLocator(String, String) - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#%3Cinit%3E(java.lang.String,java.lang.String)
        ProjectLocator locator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);
        // Ghidra API: ProjectLocator.getMarkerFile(), getProjectDir() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getMarkerFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getProjectDir()
        return locator.getMarkerFile().exists() && locator.getProjectDir().exists();
    }

    /**
     * Try to open a Ghidra project from a .gpr file path.
     * Applies shared-project auth from environment if set. Used by the open-programs resource
     * when no project is active (path from last 'open' or AGENT_DECOMPILE_PROJECT_PATH env).
     *
     * @param gprPath absolute path to the project .gpr file
     * @return true if a project is now active (opened or was already open)
     */
    public static boolean tryOpenProjectFromGprPath(String gprPath) {
        if (gprPath == null || !gprPath.toLowerCase().endsWith(".gpr")) {
            return false;
        }
        File projectFile = new File(gprPath);
        if (!projectFile.exists()) {
            return false;
        }
        String projectDir = projectFile.getParent();
        String projectName = projectFile.getName();
        if (projectName.toLowerCase().endsWith(".gpr")) {
            projectName = projectName.substring(0, projectName.length() - 4);
        }
        if (projectDir == null) {
            return false;
        }
        File projectDirFile = new File(projectDir);
        if (!projectExists(projectDirFile, projectName)) {
            return false;
        }
        if (SharedProjectEnvConfig.hasAuthFromEnv()) {
            SharedProjectEnvConfig.applySharedProjectAuthFromEnv(null);
        }
        String forceIgnoreLockEnv = System.getenv("AGENT_DECOMPILE_FORCE_IGNORE_LOCK");
        boolean forceIgnoreLock = forceIgnoreLockEnv != null
            && ("true".equalsIgnoreCase(forceIgnoreLockEnv) || "1".equals(forceIgnoreLockEnv));
        try {
            ProjectOpenResult result = createOrOpenProject(projectDirFile, projectName, true, null, forceIgnoreLock);
            return result.getProject() != null;
        } catch (IOException e) {
            Msg.debug(ProjectUtil.class, "tryOpenProjectFromGprPath failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Build the full project tree for list-project-files: metadata plus items list.
     * Always lists the entire project hierarchy (root, recursive). Works correctly
     * for both local and shared/versioned projects by using RepositoryAdapter
     * when connected to a Ghidra Server. No caching: every call refreshes and
     * builds live results.
     *
     * @param project active project, or null for empty result
     * @return map with "metadata" and "items" (same shape as list-project-files response)
     */
    public static Map<String, Object> buildListProjectFilesData(Project project) {
        Map<String, Object> metadata = new HashMap<>();
        List<Map<String, Object>> items = new ArrayList<>();
        metadata.put("folderPath", "/");
        metadata.put("folderName", "/");
        metadata.put("isRecursive", true);
        metadata.put("itemCount", 0);

        if (project == null) {
            Map<String, Object> out = new HashMap<>();
            out.put("metadata", metadata);
            out.put("items", items);
            return out;
        }

        ProjectData projectData = project.getProjectData();
        try {
            projectData.refresh(true);
        } catch (Exception e) {
            Msg.warn(ProjectUtil.class, "Error refreshing project data (continuing anyway): " + e.getMessage());
        }

        Set<String> addedPaths = new HashSet<>();

        RepositoryAdapter repo = projectData.getRepository();
        if (repo != null) {
            try {
                if (!repo.isConnected()) {
                    repo.connect();
                }
            } catch (IOException e) {
                Msg.debug(ProjectUtil.class, "Could not connect to repository: " + e.getMessage());
            }
            if (repo.isConnected()) {
                collectFromRepositoryRecursive(repo, projectData, items, addedPaths);
            }
        }

        if (projectData.getRootFolder() != null) {
            collectRecursiveViaProjectData(project, items, addedPaths);
        }

        metadata.put("itemCount", items.size());

        Map<String, Object> out = new HashMap<>();
        out.put("metadata", metadata);
        out.put("items", items);
        return out;
    }

    /**
     * Extract all file (program) paths from a list-project-files result.
     * Used so callers (e.g. getAllProgramFiles) use the same merged repo+local source.
     *
     * @param listResult result from {@link #buildListProjectFilesData(Project)}
     * @return list of programPath strings (with leading slash)
     */
    @SuppressWarnings("unchecked")
    public static List<String> getProgramPathsFromListResult(Map<String, Object> listResult) {
        List<String> paths = new ArrayList<>();
        Object itemsObj = listResult.get("items");
        if (!(itemsObj instanceof List)) {
            return paths;
        }
        for (Object o : (List<?>) itemsObj) {
            if (!(o instanceof Map)) continue;
            Map<String, Object> item = (Map<String, Object>) o;
            if (!"file".equals(item.get("type"))) continue;
            Object path = item.get("programPath");
            if (path instanceof String string) {
                paths.add(string);
            }
        }
        return paths;
    }

    private static void collectFilesInFolder(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        if (folder == null) {
            return;
        }
        try {
            for (DomainFolder subfolder : folder.getFolders()) {
                try {
                    Map<String, Object> folderInfo = new HashMap<>();
                    String fp = pathPrefix.isEmpty() ? "/" + subfolder.getName() : pathPrefix + subfolder.getName();
                    folderInfo.put("folderPath", fp);
                    folderInfo.put("type", "folder");
                    try {
                        folderInfo.put("childCount", subfolder.getFiles().length + subfolder.getFolders().length);
                    } catch (Exception e) {
                        folderInfo.put("childCount", 0);
                    }
                    filesList.add(folderInfo);
                } catch (Exception e) {
                    Msg.debug(ProjectUtil.class, "Error processing subfolder: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            Msg.debug(ProjectUtil.class, "Error getting subfolders: " + e.getMessage());
        }
        try {
            for (DomainFile file : folder.getFiles()) {
                try {
                    Map<String, Object> fileInfo = new HashMap<>();
                    fileInfo.put("programPath", file.getPathname());
                    fileInfo.put("type", "file");
                    fileInfo.put("contentType", file.getContentType());
                    fileInfo.put("lastModified", file.getLastModifiedTime());
                    fileInfo.put("readOnly", file.isReadOnly());
                    fileInfo.put("versioned", file.isVersioned());
                    fileInfo.put("checkedOut", file.isCheckedOut());
                    if ("Program".equals(file.getContentType()) && file.getMetadata() != null) {
                        try {
                            Object lang = file.getMetadata().get("CREATED_WITH_LANGUAGE");
                            if (lang != null) {
                                fileInfo.put("programLanguage", lang);
                            }
                            Object md5 = file.getMetadata().get("Executable MD5");
                            if (md5 != null) {
                                fileInfo.put("executableMD5", md5);
                            }
                        } catch (Exception e) {
                            // ignore
                        }
                    }
                    filesList.add(fileInfo);
                } catch (Exception e) {
                    Msg.debug(ProjectUtil.class, "Error processing file: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            Msg.debug(ProjectUtil.class, "Error getting files: " + e.getMessage());
        }
    }

    private static void collectFilesRecursive(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        if (folder == null) {
            return;
        }
        collectFilesInFolder(folder, filesList, pathPrefix);
        try {
            for (DomainFolder subfolder : folder.getFolders()) {
                if (subfolder == null) {
                    continue;
                }
                String newPrefix = pathPrefix.isEmpty()
                    ? "/" + subfolder.getName() + "/"
                    : (pathPrefix.endsWith("/") ? pathPrefix + subfolder.getName() + "/" : pathPrefix + "/" + subfolder.getName() + "/");
                collectFilesRecursive(subfolder, filesList, newPrefix);
            }
        } catch (Exception e) {
            Msg.debug(ProjectUtil.class, "Error getting subfolders: " + e.getMessage());
        }
    }

    // =========================================================================
    // Robust collection methods for shared/versioned projects
    // =========================================================================

    /**
     * Build a file info map from a DomainFile (extracted to avoid duplication).
     */
    private static Map<String, Object> buildFileInfoMap(DomainFile file) {
        Map<String, Object> fileInfo = new HashMap<>();
        fileInfo.put("programPath", file.getPathname());
        fileInfo.put("type", "file");
        try {
            fileInfo.put("contentType", file.getContentType());
        } catch (Exception e) {
            fileInfo.put("contentType", "Unknown");
        }
        try {
            fileInfo.put("lastModified", file.getLastModifiedTime());
        } catch (Exception e) {
            // ignore
        }
        try {
            fileInfo.put("readOnly", file.isReadOnly());
        } catch (Exception e) {
            fileInfo.put("readOnly", false);
        }
        try {
            fileInfo.put("versioned", file.isVersioned());
            fileInfo.put("checkedOut", file.isCheckedOut());
        } catch (Exception e) {
            // ignore - version info may not be available
        }
        try {
            if ("Program".equals(file.getContentType()) && file.getMetadata() != null) {
                Map<String, String> metadata = file.getMetadata();
                Object lang = metadata.get("CREATED_WITH_LANGUAGE");
                if (lang != null) {
                    fileInfo.put("programLanguage", lang);
                }
                Object md5 = metadata.get("Executable MD5");
                if (md5 != null) {
                    fileInfo.put("executableMD5", md5);
                }
            }
        } catch (Exception e) {
            // ignore metadata errors - not critical for file listing
        }
        return fileInfo;
    }

    /**
     * Build a folder info map from a DomainFolder.
     */
    private static Map<String, Object> buildFolderInfoMap(DomainFolder folder) {
        Map<String, Object> folderInfo = new HashMap<>();
        folderInfo.put("folderPath", folder.getPathname());
        folderInfo.put("type", "folder");
        try {
            folderInfo.put("childCount", folder.getFiles().length + folder.getFolders().length);
        } catch (Exception e) {
            folderInfo.put("childCount", 0);
        }
        return folderInfo;
    }

    /**
     * List all files and folders from the shared repository (RepositoryAdapter), starting at root.
     * Paths are stored without leading slash in the repo; we emit folderPath with "/" prefix.
     *
     * @param repo connected repository
     * @param projectData used to resolve DomainFile for programPath when possible
     * @param items list to append to
     * @param addedPaths paths already added this call (no leading slash); updated as we add
     */
    private static void collectFromRepositoryRecursive(RepositoryAdapter repo, ProjectData projectData,
            List<Map<String, Object>> items, Set<String> addedPaths) {
        collectFromRepositoryAt(repo, "", projectData, items, addedPaths);
    }

    private static void collectFromRepositoryAt(RepositoryAdapter repo, String folderPath,
            ProjectData projectData, List<Map<String, Object>> items, Set<String> addedPaths) {
        try {
            String[] subfolders = repo.getSubfolderList(folderPath);
            if (subfolders != null) {
                for (String name : subfolders) {
                    String subPath = folderPath.isEmpty() ? name : folderPath + "/" + name;
                    String displayPath = "/" + subPath;
                    if (addedPaths.add(subPath)) {
                        Map<String, Object> folderInfo = new HashMap<>();
                        folderInfo.put("folderPath", displayPath);
                        folderInfo.put("type", "folder");
                        folderInfo.put("childCount", 0);
                        items.add(folderInfo);
                    }
                    collectFromRepositoryAt(repo, subPath, projectData, items, addedPaths);
                }
            }
            RepositoryItem[] repoItems = repo.getItemList(folderPath);
            if (repoItems != null) {
                for (RepositoryItem item : repoItems) {
                    if (item == null) continue;
                    String pathName = item.getPathName();
                    if (pathName == null || pathName.isEmpty()) continue;
                    if (addedPaths.contains(pathName)) continue;
                    addedPaths.add(pathName);
                    String displayPath = pathName.startsWith("/") ? pathName : "/" + pathName;
                    DomainFile domainFile = projectData.getFile(pathName);
                    if (domainFile != null) {
                        items.add(buildFileInfoMap(domainFile));
                    } else {
                        Map<String, Object> fileInfo = new HashMap<>();
                        fileInfo.put("programPath", displayPath);
                        fileInfo.put("type", "file");
                        fileInfo.put("name", item.getName());
                        int lastSlash = displayPath.lastIndexOf('/');
                        fileInfo.put("folderPath", lastSlash > 0 ? displayPath.substring(0, lastSlash + 1) : "/");
                        try {
                            String contentType = item.getContentType();
                            if (contentType != null) fileInfo.put("contentType", contentType);
                        } catch (Exception ignored) { }
                        items.add(fileInfo);
                    }
                }
            }
        } catch (IOException e) {
            Msg.debug(ProjectUtil.class, "Error listing repository folder " + folderPath + ": " + e.getMessage());
        }
    }

    /**
     * Collect all files and folders recursively from project root using a robust approach that
     * works correctly with shared/versioned Ghidra projects.
     * <p>
     * Uses ProjectData's Iterable&lt;DomainFile&gt; iterator as the primary source of truth
     * for files, since DomainFolder.getFiles()/getFolders() may return cached/incomplete
     * data for shared projects connected to a Ghidra Server.
     * <p>
     * Supplements with DomainFolder.getFolders() traversal to discover empty folders
     * (folders that exist in the project but contain no files).
     *
     * @param project the active project
     * @param items list to collect results into
     * @param addedPaths paths already added this call (e.g. from repository); no leading slash; updated as we add
     */
    private static void collectRecursiveViaProjectData(Project project, List<Map<String, Object>> items,
            Set<String> addedPaths) {
        if (project == null) {
            return;
        }
        DomainFolder startFolder = project.getProjectData().getRootFolder();
        if (startFolder == null) {
            return;
        }

        String startPath = startFolder.getPathname();
        boolean isRoot = "/".equals(startPath);

        Set<String> addedFilePaths = addedPaths != null ? addedPaths : new HashSet<>();
        // LinkedHashSet preserves insertion order for consistent output
        Set<String> discoveredFolderPaths = new LinkedHashSet<>();

        // Phase 1: Iterate ALL project files using ProjectData's Iterable<DomainFile>
        // This is the most reliable approach for shared/versioned projects because
        // it queries both local and server-side filesystems and merges the results,
        // unlike DomainFolder.getFiles() which may return only cached data.
        try {
            for (DomainFile file : project.getProjectData()) {
                String filePath = file.getPathname();
                String pathKey = (filePath != null && filePath.startsWith("/")) ? filePath.substring(1) : filePath;

                // Filter to files under the target folder
                boolean underTarget = isRoot || (filePath != null && filePath.startsWith(startPath + "/"));
                if (!underTarget || addedFilePaths.contains(pathKey)) {
                    continue;
                }

                try {
                    items.add(buildFileInfoMap(file));
                    addedFilePaths.add(pathKey);

                    // Discover intermediate folders from file path
                    int lastSlash = filePath.lastIndexOf('/');
                    String dir = (lastSlash > 0) ? filePath.substring(0, lastSlash) : "/";
                    while (dir != null && !dir.isEmpty()) {
                        if (dir.equals(startPath)) break;
                        if ("/".equals(dir) && isRoot) break;
                        if (!isRoot && !dir.startsWith(startPath + "/")) break;
                        discoveredFolderPaths.add(dir);
                        int idx = dir.lastIndexOf('/');
                        if (idx <= 0) break;
                        dir = dir.substring(0, idx);
                    }
                } catch (Exception e) {
                    Msg.debug(ProjectUtil.class, "Error processing file " + filePath + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            Msg.warn(ProjectUtil.class, "Error iterating project data for files (falling back to folder traversal): " + e.getMessage());
            // Fall back to the old approach if the iterator fails entirely
            String pathPrefix = isRoot ? "" : (startPath.endsWith("/") ? startPath : startPath + "/");
            collectFilesRecursive(startFolder, items, pathPrefix);
            return;
        }

        // Phase 2: Traverse folder hierarchy using getFolders() to discover empty folders
        // (folders that exist in the project structure but contain no files)
        collectSubfolderPathsRecursive(startFolder, discoveredFolderPaths);

        // Phase 3: Build folder entries and insert them before file entries (skip if already from repo)
        List<Map<String, Object>> folderItems = new ArrayList<>();
        for (String folderPath : discoveredFolderPaths) {
            String pathKey = (folderPath != null && folderPath.startsWith("/")) ? folderPath.substring(1) : folderPath;
            if (addedFilePaths.contains(pathKey)) {
                continue; // already added by repository listing
            }
            try {
                DomainFolder df = project.getProjectData().getFolder(folderPath);
                if (df != null) {
                    folderItems.add(buildFolderInfoMap(df));
                    addedFilePaths.add(pathKey);
                } else {
                    Map<String, Object> folderInfo = new HashMap<>();
                    folderInfo.put("folderPath", folderPath);
                    folderInfo.put("type", "folder");
                    folderInfo.put("childCount", 0);
                    folderItems.add(folderInfo);
                    addedFilePaths.add(pathKey);
                }
            } catch (Exception e) {
                Msg.debug(ProjectUtil.class, "Error building folder info for " + folderPath + ": " + e.getMessage());
            }
        }

        // Insert folders at the beginning for consistent output (folders before files)
        items.addAll(0, folderItems);

        Msg.debug(ProjectUtil.class, "collectRecursiveViaProjectData: found " +
            addedFilePaths.size() + " paths, " + discoveredFolderPaths.size() + " folders under " + startPath);
    }

    /**
     * Recursively collect subfolder paths using DomainFolder.getFolders().
     * Used to discover empty folders that can't be found via file paths alone.
     */
    private static void collectSubfolderPathsRecursive(DomainFolder folder, Set<String> paths) {
        if (folder == null) return;
        try {
            for (DomainFolder subfolder : folder.getFolders()) {
                if (subfolder == null) continue;
                String path = subfolder.getPathname();
                if (!paths.contains(path)) {
                    paths.add(path);
                }
                collectSubfolderPathsRecursive(subfolder, paths);
            }
        } catch (Exception e) {
            Msg.debug(ProjectUtil.class, "Error traversing subfolders: " + e.getMessage());
        }
    }

    /**
     * Augment a non-recursive folder listing with files and folders discovered
     * via ProjectData iterator, to handle shared/versioned projects where
     * DomainFolder.getFiles()/getFolders() may return cached/incomplete data.
     *
     * @param project the active project
     * @param folder the folder being listed
     * @param items the existing items list to augment
     */
    private static void augmentNonRecursiveWithProjectData(Project project, DomainFolder folder,
            List<Map<String, Object>> items) {
        if (project == null || folder == null) {
            return;
        }

        String folderPathname = folder.getPathname();
        boolean isRoot = "/".equals(folderPathname);

        // Track what's already been collected by the standard approach
        Set<String> existingFilePaths = new HashSet<>();
        Set<String> existingFolderPaths = new HashSet<>();
        for (Map<String, Object> item : items) {
            if ("file".equals(item.get("type"))) {
                existingFilePaths.add((String) item.get("programPath"));
            } else if ("folder".equals(item.get("type"))) {
                existingFolderPaths.add((String) item.get("folderPath"));
            }
        }

        // Iterate all project files to find any missing items in this folder
        try {
            for (DomainFile file : project.getProjectData()) {
                String filePath = file.getPathname();

                // Determine the parent folder path of this file
                int lastSlash = filePath.lastIndexOf('/');
                String parentPath = (lastSlash > 0) ? filePath.substring(0, lastSlash) : "/";

                if (parentPath.equals(folderPathname)) {
                    // Direct child file - add if not already present
                    if (!existingFilePaths.contains(filePath)) {
                        try {
                            items.add(buildFileInfoMap(file));
                            existingFilePaths.add(filePath);
                        } catch (Exception e) {
                            Msg.debug(ProjectUtil.class, "Error adding augmented file: " + e.getMessage());
                        }
                    }
                } else {
                    // Check if this file reveals a missing immediate subfolder
                    boolean isUnderFolder = isRoot
                        ? filePath.startsWith("/")
                        : filePath.startsWith(folderPathname + "/");

                    if (isUnderFolder) {
                        // Extract the immediate subfolder name
                        String remainder = isRoot
                            ? filePath.substring(1)
                            : filePath.substring(folderPathname.length() + 1);
                        int nextSlash = remainder.indexOf('/');
                        if (nextSlash > 0) {
                            String subfolderPath = isRoot
                                ? "/" + remainder.substring(0, nextSlash)
                                : folderPathname + "/" + remainder.substring(0, nextSlash);

                            if (!existingFolderPaths.contains(subfolderPath)) {
                                try {
                                    DomainFolder sf = project.getProjectData().getFolder(subfolderPath);
                                    if (sf != null) {
                                        items.add(buildFolderInfoMap(sf));
                                    } else {
                                        Map<String, Object> folderInfo = new HashMap<>();
                                        folderInfo.put("folderPath", subfolderPath);
                                        folderInfo.put("type", "folder");
                                        folderInfo.put("childCount", 0);
                                        items.add(folderInfo);
                                    }
                                    existingFolderPaths.add(subfolderPath);
                                } catch (Exception e) {
                                    Msg.debug(ProjectUtil.class, "Error adding augmented folder: " + e.getMessage());
                                }
                            }
                        } else if (nextSlash < 0) {
                            // File is directly in the root-relative path without subfolder
                            // This case is already handled by the parentPath check above
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(ProjectUtil.class, "Error in ProjectData augmentation: " + e.getMessage());
        }
    }

    /**
     * Get the active project if it matches the requested project.
     *
     * @param requestedProjectDir The directory of the requested project
     * @param requestedProjectName The name of the requested project
     * @return The active Project if it matches, or null if it doesn't match or no active project exists
     */
    public static Project getMatchingActiveProject(String requestedProjectDir, String requestedProjectName) {
        // Ghidra API: AppInfo.getActiveProject() - https://ghidra.re/ghidra_docs/api/ghidra/framework/main/AppInfo.html#getActiveProject()
        Project activeProject = AppInfo.getActiveProject();
        if (activeProject != null) {
            // Ghidra API: Project.getProjectLocator(), ProjectLocator.getProjectDir() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html#getProjectLocator(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectLocator.html#getProjectDir()
            String activeProjectDir = activeProject.getProjectLocator().getProjectDir().getAbsolutePath();
            String requestedDirAbsolute = new File(requestedProjectDir).getAbsolutePath();

            if (activeProjectDir.equals(requestedDirAbsolute) || activeProject.getName().equals(requestedProjectName)) {
                return activeProject;
            }
        }
        return null;
    }

    /**
     * Delete lock files for a project, using rename trick if file handle is in use.
     * <p>
     * Deletes both &lt;projectName&gt;.lock and &lt;projectName&gt;.lock~ files.
     * If direct deletion fails (file handle in use), attempts to rename the file
     * first, then delete it.
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param logContext Object for logging context (can be null)
     */
    public static void deleteLockFiles(File projectDir, String projectName, Object logContext) {
        File lockFile = new File(projectDir, projectName + ".lock");
        File lockFileBackup = new File(projectDir, projectName + ".lock~");

        // Check if force kill is enabled
        String forceIgnoreLock = System.getenv("AGENT_DECOMPILE_FORCE_IGNORE_LOCK");
        boolean forceKillEnabled = "true".equalsIgnoreCase(forceIgnoreLock);

        // Delete main lock file
        if (lockFile.exists()) {
            try {
                if (!lockFile.delete()) {
                    if (forceKillEnabled) {
                        forceKillAndDeleteLockFile(lockFile, logContext);
                    } else {
                        // Try rename trick if direct delete fails (file handle in use)
                        File tempFile = new File(projectDir, projectName + ".lock.tmp." + System.currentTimeMillis());
                        try {
                            Files.move(lockFile.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                            tempFile.delete();
                            logInfo(logContext, "Deleted lock file using rename trick: " + lockFile.getName());
                        } catch (IOException e) {
                            logInfo(logContext, "Warning: Could not delete lock file (may be in use): " + lockFile.getName() + " - " + e.getMessage());
                        }
                    }
                } else {
                    logInfo(logContext, "Deleted lock file: " + lockFile.getName());
                }
            } catch (Exception e) {
                logInfo(logContext, "Warning: Error deleting lock file: " + lockFile.getName() + " - " + e.getMessage());
            }
        }

        // Delete backup lock file
        if (lockFileBackup.exists()) {
            try {
                if (!lockFileBackup.delete()) {
                    if (forceKillEnabled) {
                        forceKillAndDeleteLockFile(lockFileBackup, logContext);
                    } else {
                        // Try rename trick if direct delete fails
                        File tempFile = new File(projectDir, projectName + ".lock~.tmp." + System.currentTimeMillis());
                        try {
                            Files.move(lockFileBackup.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                            tempFile.delete();
                            logInfo(logContext, "Deleted backup lock file using rename trick: " + lockFileBackup.getName());
                        } catch (IOException e) {
                            logInfo(logContext, "Warning: Could not delete backup lock file (may be in use): " + lockFileBackup.getName() + " - " + e.getMessage());
                        }
                    }
                } else {
                    logInfo(logContext, "Deleted backup lock file: " + lockFileBackup.getName());
                }
            } catch (Exception e) {
                logInfo(logContext, "Warning: Error deleting backup lock file: " + lockFileBackup.getName() + " - " + e.getMessage());
            }
        }
    }

    /**
     * Force kill locking processes and delete the lock file.
     * Uses Windows Restart Manager API or handle.exe as fallback to find locking processes,
     * then attempts taskkill with UAC elevation if needed.
     *
     * @param lockFile The lock file to delete
     * @param logContext Optional logging context
     */
    private static void forceKillAndDeleteLockFile(File lockFile, Object logContext) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("windows")) {
            logInfo(logContext, "Warning: Force kill only supported on Windows: " + lockFile.getName());
            return;
        }

        try {
            List<ProcessInfo> lockingProcesses = getLockingProcesses(lockFile.getAbsolutePath());

            if (lockingProcesses.isEmpty()) {
                logInfo(logContext, "No locking processes found for: " + lockFile.getName());
                // Try delete again in case handles were released
                if (lockFile.delete()) {
                    logInfo(logContext, "Deleted lock file after checking for locks: " + lockFile.getName());
                } else {
                    logInfo(logContext, "Warning: Could not delete lock file (no locks found but still in use): " + lockFile.getName());
                }
                return;
            }

            logInfo(logContext, "Found " + lockingProcesses.size() + " locking process(es) for " + lockFile.getName() + ": " +
                lockingProcesses.stream().map(p -> p.processName + "(PID:" + p.processId + ")").collect(Collectors.joining(", ")));

            for (ProcessInfo proc : lockingProcesses) {
                boolean killOk = killProcess(proc.processId);
                if (!killOk) {
                    logInfo(logContext, "Warning: Failed to kill process " + proc.processName + " (PID: " + proc.processId + ")");
                } else {
                    logInfo(logContext, "Killed locking process " + proc.processName + " (PID: " + proc.processId + ")");
                }
            }

            // Wait a bit for handles to be released
            Thread.sleep(1000);

            // Try delete again
            if (lockFile.delete()) {
                logInfo(logContext, "Deleted lock file after killing processes: " + lockFile.getName());
            } else {
                logInfo(logContext, "Warning: Could not delete lock file even after killing processes (may need UAC elevation): " + lockFile.getName());
            }

        } catch (Exception e) {
            logInfo(logContext, "Warning: Error during force kill attempt: " + lockFile.getName() + " - " + e.getMessage());
        }
    }

    /**
     * Get list of processes locking a file using Windows Restart Manager API or handle.exe fallback.
     */
    private static List<ProcessInfo> getLockingProcesses(String filePath) throws Exception {
        List<ProcessInfo> processes = new ArrayList<>();

        // Try Windows Restart Manager API first
        try {
            processes = getLockingProcessesViaRestartManager(filePath);
        } catch (Exception e) {
            // Fallback to handle.exe if Restart Manager fails
            try {
                processes = getLockingProcessesViaHandleExe(filePath);
            } catch (Exception e2) {
                throw new Exception("Failed to detect locking processes via Restart Manager (" + e.getMessage() +
                    ") and handle.exe fallback (" + e2.getMessage() + ")");
            }
        }

        return processes;
    }

    /**
     * Get locking processes using Windows Restart Manager API.
     */
    private static List<ProcessInfo> getLockingProcessesViaRestartManager(String filePath) throws Exception {
        // This would require JNI/JNA to call rstrtmgr.dll
        // For now, we'll rely on handle.exe fallback
        // TODO: Implement JNI/JNA version if needed

        throw new UnsupportedOperationException("Restart Manager API not implemented - using handle.exe fallback");
    }

    /**
     * Get locking processes using handle.exe tool.
     */
    private static List<ProcessInfo> getLockingProcessesViaHandleExe(String filePath) throws Exception {
        List<ProcessInfo> processes = new ArrayList<>();

        // Run handle.exe -a <filepath>
        ProcessBuilder pb = new ProcessBuilder("handle.exe", "-a", filePath);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            boolean inResults = false;

            while ((line = reader.readLine()) != null) {
                line = line.trim();

                if (line.isEmpty()) continue;

                // Look for the start of results
                if (line.contains("Handle v")) {
                    inResults = true;
                    continue;
                }

                if (!inResults) continue;

                // Parse lines like: java.exe           pid: 1234   type: File           1AB0: C:\path\to\file.lock
                if (line.matches("^[a-zA-Z0-9_\\.]+\\s+pid:\\s+\\d+.*")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3 && parts[1].equals("pid:")) {
                        try {
                            String processName = parts[0];
                            int processId = Integer.parseInt(parts[2]);
                            processes.add(new ProcessInfo(processId, processName));
                        } catch (NumberFormatException e) {
                            // Skip invalid lines
                        }
                    }
                }
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new Exception("handle.exe exited with code " + exitCode);
        }

        return processes;
    }

    /**
     * Kill a process by PID, trying regular taskkill first, then UAC elevation.
     */
    private static boolean killProcess(int processId) {
        try {
            // Try regular taskkill first
            if (killProcessRegular(processId)) {
                return true;
            }

            // Fall back to UAC elevation
            return killProcessElevated(processId);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Kill process using regular taskkill (no elevation).
     */
    private static boolean killProcessRegular(int processId) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("taskkill.exe", "/PID", String.valueOf(processId), "/T", "/F");
        pb.redirectErrorStream(true);
        Process process = pb.start();

        int exitCode = process.waitFor();
        return exitCode == 0;
    }

    /**
     * Kill process using taskkill with UAC elevation.
     */
    private static boolean killProcessElevated(int processId) throws Exception {
        // Use PowerShell to run taskkill with RunAs verb
        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe",
            "-Command",
            "Start-Process -FilePath 'taskkill.exe' -ArgumentList '/PID', '" + processId + "', '/T', '/F' -Verb RunAs -Wait"
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();

        int exitCode = process.waitFor();
        return exitCode == 0;
    }

    /**
     * Simple process info container.
     */
    private static class ProcessInfo {
        final int processId;
        final String processName;

        ProcessInfo(int processId, String processName) {
            this.processId = processId;
            this.processName = processName;
        }
    }

    /**
     * Log an info message with context
     */
    private static void logInfo(Object logContext, String message) {
        if (logContext != null) {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(logContext, message);
        } else {
            // Ghidra API: Msg.info(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#info(java.lang.Object,java.lang.Object)
            Msg.info(ProjectUtil.class, message);
        }
    }
}
