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

import ghidra.framework.model.Project;

/**
 * Holds the project opened by the headless launcher when running without GUI.
 * In headless mode, {@link ghidra.framework.main.AppInfo#getActiveProject()} is often null
 * because there is no FrontEnd/ProjectManager. The headless launcher sets the opened project
 * here so tools (e.g. list-project-files) can use it.
 */
public final class HeadlessProjectHolder {
    private static volatile Project headlessProject = null;

    private HeadlessProjectHolder() {}

    /**
     * Set the project opened in headless mode. Called by {@link agentdecompile.headless.AgentDecompileHeadlessLauncher}.
     *
     * @param project the opened project, or null to clear
     */
    public static void setProject(Project project) {
        headlessProject = project;
    }

    /**
     * Get the project opened in headless mode, if any.
     *
     * @return the headless project, or null
     */
    public static Project getProject() {
        return headlessProject;
    }

    /**
     * Clear the headless project. Called on launcher stop.
     */
    public static void clear() {
        headlessProject = null;
    }
}
