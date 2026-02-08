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
package agentdecompile.ui;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.InputDialog;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import agentdecompile.debug.DebugCaptureService;

/**
 * Menu action for capturing debug information (Tools -&gt; AgentDecompile -&gt; Capture Debug Info).
 * <p>
 * Ghidra API: {@link docking.action.DockingAction}, {@link docking.widgets.dialogs.InputDialog} -
 * <a href="https://ghidra.re/ghidra_docs/api/docking/action/DockingAction.html">DockingAction API</a>.
 * Uses {@link agentdecompile.debug.DebugCaptureService} for capture.
 * </p>
 */
public class CaptureDebugAction extends DockingAction {

    private static final String ACTION_NAME = "Capture Debug Info";
    private static final String MENU_GROUP = "AgentDecompile";

    private final PluginTool tool;

    /**
     * Create a new CaptureDebugAction.
     * @param owner The owner plugin name
     * @param tool The plugin tool for showing dialogs
     */
    public CaptureDebugAction(String owner, PluginTool tool) {
        super(ACTION_NAME, owner);
        this.tool = tool;

        // Set up menu location: Tools -> AgentDecompile -> Capture Debug Info
        setMenuBarData(new MenuData(
            new String[] { "Tools", MENU_GROUP, ACTION_NAME }
        ));

        setEnabled(true);
        setDescription("Capture debug information for troubleshooting AgentDecompile issues");
    }

    @Override
    public void actionPerformed(ActionContext context) {
        // Show input dialog for user message
        InputDialog dialog = new InputDialog(
            "Capture Debug Info",
            "Describe the issue or context (optional):"
        );

        tool.showDialog(dialog);

        if (dialog.isCanceled()) {
            return;
        }

        String userMessage = dialog.getValue();
        if (userMessage == null || userMessage.isBlank()) {
            userMessage = "(No message provided)";
        }

        try {
            DebugCaptureService service = new DebugCaptureService();
            File zipFile = service.captureDebugInfo(userMessage);

            // Ghidra API: Msg.showInfo(Object, Component, String, Object) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#showInfo(java.lang.Object,java.awt.Component,java.lang.String,java.lang.Object)
            Msg.showInfo(
                getClass(),
                tool.getToolFrame(),
                "Debug Info Captured",
                "Debug information saved to:\n" + zipFile.getAbsolutePath()
            );

        } catch (Exception e) {
            // Ghidra API: Msg.showError(Object, Component, String, Object, Throwable) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#showError(java.lang.Object,java.awt.Component,java.lang.String,java.lang.Object,java.lang.Throwable)
            Msg.showError(
                getClass(),
                tool.getToolFrame(),
                "Capture Failed",
                "Failed to capture debug info: " + e.getMessage(),
                e
            );
        }
    }
}
