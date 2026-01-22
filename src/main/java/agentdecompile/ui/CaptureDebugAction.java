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
 * Menu action for capturing debug information for troubleshooting.
 * Accessible from Tools -> AgentDecompile -> Capture Debug Info
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

            // Show success message with file location
            Msg.showInfo(
                getClass(),
                tool.getToolFrame(),
                "Debug Info Captured",
                "Debug information saved to:\n" + zipFile.getAbsolutePath()
            );

        } catch (Exception e) {
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
