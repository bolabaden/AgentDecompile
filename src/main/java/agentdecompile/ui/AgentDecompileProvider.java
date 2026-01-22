/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agentdecompile.ui;

import java.awt.BorderLayout;
import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * UI provider for the AgentDecompile plugin.
 * This class provides the graphical user interface for configuring and
 * monitoring the AgentDecompile server.
 */
public class AgentDecompileProvider extends ComponentProvider {
    private JPanel panel;
    private JTextArea statusArea;
    private DockingAction configAction;

    /**
     * Constructor
     * @param plugin The parent plugin
     * @param owner The owner name
     */
    public AgentDecompileProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "AgentDecompile Provider", owner);
        try {
            buildPanel();
            createActions();
            setStatusText("AgentDecompile Model Context Protocol server is running");
        } catch (Exception e) {
            // If GUI components can't be created (e.g., no display), just log and continue
            // The provider will still exist but without GUI components
            System.err.println("Failed to initialize AgentDecompile UI components: " + e.getMessage());
            // Don't rethrow - allow the plugin to load without GUI
        }
    }

    /**
     * Build the UI panel
     */
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        // Status area to show server status
        statusArea = new JTextArea(10, 40);
        statusArea.setEditable(false);

        // Add components to panel
        panel.add(new JScrollPane(statusArea), BorderLayout.CENTER);

        // Only set visible if we have a display
        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            setVisible(true);
        }
    }

    /**
     * Create actions for the toolbar
     */
    private void createActions() {
        configAction = new DockingAction("AgentDecompile Configuration", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                // TODO: Show configuration dialog
                JOptionPane.showMessageDialog(panel,
                    "AgentDecompile Configuration (TODO)",
                    "AgentDecompile Configuration",
                    JOptionPane.INFORMATION_MESSAGE);
            }
        };

        configAction.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));
        configAction.setEnabled(true);
        configAction.setDescription("Configure AgentDecompile");
        configAction.setHelpLocation(new HelpLocation("AgentDecompile", "Configuration"));

        addLocalAction(configAction);
    }

    /**
     * Set status text to display
     * @param status The status text to display
     */
    public void setStatusText(String status) {
        statusArea.append(status + "\n");
        statusArea.setCaretPosition(statusArea.getText().length());
    }

    /**
     * Get the UI component
     * @return The JComponent for this provider
     */
    @Override
    public JComponent getComponent() {
        return panel;
    }
}
