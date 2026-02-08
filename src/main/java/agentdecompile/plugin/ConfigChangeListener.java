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

/**
 * Interface for listening to configuration changes in the AgentDecompile plugin.
 * Implementations register with ConfigManager to receive notifications when configuration values change.
 * <p>
 * Internal interface; no Ghidra or MCP API.
 * </p>
 */
public interface ConfigChangeListener {
    
    /**
     * Called when a configuration option has changed.
     * 
     * @param category The category of the option that changed
     * @param name The name of the option that changed
     * @param oldValue The previous value of the option
     * @param newValue The new value of the option
     */
    void onConfigChanged(String category, String name, Object oldValue, Object newValue);
}