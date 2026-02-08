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
package agentdecompile.plugin.config;

/**
 * Listener interface for configuration backend changes.
 * Backends that support change notifications call this when values change.
 * <p>
 * Internal interface; no external API.
 * </p>
 */
public interface ConfigurationBackendListener {

    /**
     * Called when a configuration value changes
     * @param category The configuration category
     * @param name The configuration name
     * @param oldValue The previous value
     * @param newValue The new value
     */
    void onConfigurationChanged(String category, String name, Object oldValue, Object newValue);
}
