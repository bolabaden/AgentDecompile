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

/**
 * Utility class for reading default parameter values from environment variables.
 * Environment variables follow the pattern: AGENT_DECOMPILE_&lt;PARAMETER_NAME&gt;
 * where PARAMETER_NAME is the parameter name in UPPER_SNAKE_CASE.
 * <p>
 * Examples: auto_label -&gt; AGENT_DECOMPILE_AUTO_LABEL; max_results -&gt; AGENT_DECOMPILE_MAX_RESULTS.
 * </p>
 * <p>
 * Internal utility; no Ghidra or MCP API (uses {@link System#getenv()}).
 * </p>
 */
public class EnvConfigUtil {

    /**
     * Get a boolean default value from environment variable.
     * Checks AGENT_DECOMPILE_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set
     */
    public static boolean getBooleanDefault(String parameterName, boolean defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null) {
            return defaultValue;
        }

        String normalized = envValue.trim().toLowerCase();
        return "true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized);
    }

    /**
     * Get a string default value from environment variable.
     * Checks AGENT_DECOMPILE_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set
     */
    public static String getStringDefault(String parameterName, String defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.trim().isEmpty()) {
            return defaultValue;
        }
        return envValue.trim();
    }

    /**
     * Get an integer default value from environment variable.
     * Checks AGENT_DECOMPILE_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set or invalid
     */
    public static int getIntDefault(String parameterName, int defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.trim().isEmpty()) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(envValue.trim());
        } catch (NumberFormatException e) {
            // Invalid format, return default
            return defaultValue;
        }
    }

    /**
     * Get a double default value from environment variable.
     * Checks AGENT_DECOMPILE_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set or invalid
     */
    public static double getDoubleDefault(String parameterName, double defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.trim().isEmpty()) {
            return defaultValue;
        }

        try {
            return Double.parseDouble(envValue.trim());
        } catch (NumberFormatException e) {
            // Invalid format, return default
            return defaultValue;
        }
    }

    /**
     * Convert a parameter name to environment variable name.
     * Converts snake_case or camelCase to AGENT_DECOMPILE_UPPER_SNAKE_CASE.
     *
     * Examples:
     * - auto_label -> AGENT_DECOMPILE_AUTO_LABEL
 * - auto_tag -> AGENT_DECOMPILE_AUTO_TAG
     * - autoLabel -> AGENT_DECOMPILE_AUTO_LABEL
     * - autoTag -> AGENT_DECOMPILE_AUTO_TAG
     * - max_results -> AGENT_DECOMPILE_MAX_RESULTS
     * - analyzeAfterImport -> AGENT_DECOMPILE_ANALYZE_AFTER_IMPORT
     *
     * @param parameterName The parameter name
     * @return The environment variable name
     */
    private static String toEnvVarName(String parameterName) {
        if (parameterName == null || parameterName.isEmpty()) {
            return "AGENT_DECOMPILE_";
        }

        // Convert camelCase to snake_case first if needed
        if (parameterName.matches(".*[a-z][A-Z].*")) {
            // Has camelCase pattern, convert to snake_case
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameterName.length(); i++) {
                char c = parameterName.charAt(i);
                if (Character.isUpperCase(c) && i > 0) {
                    sb.append('_');
                }
                sb.append(Character.toUpperCase(c));
            }
            return "AGENT_DECOMPILE_" + sb.toString();
        } else {
            // Already snake_case, just uppercase
            return "AGENT_DECOMPILE_" + parameterName.toUpperCase();
        }
    }
}
