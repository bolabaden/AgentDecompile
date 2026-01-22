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

/**
 * Utility class for reading default parameter values from environment variables.
 * Environment variables follow the pattern: AGENT_DECOMPILE_<PARAMETER_NAME>
 * where PARAMETER_NAME is the parameter name in UPPER_SNAKE_CASE.
 *
 * Examples:
 * - auto_label -> AGENT_DECOMPILE_AUTO_LABEL
 * - auto_tag -> AGENT_DECOMPILE_AUTO_TAG
 * - max_results -> AGENT_DECOMPILE_MAX_RESULTS
 * - analyze_after_import -> AGENT_DECOMPILE_ANALYZE_AFTER_IMPORT
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
