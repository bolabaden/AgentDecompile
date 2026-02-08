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

import java.io.IOException;

import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.HeadlessClientAuthenticator;
import ghidra.framework.client.PasswordClientAuthenticator;
import ghidra.util.Msg;

/**
 * Reads shared-project / Ghidra Server configuration from environment variables
 * and applies authentication so that opening shared projects works in headless mode.
 * <p>
 * Environment variables (all optional):
 * <ul>
 *   <li>{@code AGENT_DECOMPILE_SERVER_USERNAME} - Username for Ghidra Server (password auth)</li>
 *   <li>{@code AGENT_DECOMPILE_SERVER_PASSWORD} - Password for Ghidra Server (password auth)</li>
 *   <li>{@code AGENT_DECOMPILE_SERVER_HOST} - Server host (for reference / URL-based open)</li>
 *   <li>{@code AGENT_DECOMPILE_SERVER_PORT} - Server port (0 or unset = default 13100)</li>
 *   <li>{@code AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY} - Repository name on server</li>
 *   <li>{@code AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH} - PKI/SSH keystore path (alternative to password)</li>
 *   <li>{@code AGENT_DECOMPILE_GHIDRA_SERVER_ALLOW_PASSWORD_PROMPT} - Allow console password prompt (true/false)</li>
 * </ul>
 * <p>
 * If both username+password and keystore are set, password auth is applied first (and used when
 * opening projects); keystore can be used for HeadlessClientAuthenticator for other prompts.
 * <p>
 * Ghidra API: {@link ClientUtil}, {@link PasswordClientAuthenticator}, {@link HeadlessClientAuthenticator}.
 */
public final class SharedProjectEnvConfig {

    /** Environment variable: Ghidra Server username (password authentication). */
    public static final String ENV_SERVER_USERNAME = "AGENT_DECOMPILE_SERVER_USERNAME";
    /** Environment variable: Ghidra Server password (password authentication). */
    public static final String ENV_SERVER_PASSWORD = "AGENT_DECOMPILE_SERVER_PASSWORD";
    /** Environment variable: Ghidra Server host. */
    public static final String ENV_SERVER_HOST = "AGENT_DECOMPILE_SERVER_HOST";
    /** Environment variable: Ghidra Server port (0 or unset = default). */
    public static final String ENV_SERVER_PORT = "AGENT_DECOMPILE_SERVER_PORT";
    /** Environment variable: Repository name on the server. */
    public static final String ENV_GHIDRA_SERVER_REPOSITORY = "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY";
    /** Environment variable: PKI/SSH keystore path (alternative to password). */
    public static final String ENV_GHIDRA_SERVER_KEYSTORE_PATH = "AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH";
    /** Environment variable: Allow console password prompt (true/false). */
    public static final String ENV_GHIDRA_SERVER_ALLOW_PASSWORD_PROMPT = "AGENT_DECOMPILE_GHIDRA_SERVER_ALLOW_PASSWORD_PROMPT";
    /** Environment variable: Path to Ghidra project file (.gpr) to open when no project is active. */
    public static final String ENV_PROJECT_PATH = "AGENT_DECOMPILE_PROJECT_PATH";

    /** Default Ghidra Server port when not specified. */
    public static final int DEFAULT_SERVER_PORT = 13100;

    private SharedProjectEnvConfig() {
    }

    /**
     * Read server username from environment.
     *
     * @return username or null if unset/empty
     */
    public static String getServerUsername() {
        return trimOrNull(System.getenv(ENV_SERVER_USERNAME));
    }

    /**
     * Read server password from environment.
     *
     * @return password or null if unset/empty
     */
    public static String getServerPassword() {
        return trimOrNull(System.getenv(ENV_SERVER_PASSWORD));
    }

    /**
     * Read server host from environment.
     *
     * @return host or null if unset/empty
     */
    public static String getServerHost() {
        return trimOrNull(System.getenv(ENV_SERVER_HOST));
    }

    /**
     * Read server port from environment; 0 or invalid means default.
     *
     * @return port number, or {@link #DEFAULT_SERVER_PORT} if unset/invalid
     */
    public static int getServerPort() {
        String raw = trimOrNull(System.getenv(ENV_SERVER_PORT));
        if (raw == null) {
            return DEFAULT_SERVER_PORT;
        }
        try {
            int p = Integer.parseInt(raw);
            return p <= 0 ? DEFAULT_SERVER_PORT : p;
        } catch (NumberFormatException e) {
            return DEFAULT_SERVER_PORT;
        }
    }

    /**
     * Read repository name from environment.
     *
     * @return repository name or null if unset/empty
     */
    public static String getRepositoryName() {
        return trimOrNull(System.getenv(ENV_GHIDRA_SERVER_REPOSITORY));
    }

    /**
     * Read keystore path from environment (for PKI/SSH auth).
     *
     * @return keystore path or null if unset/empty
     */
    public static String getKeystorePath() {
        return trimOrNull(System.getenv(ENV_GHIDRA_SERVER_KEYSTORE_PATH));
    }

    /**
     * Read project path (.gpr file) from environment.
     * Used when no project is active to auto-open (e.g. by open-programs resource).
     *
     * @return absolute path to .gpr file or null if unset/empty
     */
    public static String getProjectPath() {
        return trimOrNull(System.getenv(ENV_PROJECT_PATH));
    }

    /**
     * Whether to allow console password prompt (for HeadlessClientAuthenticator).
     *
     * @return true if env is set to true/1, false otherwise
     */
    public static boolean isAllowPasswordPrompt() {
        String v = trimOrNull(System.getenv(ENV_GHIDRA_SERVER_ALLOW_PASSWORD_PROMPT));
        return v != null && ("true".equalsIgnoreCase(v) || "1".equals(v));
    }

    /**
     * Check if any shared-project auth is configured via environment.
     *
     * @return true if username+password or keystore path is set
     */
    public static boolean hasAuthFromEnv() {
        return (getServerUsername() != null && getServerPassword() != null) || getKeystorePath() != null;
    }

    /**
     * Apply shared-project authentication from environment variables.
     * Call this before opening any project so that Ghidra Server connections can authenticate.
     * <ul>
     *   <li>If {@code AGENT_DECOMPILE_SERVER_USERNAME} and {@code AGENT_DECOMPILE_SERVER_PASSWORD}
     *       are set, installs {@link PasswordClientAuthenticator} via {@link ClientUtil#setClientAuthenticator(ClientAuthenticator)}.</li>
     *   <li>If {@code AGENT_DECOMPILE_GHIDRA_SERVER_KEYSTORE_PATH} is set, installs
     *       {@link HeadlessClientAuthenticator} (PKI/SSH or console password prompts).</li>
     * </ul>
     *
     * @param logContext optional object for logging (e.g. this); can be null
     */
    public static void applySharedProjectAuthFromEnv(Object logContext) {
        Object ctx = logContext != null ? logContext : SharedProjectEnvConfig.class;

        String username = getServerUsername();
        String password = getServerPassword();
        String keystorePath = getKeystorePath();

        if (username != null && password != null) {
            try {
                ClientAuthenticator authenticator = new PasswordClientAuthenticator(username, password);
                ClientUtil.setClientAuthenticator(authenticator);
                Msg.info(ctx, "Shared project authentication configured from environment (username: " + username + ")");
            } catch (Exception e) {
                Msg.warn(ctx, "Failed to set password authenticator from env: " + e.getMessage());
            }
        }

        if (keystorePath != null) {
            try {
                HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                    username != null ? username : null,
                    keystorePath,
                    isAllowPasswordPrompt()
                );
                Msg.info(ctx, "Headless client authenticator installed from environment (keystore)");
            } catch (IOException e) {
                Msg.warn(ctx, "Failed to install headless client authenticator from env: " + e.getMessage());
            }
        }
    }

    private static String trimOrNull(String s) {
        if (s == null) {
            return null;
        }
        s = s.trim();
        return s.isEmpty() ? null : s;
    }
}
