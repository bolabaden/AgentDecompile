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
package agentdecompile.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.util.Msg;

import agentdecompile.plugin.ConfigManager;

/**
 * Authentication filter for API key-based access control to the MCP server.
 * Checks for the X-API-Key header when authentication is enabled in configuration.
 * <p>
 * Uses {@link agentdecompile.plugin.ConfigManager} for API key configuration.
 * Servlet API: Jakarta Servlet Filter; MCP transport: <a href="https://modelcontextprotocol.info/docs/sdk/java/mcp-server/">MCP Java Server</a>.
 * </p>
 */
public class ApiKeyAuthFilter implements Filter {
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private final ConfigManager configManager;

    /**
     * Constructor
     * @param configManager The configuration manager to get API key settings from
     */
    public ApiKeyAuthFilter(ConfigManager configManager) {
        this.configManager = configManager;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Only process HTTP requests
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Check if API key authentication is enabled
        if (!configManager.isApiKeyEnabled()) {
            // Authentication disabled - allow all requests
            chain.doFilter(request, response);
            return;
        }

        // Get the API key from the request header
        String providedApiKey = httpRequest.getHeader(API_KEY_HEADER);
        String configuredApiKey = configManager.getApiKey();

        // Validate API key
        if (providedApiKey == null || providedApiKey.trim().isEmpty()) {
            // Ghidra API: Msg.warn(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
            Msg.warn(this, "API key authentication failed: missing X-API-Key header from " +
                     getClientInfo(httpRequest));
            sendUnauthorizedResponse(httpResponse, "Missing X-API-Key header");
            return;
        }

        if (configuredApiKey == null || configuredApiKey.trim().isEmpty()) {
            // Ghidra API: Msg.error(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#error(java.lang.Object,java.lang.Object)
            Msg.error(this, "API key authentication failed: no API key configured in settings");
            sendUnauthorizedResponse(httpResponse, "Server configuration error");
            return;
        }

        if (!providedApiKey.equals(configuredApiKey)) {
            // Ghidra API: Msg.warn(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#warn(java.lang.Object,java.lang.Object)
            Msg.warn(this, "API key authentication failed: invalid API key from " +
                     getClientInfo(httpRequest));
            sendUnauthorizedResponse(httpResponse, "Invalid API key");
            return;
        }

        // API key is valid - allow the request to continue
        // Ghidra API: Msg.debug(Object, String) - https://ghidra.re/ghidra_docs/api/ghidra/util/Msg.html#debug(java.lang.Object,java.lang.Object)
        Msg.debug(this, "API key authentication successful for " + getClientInfo(httpRequest));
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // No cleanup needed
    }

    /**
     * Send an HTTP 401 Unauthorized response
     * @param response The HTTP response to modify
     * @param message The error message to include
     * @throws IOException If writing the response fails
     */
    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");

        // Use Jackson to properly serialize JSON and prevent injection
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", message);

        response.getWriter().write(JSON_MAPPER.writeValueAsString(errorResponse));
    }

    /**
     * Get client information for logging
     * @param request The HTTP request
     * @return A string with client IP and user agent
     */
    private String getClientInfo(HttpServletRequest request) {
        String clientIP;
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, the first is the original client
            clientIP = xForwardedFor.split(",")[0].trim();
        } else {
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                clientIP = xRealIp;
            } else {
                clientIP = request.getRemoteAddr();
            }
        }
        String userAgent = request.getHeader("User-Agent");
        return clientIP + (userAgent != null ? " (" + userAgent + ")" : "");
    }
}