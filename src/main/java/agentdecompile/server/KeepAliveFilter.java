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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * HTTP keep-alive filter to prevent premature connection termination.
 * Sets keep-alive headers so long-lived MCP sessions are not closed by timeouts.
 * <p>
 * Uses Jakarta Servlet API: {@link jakarta.servlet.Filter} -
 * <a href="https://jakarta.ee/specifications/platform/9/jakarta-platform-spec-9.0">Jakarta EE</a>.
 * </p>
 */
public class KeepAliveFilter implements Filter {

    /**
     * Initialize the filter (no-op)
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization needed
    }

    /**
     * Add keep-alive headers to HTTP responses
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Only process HTTP requests
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Explicitly set keep-alive headers to prevent connection termination
        // Connection: keep-alive tells the client to keep the connection open
        httpResponse.setHeader("Connection", "keep-alive");
        
        // Keep-Alive header specifies timeout and max requests
        // timeout=86400: keep connection alive for 24 hours of inactivity (matches Jetty idle timeout)
        // This prevents premature connection closure that causes "Session terminated" errors
        // The MCP SDK's keepAliveInterval (30s) sends periodic messages to keep the connection alive
        // max=10000: allow up to 10000 requests on the same connection for long-running sessions
        httpResponse.setHeader("Keep-Alive", "timeout=86400, max=10000");

        // Continue with the filter chain
        chain.doFilter(request, response);
    }

    /**
     * Cleanup (no-op)
     */
    @Override
    public void destroy() {
        // No cleanup needed
    }
}
