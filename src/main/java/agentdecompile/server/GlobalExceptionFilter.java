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

import ghidra.util.Msg;

/**
 * Global exception-catching filter that prevents unhandled exceptions from crashing
 * the MCP server connection.
 * <p>
 * This filter wraps the entire servlet filter chain and catches any exceptions that
 * propagate up from tool execution, the MCP transport layer, or Jetty internals.
 * Instead of letting Jetty render an HTML error page or close the connection, it
 * returns a structured JSON error response that keeps the connection alive.
 * <p>
 * This is critical for stability under heavy concurrent load: when many parallel
 * requests overwhelm Ghidra's resources, a single tool failure can cause an exception
 * that cascades into HTTP 500 errors. Without this filter, those 500 errors break
 * the MCP session permanently (the Python bridge sees BrokenResourceError and
 * ClosedResourceError). With this filter, errors are contained and the session
 * remains alive.
 * <p>
 * Uses Jakarta Servlet API: {@link jakarta.servlet.Filter} -
 * <a href="https://jakarta.ee/specifications/platform/9/jakarta-platform-spec-9.0">Jakarta EE</a>.
 * </p>
 */
public class GlobalExceptionFilter implements Filter {

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

        try {
            chain.doFilter(request, response);
        } catch (Exception e) {
            // Log the error
            Msg.error(this, String.format(
                "Caught unhandled exception for %s %s: %s: %s",
                httpRequest.getMethod(),
                httpRequest.getRequestURI(),
                e.getClass().getName(),
                e.getMessage()), e);

            // Only write error response if the response hasn't been committed yet
            // (If it's already committed, writing more data would cause another exception)
            if (!httpResponse.isCommitted()) {
                try {
                    // Reset the response to clear any partial output
                    httpResponse.reset();
                    
                    // Set status and headers
                    httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    httpResponse.setContentType("application/json");
                    httpResponse.setHeader("Connection", "keep-alive");
                    httpResponse.setHeader("Keep-Alive", "timeout=86400, max=10000");

                    // Return a structured JSON-RPC error response
                    String errorJson = String.format(
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"},\"id\":null}",
                        -32603,
                        escapeJson("Internal server error: " + e.getClass().getSimpleName() + 
                                   ". The server is under heavy load. Please retry in a moment."));
                    httpResponse.getWriter().write(errorJson);
                    httpResponse.getWriter().flush();
                } catch (Exception writeError) {
                    // If we can't even write the error response, just log it
                    Msg.error(this, "Failed to write error response: " + writeError.getMessage());
                }
            } else {
                Msg.warn(this, "Response already committed - cannot write error JSON. " +
                    "The client may see an incomplete response.");
            }
        }
    }

    /**
     * Escape special characters for JSON string values.
     * @param input The string to escape
     * @return JSON-safe string
     */
    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    @Override
    public void destroy() {
        // No cleanup needed
    }
}
