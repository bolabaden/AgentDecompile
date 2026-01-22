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
 * 
 * This filter explicitly sets HTTP keep-alive headers to ensure long-lived
 * MCP sessions don't get terminated due to connection timeouts. It prevents
 * the "Session terminated" error that occurs when the server closes connections
 * before the client finishes processing.
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
