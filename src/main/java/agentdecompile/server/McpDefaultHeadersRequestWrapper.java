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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.Collections;
import java.util.Enumeration;
import java.util.UUID;

/**
 * Wraps an HTTP request to supply default MCP transport headers when missing.
 * Makes Accept and mcp-session-id optional for callers (e.g. curl or simple
 * HTTP clients) by defaulting to values required by the MCP SDK.
 * <p>
 * Defaults applied only when the client omits the header or sends a value
 * that does not satisfy the SDK:
 * <ul>
 *   <li>Accept: "text/event-stream, application/json" when missing or when
 *       it does not include both types</li>
 *   <li>mcp-session-id: a new UUID per request when missing</li>
 * </ul>
 */
public class McpDefaultHeadersRequestWrapper extends HttpServletRequestWrapper {

    /** Default Accept value required by MCP streamable HTTP transport. */
    public static final String DEFAULT_ACCEPT = "text/event-stream, application/json";

    private final String effectiveAccept;
    private final String effectiveSessionId;

    /**
     * @param request the wrapped request
     */
    public McpDefaultHeadersRequestWrapper(HttpServletRequest request) {
        super(request);
        String accept = request.getHeader("Accept");
        if (accept == null || accept.isBlank()
                || !accept.contains("text/event-stream")
                || !accept.contains("application/json")) {
            this.effectiveAccept = DEFAULT_ACCEPT;
        } else {
            this.effectiveAccept = accept;
        }
        String sessionId = request.getHeader("mcp-session-id");
        if (sessionId == null || sessionId.isBlank()) {
            this.effectiveSessionId = UUID.randomUUID().toString();
        } else {
            this.effectiveSessionId = sessionId;
        }
    }

    @Override
    public String getHeader(String name) {
        if (name == null) {
            return super.getHeader(name);
        }
        switch (name) {
            case "Accept":
                return effectiveAccept;
            case "mcp-session-id":
                return effectiveSessionId;
            default:
                return super.getHeader(name);
        }
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (name == null) {
            return super.getHeaders(name);
        }
        switch (name) {
            case "Accept":
                return Collections.enumeration(Collections.singletonList(effectiveAccept));
            case "mcp-session-id":
                return Collections.enumeration(Collections.singletonList(effectiveSessionId));
            default:
                return super.getHeaders(name);
        }
    }
}
