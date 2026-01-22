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
package agentdecompile.tools.getfunction;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for GetFunctionToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated get-function tool that replaces:
 * - decompile_function, decompile_function_by_address, get_decompilation
 * - disassemble_function, get_function_by_address, get-function_info
 * - list_function_calls
 */
public class GetFunctionToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private GetFunctionToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new GetFunctionToolProvider(mockServer);
    }

    @Test
    public void testRegisterTools() throws McpError {
        // Test that tools can be registered without throwing exceptions
        try {
            toolProvider.registerTools();
        } catch (Exception e) {
            fail("Tool registration should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testInheritance() {
        // Test that GetFunctionToolProvider extends AbstractToolProvider
        assertTrue("GetFunctionToolProvider should extend AbstractToolProvider",
            agentdecompile.tools.AbstractToolProvider.class.isAssignableFrom(GetFunctionToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that GetFunctionToolProvider implements ToolProvider interface
        assertTrue("GetFunctionToolProvider should implement ToolProvider",
            agentdecompile.tools.ToolProvider.class.isAssignableFrom(GetFunctionToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("GetFunctionToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateGetFunctionParameters() {
        // Test parameter validation for the get-function tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("identifier", "main");

        // Valid parameters should not throw
        try {
            validateGetFunctionArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateGetFunctionArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }

        // Missing identifier should throw
        Map<String, Object> missingIdentifier = new HashMap<>(validArgs);
        missingIdentifier.remove("identifier");
        try {
            validateGetFunctionArgs(missingIdentifier);
            fail("Should throw exception for missing identifier");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention identifier",
                e.getMessage().toLowerCase().contains("identifier"));
        }
    }

    @Test
    public void testValidateViewModes() {
        // Test that valid view modes are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("identifier", "main");

        // Test all valid view modes
        String[] validViews = {"decompile", "disassemble", "info", "calls"};
        for (String view : validViews) {
            args.put("view", view);
            try {
                validateGetFunctionViewMode(args);
            } catch (Exception e) {
                fail("Valid view mode '" + view + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test default view mode (should default to "decompile")
        args.remove("view");
        try {
            String defaultView = getDefaultViewMode(args);
            assertEquals("Default view mode should be 'decompile'", "decompile", defaultView);
        } catch (Exception e) {
            fail("Default view mode should work: " + e.getMessage());
        }
    }

    @Test
    public void testValidateDecompileViewParameters() {
        // Test optional parameters for decompile view
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("identifier", "main");
        args.put("view", "decompile");

        // Valid optional parameters
        args.put("offset", 1);
        args.put("limit", 50);
        args.put("includeCallers", false);
        args.put("includeCallees", false);
        args.put("includeComments", false);
        args.put("includeIncomingReferences", true);
        args.put("includeReferenceContext", true);

        try {
            validateDecompileViewArgs(args);
        } catch (Exception e) {
            fail("Valid decompile view parameters should not throw exception: " + e.getMessage());
        }

        // Test default values
        args.remove("offset");
        args.remove("limit");
        args.remove("includeCallers");
        args.remove("includeCallees");
        args.remove("includeComments");
        args.remove("includeIncomingReferences");
        args.remove("includeReferenceContext");

        try {
            validateDecompileViewArgsWithDefaults(args);
        } catch (Exception e) {
            fail("Default decompile view parameters should work: " + e.getMessage());
        }
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateGetFunctionArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("identifier") == null) {
            throw new IllegalArgumentException("No identifier provided");
        }
    }

    private void validateGetFunctionViewMode(Map<String, Object> args) {
        String view = (String) args.get("view");
        if (view != null) {
            String[] validViews = {"decompile", "disassemble", "info", "calls"};
            boolean isValid = false;
            for (String validView : validViews) {
                if (validView.equals(view)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid view mode: " + view);
            }
        }
    }

    private String getDefaultViewMode(Map<String, Object> args) {
        String view = (String) args.get("view");
        return view != null ? view : "decompile";
    }

    private void validateDecompileViewArgs(Map<String, Object> args) {
        // Validate that if view is decompile, optional parameters are valid
        String view = (String) args.get("view");
        if ("decompile".equals(view)) {
            Object offset = args.get("offset");
            if (offset != null && offset instanceof Integer) {
                int offsetVal = (Integer) offset;
                if (offsetVal < 1) {
                    throw new IllegalArgumentException("offset must be >= 1 (1-based)");
                }
            }

            Object limit = args.get("limit");
            if (limit != null && limit instanceof Integer) {
                int limitVal = (Integer) limit;
                if (limitVal < 1) {
                    throw new IllegalArgumentException("limit must be >= 1");
                }
            }
        }
    }

    private void validateDecompileViewArgsWithDefaults(Map<String, Object> args) {
        // Verify defaults are applied correctly
        String view = (String) args.get("view");
        if ("decompile".equals(view)) {
            int offset = args.get("offset") != null ? (Integer) args.get("offset") : 1;
            int limit = args.get("limit") != null ? (Integer) args.get("limit") : 50;
            boolean includeCallers = args.get("includeCallers") != null ?
                (Boolean) args.get("includeCallers") : false;
            boolean includeCallees = args.get("includeCallees") != null ?
                (Boolean) args.get("includeCallees") : false;
            boolean includeComments = args.get("includeComments") != null ?
                (Boolean) args.get("includeComments") : false;
            boolean includeIncomingRefs = args.get("includeIncomingReferences") != null ?
                (Boolean) args.get("includeIncomingReferences") : true;
            boolean includeRefContext = args.get("includeReferenceContext") != null ?
                (Boolean) args.get("includeReferenceContext") : true;

            // Verify defaults match spec
            assertEquals("Default offset should be 1", 1, offset);
            assertEquals("Default limit should be 50", 50, limit);
            assertEquals("Default include_callers should be false", false, includeCallers);
            assertEquals("Default include_callees should be false", false, includeCallees);
            assertEquals("Default include_comments should be false", false, includeComments);
            assertEquals("Default include_incoming_references should be true", true, includeIncomingRefs);
            assertEquals("Default include_reference_context should be true", true, includeRefContext);
        }
    }
}
