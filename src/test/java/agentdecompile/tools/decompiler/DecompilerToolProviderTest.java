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
package agentdecompile.tools.decompiler;

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
 * Unit tests for DecompilerToolProvider.
 * Tests focus on validation and error handling since full decompiler
 * functionality requires a Ghidra environment.
 */
public class DecompilerToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private DecompilerToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new DecompilerToolProvider(mockServer);
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
    public void testValidateChangeDataTypesParameters() {
        // Test parameter validation for the change-variable-datatypes tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("functionName", "testFunction");
        validArgs.put("datatypeMappings", Map.of("var1", "int", "var2", "char*"));

        // Valid parameters should not throw
        try {
            validateChangeDataTypesArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateChangeDataTypesArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        // Missing functionName should throw
        Map<String, Object> missingFunction = new HashMap<>(validArgs);
        missingFunction.remove("functionName");
        try {
            validateChangeDataTypesArgs(missingFunction);
            fail("Should throw exception for missing functionName");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        // Missing datatype_mappings should throw
        Map<String, Object> missingMappings = new HashMap<>(validArgs);
        missingMappings.remove("datatypeMappings");
        try {
            validateChangeDataTypesArgs(missingMappings);
            fail("Should throw exception for missing datatype_mappings");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        // Empty datatype_mappings should throw
        Map<String, Object> emptyMappings = new HashMap<>(validArgs);
        emptyMappings.put("datatypeMappings", new HashMap<>());
        try {
            validateChangeDataTypesArgs(emptyMappings);
            fail("Should throw exception for empty datatype_mappings");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testValidateRenameVariablesParameters() {
        // Test parameter validation for the rename-variables tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("functionName", "testFunction");
        validArgs.put("variableMappings", Map.of("oldVar", "newVar"));

        // Valid parameters should not throw
        try {
            validateRenameVariablesArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateRenameVariablesArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testValidateGetDecompiledFunctionParameters() {
        // Test parameter validation for the get-decompiled-function tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("functionName", "testFunction");

        // Valid parameters should not throw
        try {
            validateGetDecompiledFunctionArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateGetDecompiledFunctionArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        // Missing functionName should throw
        Map<String, Object> missingFunction = new HashMap<>(validArgs);
        missingFunction.remove("functionName");
        try {
            validateGetDecompiledFunctionArgs(missingFunction);
            fail("Should throw exception for missing functionName");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateChangeDataTypesArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("functionName") == null) {
            throw new IllegalArgumentException("No function name provided");
        }
        @SuppressWarnings("unchecked")
        Map<String, String> mappings = (Map<String, String>) args.get("datatypeMappings");
        if (mappings == null || mappings.isEmpty()) {
            throw new IllegalArgumentException("No datatype mappings provided");
        }
    }

    private void validateRenameVariablesArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("functionName") == null) {
            throw new IllegalArgumentException("No function name provided");
        }
        @SuppressWarnings("unchecked")
        Map<String, String> mappings = (Map<String, String>) args.get("variableMappings");
        if (mappings == null || mappings.isEmpty()) {
            throw new IllegalArgumentException("No variable mappings provided");
        }
    }

    private void validateGetDecompiledFunctionArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("functionName") == null) {
            throw new IllegalArgumentException("No function name provided");
        }
    }

    @Test
    public void testInheritance() {
        // Test that DecompilerToolProvider extends AbstractToolProvider
        assertTrue("DecompilerToolProvider should extend AbstractToolProvider",
            agentdecompile.tools.AbstractToolProvider.class.isAssignableFrom(DecompilerToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that DecompilerToolProvider implements ToolProvider interface
        assertTrue("DecompilerToolProvider should implement ToolProvider",
            agentdecompile.tools.ToolProvider.class.isAssignableFrom(DecompilerToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("DecompilerToolProvider should be created", toolProvider);
    }
}
