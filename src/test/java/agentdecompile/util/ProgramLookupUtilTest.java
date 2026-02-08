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

import static org.junit.Assert.*;

import java.lang.reflect.Method;

import org.junit.Test;

/**
 * Test class for ProgramLookupUtil utility methods.
 * Tests the path normalization and matching logic used to resolve "program not found" errors.
 */
public class ProgramLookupUtilTest {

    /**
     * Test pathsMatch with exact matching paths
     */
    @Test
    public void testPathsMatch_ExactMatch() throws Exception {
        assertTrue(invokePathsMatch("/k1_win_gog_swkotor.exe", "/k1_win_gog_swkotor.exe"));
    }

    /**
     * Test pathsMatch with case-insensitive matching
     */
    @Test
    public void testPathsMatch_CaseInsensitive() throws Exception {
        assertTrue(invokePathsMatch("/K1_Win_GOG_SWKOTOR.exe", "/k1_win_gog_swkotor.exe"));
        assertTrue(invokePathsMatch("/k1_win_gog_swkotor.exe", "/K1_WIN_GOG_SWKOTOR.EXE"));
    }

    /**
     * Test pathsMatch with leading/trailing whitespace
     */
    @Test
    public void testPathsMatch_Whitespace() throws Exception {
        assertTrue(invokePathsMatch("  /program.exe  ", "/program.exe"));
        assertTrue(invokePathsMatch("/program.exe", "  /program.exe  "));
    }

    /**
     * Test pathsMatch with filename matching (full path vs filename only)
     */
    @Test
    public void testPathsMatch_FilenameMatching() throws Exception {
        assertTrue(invokePathsMatch("program.exe", "/folder/program.exe"));
        assertTrue(invokePathsMatch("/folder/program.exe", "program.exe"));
    }

    /**
     * Test pathsMatch with different paths (no match expected)
     */
    @Test
    public void testPathsMatch_NoMatch() throws Exception {
        assertFalse(invokePathsMatch("/different.exe", "/program.exe"));
        assertFalse(invokePathsMatch("/folder1/program.exe", "/folder2/other.exe"));
    }

    /**
     * Test pathsMatch with null inputs
     */
    @Test
    public void testPathsMatch_NullInputs() throws Exception {
        assertFalse(invokePathsMatch(null, "/program.exe"));
        assertFalse(invokePathsMatch("/program.exe", null));
        assertFalse(invokePathsMatch(null, null));
    }

    /**
     * Test pathsMatch with trailing slashes
     */
    @Test
    public void testPathsMatch_TrailingSlash() throws Exception {
        assertTrue(invokePathsMatch("/program.exe/", "/program.exe"));
        assertTrue(invokePathsMatch("/program.exe", "/program.exe/"));
    }

    /**
     * Test pathsMatch with Windows backslash paths
     */
    @Test
    public void testPathsMatch_WindowsBackslash() throws Exception {
        // Trailing backslash should be handled
        assertTrue(invokePathsMatch("C:\\program.exe\\", "C:\\program.exe"));
        assertTrue(invokePathsMatch("C:\\program.exe", "C:\\program.exe\\"));
    }

    /**
     * Test normalizePath with various inputs
     */
    @Test
    public void testNormalizePath() throws Exception {
        assertEquals("/program.exe", invokeNormalizePath("  /program.exe  "));
        assertEquals("/program.exe", invokeNormalizePath("/program.exe/"));
        assertEquals("/program.exe", invokeNormalizePath("/program.exe"));
        assertEquals("", invokeNormalizePath(null));
    }

    /**
     * Test normalizePath with Windows backslash paths
     */
    @Test
    public void testNormalizePath_WindowsBackslash() throws Exception {
        assertEquals("C:\\program.exe", invokeNormalizePath("C:\\program.exe\\"));
        assertEquals("C:\\folder\\program.exe", invokeNormalizePath("  C:\\folder\\program.exe\\  "));
    }

    /**
     * Test getFileName with various paths
     */
    @Test
    public void testGetFileName() throws Exception {
        assertEquals("program.exe", invokeGetFileName("/folder/program.exe"));
        assertEquals("program.exe", invokeGetFileName("program.exe"));
        assertEquals("file.txt", invokeGetFileName("/a/b/c/file.txt"));
        assertEquals("", invokeGetFileName("/"));
    }

    /**
     * Helper method to invoke the private pathsMatch method via reflection
     */
    private boolean invokePathsMatch(String path1, String path2) throws Exception {
        Method method = ProgramLookupUtil.class.getDeclaredMethod("pathsMatch", String.class, String.class);
        method.setAccessible(true);
        return (Boolean) method.invoke(null, path1, path2);
    }

    /**
     * Helper method to invoke the private normalizePath method via reflection
     */
    private String invokeNormalizePath(String path) throws Exception {
        Method method = ProgramLookupUtil.class.getDeclaredMethod("normalizePath", String.class);
        method.setAccessible(true);
        return (String) method.invoke(null, path);
    }

    /**
     * Helper method to invoke the private getFileName method via reflection
     */
    private String invokeGetFileName(String path) throws Exception {
        Method method = ProgramLookupUtil.class.getDeclaredMethod("getFileName", String.class);
        method.setAccessible(true);
        return (String) method.invoke(null, path);
    }

    /**
     * Test buildErrorMessageWithSuggestions to verify exact-match paths are filtered from suggestions.
     * This tests FIX 2: avoiding "not found X, did you mean X?" messages.
     */
    @Test
    public void testBuildErrorMessageWithSuggestions_FiltersExactMatches() throws Exception {
        java.util.List<String> availablePrograms = java.util.Arrays.asList(
            "/k1_win_gog_swkotor.exe",
            "/other_program.exe"
        );
        
        // When requesting with matching filename, it should not suggest the same name
        String errorMessage = invokeBuildErrorMessageWithSuggestions("k1_win_gog_swkotor.exe", availablePrograms);
        
        // Should NOT contain "Did you mean one of these?" followed by the exact same name
        // Instead, it should list "Available programs:" since the match is filtered out
        assertFalse("Should not suggest the same program that was requested", 
            errorMessage.contains("Did you mean") && errorMessage.contains("k1_win_gog_swkotor.exe"));
    }

    /**
     * Test buildErrorMessageWithSuggestions shows "Available programs" when no similar programs found.
     */
    @Test
    public void testBuildErrorMessageWithSuggestions_ShowsAvailablePrograms() throws Exception {
        java.util.List<String> availablePrograms = java.util.Arrays.asList(
            "/program1.exe",
            "/program2.exe"
        );
        
        // When requesting a completely different name, should show available programs
        String errorMessage = invokeBuildErrorMessageWithSuggestions("/completely_different.exe", availablePrograms);
        
        // Should contain available programs section
        assertTrue("Should show available programs", errorMessage.contains("Available programs:"));
    }

    /**
     * Test pathsMatch ensures exact program name matches even with path differences.
     * This is critical for FIX 2.
     */
    @Test
    public void testPathsMatch_SameFilenameInDifferentFolders() throws Exception {
        // Same filename in different folders should match (for user convenience)
        assertTrue(invokePathsMatch("/folder1/program.exe", "/folder2/program.exe"));
        assertTrue(invokePathsMatch("program.exe", "/deeply/nested/path/program.exe"));
    }

    /**
     * Test pathsMatch with leading slash differences.
     * Programs may be requested as "program.exe" or "/program.exe".
     */
    @Test
    public void testPathsMatch_LeadingSlashDifferences() throws Exception {
        // With leading slash in stored path but not in request
        assertTrue(invokePathsMatch("program.exe", "/program.exe"));
        // Without leading slash in stored path but with in request  
        assertTrue(invokePathsMatch("/program.exe", "program.exe"));
    }

    /**
     * Helper method to invoke the private buildErrorMessageWithSuggestions method via reflection
     */
    @SuppressWarnings("unchecked")
    private String invokeBuildErrorMessageWithSuggestions(String requestedPath, java.util.List<String> availableProgramPaths) throws Exception {
        Method method = ProgramLookupUtil.class.getDeclaredMethod("buildErrorMessageWithSuggestions", 
            String.class, java.util.List.class);
        method.setAccessible(true);
        return (String) method.invoke(null, requestedPath, availableProgramPaths);
    }
}
