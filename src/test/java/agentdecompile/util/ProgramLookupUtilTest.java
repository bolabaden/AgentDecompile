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
}
