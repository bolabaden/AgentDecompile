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
package agentdecompile;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.program.model.listing.Program;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

import org.junit.After;
import org.junit.Before;

/**
 * Base class for AgentDecompile headless integration tests that don't require a GUI tool.
 * This is a simpler alternative that just tests with programs directly.
 */
public abstract class AgentDecompileHeadlessIntegrationTestBase extends AbstractGhidraHeadlessIntegrationTest {

    protected Program program;

    @Before
    public void setUp() throws Exception {
        // Create a test program
        program = createDefaultProgram();
    }

    @After
    public void tearDown() throws Exception {
        if (program != null && program instanceof ProgramDB) {
            ((ProgramDB) program).release(this);
        }
        program = null;
    }

    /**
     * Creates a default program for testing.
     * Subclasses can override this to customize the test program.
     *
     * @return A new Program instance
     * @throws Exception if program creation fails
     */
    protected Program createDefaultProgram() throws Exception {
        Language language = getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
        ProgramDB testProgram = new ProgramDB("TestProgram", language, compilerSpec, this);

        // Add a memory block
        Memory memory = testProgram.getMemory();
        int txId = testProgram.startTransaction("Create Memory");
        try {
            memory.createInitializedBlock("test",
                testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                0x1000, (byte) 0, TaskMonitor.DUMMY, false);
        } finally {
            testProgram.endTransaction(txId, true);
        }

        return testProgram;
    }
}