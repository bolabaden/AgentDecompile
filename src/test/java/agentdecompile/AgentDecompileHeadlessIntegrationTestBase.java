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