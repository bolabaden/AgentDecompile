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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra analyzer implementation (template/skeleton).
 * <p>
 * Ghidra API: {@link ghidra.app.services.AbstractAnalyzer}, {@link ghidra.program.model.listing.Program} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html">AbstractAnalyzer API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class agentdecompileAnalyzer extends AbstractAnalyzer {

	public agentdecompileAnalyzer() {

		// Name the analyzer and give it a description.

		super("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	// Ghidra API: AbstractAnalyzer.getDefaultEnablement(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html#getDefaultEnablement(ghidra.program.model.listing.Program)
	public boolean getDefaultEnablement(Program program) {

		return true;
	}

	@Override
	// Ghidra API: AbstractAnalyzer.canAnalyze(Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html#canAnalyze(ghidra.program.model.listing.Program)
	public boolean canAnalyze(Program program) {

		return true;
	}

	@Override
	// Ghidra API: AbstractAnalyzer.registerOptions(Options, Program) - https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html#registerOptions(ghidra.framework.options.Options,ghidra.program.model.listing.Program)
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	// Ghidra API: AbstractAnalyzer.added(Program, AddressSetView, TaskMonitor, MessageLog) - https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html#added(ghidra.program.model.listing.Program,ghidra.program.model.address.AddressSetView,ghidra.util.task.TaskMonitor,ghidra.app.util.importer.MessageLog)
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		return false;
	}
}
