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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra exporter implementation (template/skeleton).
 * <p>
 * Ghidra API: {@link ghidra.app.util.exporter.Exporter}, {@link ghidra.framework.model.DomainObject} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/Exporter.html">Exporter API</a>.
 * See <a href="https://ghidra.re/ghidra_docs/api/">Ghidra API Overview</a>.
 * </p>
 */
public class agentdecompileExporter extends Exporter {

	/**
	 * Exporter constructor.
	 */
	public agentdecompileExporter() {

		// Name the exporter and associate a file extension with it

		super("My Exporter", "exp", null);
	}

	@Override
	public boolean supportsAddressRestrictedExport() {

		// Return true if addrSet export parameter can be used to restrict export

		return false;
	}

	@Override
	// Ghidra API: Exporter.export(File, DomainObject, AddressSetView, TaskMonitor) - https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/Exporter.html#export(java.io.File,ghidra.framework.model.DomainObject,ghidra.program.model.address.AddressSetView,ghidra.util.task.TaskMonitor)
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException {


		return false;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> list = new ArrayList<>();

		// If this exporter has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {

		// If this exporter has custom options, assign their values to the exporter here
	}
}
