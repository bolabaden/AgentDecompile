/*
 * Copyright (c) 2025 AgentDecompile contributors.
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
package agentdecompile.headless;

import java.io.PrintStream;

/**
 * Redirects Java's System.out and System.err to a {@link StderrWriter} callback.
 * Used by the Python CLI so Java log output goes through Python's stderr (and
 * thus through the JSON-RPC log filter) without Python extending Java's OutputStream.
 */
public final class JavaOutputRedirect {

	private JavaOutputRedirect() {}

	/**
	 * Redirect System.out and System.err to the given writer. Both streams will
	 * use the same PrintStream backed by the writer.
	 *
	 * @param writer callback that receives all bytes (e.g. Python sys.stderr);
	 *               must not be null
	 */
	public static void redirectToWriter(StderrWriter writer) {
		PrintStream stream = new PrintStream(new CallbackOutputStream(writer), true);
		System.setOut(stream);
		System.setErr(stream);
	}
}
