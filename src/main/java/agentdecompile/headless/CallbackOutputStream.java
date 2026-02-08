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

import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream that delegates to a {@link StderrWriter} callback.
 * Used so Java System.out/err can be redirected to a Python-provided writer
 * without Python extending OutputStream.
 */
public final class CallbackOutputStream extends OutputStream {

	private final StderrWriter writer;

	/**
	 * @param writer callback to receive written bytes (must not be null)
	 */
	public CallbackOutputStream(StderrWriter writer) {
		if (writer == null) {
			throw new IllegalArgumentException("writer must not be null");
		}
		this.writer = writer;
	}

	@Override
	public void write(int b) throws IOException {
		writer.write(new byte[] { (byte) b }, 0, 1);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (b == null) {
			throw new NullPointerException();
		}
		if (off < 0 || len < 0 || off + len > b.length) {
			throw new IndexOutOfBoundsException();
		}
		if (len == 0) {
			return;
		}
		writer.write(b, off, len);
	}
}
