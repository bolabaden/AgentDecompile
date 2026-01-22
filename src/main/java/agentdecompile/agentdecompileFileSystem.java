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

import java.io.IOException;
import java.util.Comparator;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "fstypegoeshere", // ([a-z0-9]+ only)
		description = "File system description goes here", factory = agentdecompileFileSystem.MyFileSystemFactory.class)
public class agentdecompileFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<MyMetadata> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public agentdecompileFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + agentdecompileFileSystem.class.getSimpleName() + "...");

		// Customize how things in the file system are stored.  The following should be 
		// treated as pseudo-code.
		for (MyMetadata metadata : new MyMetadata[10]) {
			if (monitor.isCancelled()) {
				break;
			}
			fsih.storeFile(metadata.path, fsih.getFileCount(), false, metadata.size, metadata);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public GFile lookup(String path, Comparator<String> nameComp) throws IOException {
		return fsih.lookup(null, path, nameComp);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// Get an ByteProvider for a file.  The following is an example of how the metadata
		// might be used to get an sub-ByteProvider from a stored provider offset.
		MyMetadata metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		MyMetadata metadata = fsih.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			result.add(FileAttributeType.NAME_ATTR, metadata.name);
			result.add(FileAttributeType.SIZE_ATTR, metadata.size);
		}
		return result;
	}

	// Customize for the real file system.
	public static class MyFileSystemFactory
			implements GFileSystemFactoryByteProvider<agentdecompileFileSystem>,
			GFileSystemProbeByteProvider {

		@Override
		public agentdecompileFileSystem create(FSRLRoot targetFSRL,
				ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			agentdecompileFileSystem fs = new agentdecompileFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			// Quickly and efficiently examine the bytes in 'byteProvider' to determine if 
			// it's a valid file system.  If it is, return true. 

			return false;
		}
	}

	// Customize with metadata from files in the real file system.  This is just a stub.
	// The elements of the file system will most likely be modeled by Java classes external to this
	// file.
	private static class MyMetadata {
		private String name;
		private String path;
		private long offset;
		private long size;
	}
}
