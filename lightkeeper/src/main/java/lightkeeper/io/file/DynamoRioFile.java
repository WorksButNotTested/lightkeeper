package lightkeeper.io.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.IEventListener;
import lightkeeper.io.BinaryLineReader;
import lightkeeper.io.CountedByteProvider;
import lightkeeper.io.block.BlockEntry;
import lightkeeper.io.block.BlockReader;
import lightkeeper.io.module.ModuleEntry;
import lightkeeper.io.module.ModuleReader;

public class DynamoRioFile implements IEventListener {
	/**
	 * From version 3 of the file format, block offsets are relative to the start of
	 * the module table entry (segment) which contains them, rather than the base
	 * address of the whole module as they were in version 2. See
	 * DRCOV_VERSION_SEGMENT_OFFSETS in DynamoRIO's ext/drcovlib/drcovlib.h.
	 */
	protected static final int SEGMENT_OFFSET_VERSION = 3;

	protected final Pattern HEADER_REGEX = Pattern.compile("^DRCOV VERSION: (?<version>[23])$");
	protected final Pattern FLAVOUR_REGEX = Pattern.compile("^DRCOV FLAVOR: (?<flavour>.*)$");
	protected final Pattern TABLE_REGEX = Pattern
			.compile("^Module Table: (version (?<version>\\d+), count )?(?<count>\\d+)$");
	protected final Pattern BB_TABLE_REGEX = Pattern.compile("^BB Table: (?<blocks>\\d+) bbs$");

	protected CountedByteProvider provider;
	protected BinaryLineReader reader;
	protected File file;

	protected String flavour;
	protected int fileVersion;
	protected int tableVersion;
	protected int tableCount;
	protected ArrayList<ModuleEntry> modules = new ArrayList<>();
	protected long blockCount;
	protected ArrayList<BlockEntry> blocks = new ArrayList<>();
	private List<IEventListener> listeners = new ArrayList<>();

	public DynamoRioFile(File file) throws IOException {
		var stream = new FileInputStream(file);
		provider = new CountedByteProvider(stream, file.length());
		reader = new BinaryLineReader(provider);
		this.file = file;
	}

	public void read(TaskMonitor monitor) throws IOException, CancelledException {
		readHeader(monitor);
		readFlavour(monitor);
		readTable(monitor);
		readModules(monitor);
		readBbHeader(monitor);
		readBlocks(monitor);
	}

	public void addListener(IEventListener listener) {
		listeners.add(listener);
	}

	@Override
	public void addMessage(String message) {
		listeners.forEach(l -> l.addMessage(message));
	}

	@Override
	public void addErrorMessage(String message) {
		listeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		listeners.forEach(l -> l.addException(exc));
	}

	private void readHeader(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCancelled();
		monitor.setMessage("Reading header");
		var headerLine = reader.readLine();
		addMessage(headerLine);
		var headerMatcher = HEADER_REGEX.matcher(headerLine);
		if (!headerMatcher.matches()) {
			throw new IOException(String.format("Invalid header: '%s'", headerLine));
		}
		fileVersion = Integer.parseInt(headerMatcher.group("version"));
		addMessage(String.format("Detected file version: %d", fileVersion));
		monitor.checkCancelled();
	}

	private void readFlavour(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCancelled();
		monitor.setMessage("Reading flavour");
		var flavourLine = reader.readLine();
		addMessage(flavourLine);
		var flavourMatcher = FLAVOUR_REGEX.matcher(flavourLine);
		if (!flavourMatcher.matches()) {
			throw new IOException(String.format("Invalid flavour: '%s'", flavourLine));
		}
		flavour = flavourMatcher.group("flavour");
		addMessage(String.format("Detected flavour: %s", flavour));
		monitor.checkCancelled();
	}

	private void readTable(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCancelled();
		monitor.setMessage("Reading table");
		var tableLine = reader.readLine();
		addMessage(tableLine);
		var tableMatcher = TABLE_REGEX.matcher(tableLine);
		if (!tableMatcher.matches()) {
			throw new IOException(String.format("Invalid table header: '%s'", tableLine));
		}

		var version = tableMatcher.group("version");
		if (version == null) {
			tableVersion = 1;
		} else {
			tableVersion = Integer.parseInt(version);
		}

		addMessage(String.format("Detected table version: %d", tableVersion));

		var count = tableMatcher.group("count");
		tableCount = Integer.parseInt(count);
		addMessage(String.format("Detected table count: %d", tableCount));
		monitor.checkCancelled();
	}

	private void readModules(TaskMonitor monitor) throws CancelledException, IOException {
		var moduleReader = new ModuleReader(monitor, reader, tableVersion);
		moduleReader.addListener(this);
		for (var i = 0; i < tableCount; i++) {
			monitor.checkCancelled();
			monitor.setMessage(String.format("Reading module: %d", i));
			var module = moduleReader.read();
			modules.add(module);
		}
	}

	private void readBbHeader(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCancelled();
		monitor.setMessage("Reading BB header");
		var bbHeaderLine = reader.readLine();
		addMessage(bbHeaderLine);
		var bbHeaderMatcher = BB_TABLE_REGEX.matcher(bbHeaderLine);
		if (!bbHeaderMatcher.matches()) {
			throw new IOException(String.format("Invalid block header: '%s'", bbHeaderLine));
		}

		var blockString = bbHeaderMatcher.group("blocks");
		blockCount = Integer.parseInt(blockString);
		addMessage(String.format("Detected: %d blocks", blockCount));
		monitor.checkCancelled();
	}

	private void readBlocks(TaskMonitor monitor) throws CancelledException, IOException {
		var blockReader = new BlockReader(monitor, reader);
		blockReader.addListener(this);

		var containingStarts = getContainingStarts();
		var moduleLimits = getModuleLimits(containingStarts);
		var segmentOffsets = getSegmentOffsets(containingStarts);

		for (var i = 0; i < blockCount; i++) {
			monitor.checkCancelled();
			monitor.setMessage(String.format("Reading block: %d", i));
			var block = rebaseBlock(blockReader.read(), segmentOffsets);

			var moduleLimit = moduleLimits.get(block.getModule());
			if (moduleLimit == null) {
				throw new IOException(
						String.format("Block: %d references unknown module: %d", i, block.getModule()));
			}

			if (block.getEnd() > moduleLimit) {
				addMessage(String.format("Block offset: %x greater than module size: %d", block.getEnd(), moduleLimit));
			}
			blocks.add(block);
		}

		monitor.checkCancelled();

		if (provider.getLength() != provider.getPosition()) {
			throw new IOException(String.format("File has: %d unexpected trailing bytes at position: %d",
					provider.getLength() - provider.getPosition(), provider.getPosition()));
		}

		monitor.setMessage("File parsing complete");
		addMessage("File parsing complete");
	}

	public ArrayList<ModuleEntry> getModules() {
		return modules;
	}

	public ArrayList<BlockEntry> getBlocks() {
		return blocks;
	}

	/**
	 * Maps each module id to the base address of the module which contains it. A
	 * module which is split into multiple segments has a module table entry, and
	 * hence an id, per segment, each of which shares the containing_id of the first.
	 */
	protected HashMap<Integer, Long> getContainingStarts() {
		var starts = new HashMap<Integer, Long>();
		modules.forEach(m -> starts.put(m.getId(), m.getStart()));

		var containingStarts = new HashMap<Integer, Long>();
		for (ModuleEntry module : modules) {
			var containingStart = starts.get(module.getContainingId());
			if (containingStart == null) {
				addErrorMessage(String.format("Module: %d has unknown containing_id: %d, assuming it is not a segment",
						module.getId(), module.getContainingId()));
				containingStart = module.getStart();
			}
			containingStarts.put(module.getId(), containingStart);
		}
		return containingStarts;
	}

	/**
	 * Maps each module id to the offset of its segment from the base address of the
	 * containing module, which is zero for a module which has not been split into
	 * segments. Note that the offset column of the module table cannot be used for
	 * this, since for ELF modules it holds the offset of the segment within the file
	 * rather than within the loaded module.
	 */
	protected HashMap<Integer, Long> getSegmentOffsets(HashMap<Integer, Long> containingStarts) {
		var segmentOffsets = new HashMap<Integer, Long>();
		for (ModuleEntry module : modules) {
			segmentOffsets.put(module.getId(), module.getStart() - containingStarts.get(module.getId()));
		}
		return segmentOffsets;
	}

	/**
	 * Converts a block offset which is relative to the start of its segment into one
	 * relative to the base address of the containing module, so that blocks read
	 * from either version of the file format can be treated alike.
	 */
	protected BlockEntry rebaseBlock(BlockEntry block, HashMap<Integer, Long> segmentOffsets) {
		if (fileVersion < SEGMENT_OFFSET_VERSION) {
			return block;
		}

		var segmentOffset = segmentOffsets.get(block.getModule());
		if (segmentOffset == null || segmentOffset == 0) {
			return block;
		}

		return new BlockEntry(block.getStart() + segmentOffset, block.getSize(), block.getModule());
	}

	/**
	 * Maps each module id to the size of the module which contains it, for
	 * comparison against block offsets which have been rebased to that module.
	 */
	protected HashMap<Integer, Long> getModuleLimits(HashMap<Integer, Long> containingStarts) {
		var moduleLimits = new HashMap<Integer, Long>();
		for (ModuleEntry module : modules) {
			var containing_id = module.getContainingId();
			var selectedModules = modules.stream().filter(m -> m.getContainingId() == containing_id);
			Stream<Long> limits = selectedModules.map(ModuleEntry::getEnd);
			var maxLimit = limits.max(Long::compare).get();
			moduleLimits.put(module.getId(), maxLimit - containingStarts.get(module.getId()));
		}
		return moduleLimits;
	}

	public String getName() {
		return file.getName();
	}
}
