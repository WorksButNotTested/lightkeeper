package lightkeeper.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.EventListener;
import lightkeeper.io.block.BlockEntry;
import lightkeeper.io.block.BlockReader;
import lightkeeper.io.module.ModuleEntry;
import lightkeeper.io.module.ModuleReader;

public class DynamoRioFile implements EventListener {		
	protected final String HEADER = "DRCOV VERSION: 2";
	protected final Pattern FLAVOUR_REGEX = Pattern.compile("^DRCOV FLAVOR: (?<flavour>.*)$");
	protected final Pattern TABLE_REGEX = Pattern.compile("^Module Table: (version (?<version>\\d+), count )?(?<count>\\d+)$");
	protected final Pattern BB_TABLE_REGEX = Pattern.compile("^BB Table: (?<blocks>\\d+) bbs$");
			
	protected CountedByteProvider provider;
	protected BinaryLineReader reader;	

	protected String flavour;
	protected int tableVersion;
	protected int tableCount;
	protected ArrayList<ModuleEntry> modules = new ArrayList<ModuleEntry>();
	protected long blockCount;
	protected ArrayList<BlockEntry> blocks = new ArrayList<BlockEntry>();
	private List<EventListener> listeners = new ArrayList<EventListener>();
	
	public DynamoRioFile (File file) throws IOException {		
		FileInputStream stream = new FileInputStream(file);
		this.provider = new CountedByteProvider(stream, file.length());
		this.reader = new BinaryLineReader(provider);			
	}
	
	public void read(TaskMonitor monitor) throws IOException, CancelledException {
		this.readHeader(monitor);
		this.readFlavour(monitor);
		this.readTable(monitor);		
		this.readModules(monitor);
		this.readBbHeader(monitor);
		this.readBlocks(monitor);
	}
	
	public void addListener(EventListener listener) {
		this.listeners.add(listener);
	}
	
	@Override
	public void addMessage(String message) {
		this.listeners.forEach(l -> l.addMessage(message));
	}
	
	@Override
	public void addErrorMessage(String message) {
		this.listeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		this.listeners.forEach(l -> l.addException(exc));		
	}
	
	private void readHeader(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCanceled();
		monitor.setMessage("Reading header");
		String headerLine = this.reader.readLine();
		this.addMessage(headerLine);		
		if (!headerLine.equals(HEADER))		
			throw new IOException(String.format("Invalid header: '%s' expected '%s'", headerLine, HEADER));			
		monitor.checkCanceled();
	}
	
	private void readFlavour(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCanceled();
		monitor.setMessage("Reading flavour");
		String flavourLine = this.reader.readLine();
		this.addMessage(flavourLine);
		Matcher flavourMatcher = FLAVOUR_REGEX.matcher(flavourLine);
		if (!flavourMatcher.matches())
			throw new IOException(String.format("Invalid flavour: '%s'", flavourLine));
		this.flavour = flavourMatcher.group("flavour");
		this.addMessage(String.format("Detected flavour: %s", this.flavour));
		monitor.checkCanceled();
	}
	
	private void readTable(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCanceled();
		monitor.setMessage("Reading table");
		String tableLine = reader.readLine();
		this.addMessage(tableLine);
		Matcher tableMatcher = TABLE_REGEX.matcher(tableLine);
		if (!tableMatcher.matches())
			throw new IOException(String.format("Invalid table header: '%s'", tableLine));
		
		String version = tableMatcher.group("version");
		if (version == null)
			this.tableVersion = 1;
		else
			this.tableVersion = Integer.parseInt(version);
		
		this.addMessage(String.format("Detected table version: %d", this.tableVersion));
			
		String count = tableMatcher.group("count");
		this.tableCount = Integer.parseInt(count);
		this.addMessage(String.format("Detected table count: %d", this.tableCount));		
		monitor.checkCanceled();
	}
	
	private void readModules(TaskMonitor monitor) throws CancelledException, IOException {
		ModuleReader moduleReader = new ModuleReader(monitor, this.reader, this.tableVersion);
		moduleReader.addListener(this);
		for (int i = 0; i < tableCount; i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Reading module: %d", i));
			ModuleEntry module = moduleReader.read();
			modules.add(module);
		}
	}
	
	private void readBbHeader(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.checkCanceled();
		monitor.setMessage("Reading BB header");
		String bbHeaderLine = this.reader.readLine();
		this.addMessage(bbHeaderLine);
		Matcher bbHeaderMatcher = BB_TABLE_REGEX.matcher(bbHeaderLine);
		if (!bbHeaderMatcher.matches())
			throw new IOException(String.format("Invalid block header: '%s'", bbHeaderLine));
		
		String blockString = bbHeaderMatcher.group("blocks");
		this.blockCount = Integer.parseInt(blockString);		
		this.addMessage(String.format("Detected: %d blocks", this.blockCount));
		monitor.checkCanceled();
	}
	
	private void readBlocks(TaskMonitor monitor) throws CancelledException, IOException {
		BlockReader blockReader = new BlockReader(monitor, this.reader);
		blockReader.addListener(this);
		
		HashMap<Integer, Long> moduleLimits = this.getModuleLimits();
		
		for (int i = 0; i < this.blockCount; i++) {
			monitor.checkCanceled();
			monitor.setMessage(String.format("Reading block: %d", i));
			BlockEntry block = blockReader.read();
			long moduleLimit = moduleLimits.get(block.getModule());
			if (block.getEnd() > moduleLimit) {
				throw new IOException(String.format("Block offset: %x greater than module size: %d", block.getEnd(), moduleLimit));
			}
			blocks.add(block);
		}
		
		monitor.checkCanceled();
		
		if (this.provider.getLength() != this.provider.getPosition())
			throw new IOException(String.format("File has: %d unexpected trailing bytes at position: %d", this.provider.getLength() - this.provider.getPosition(), this.provider.getPosition()));
		
		monitor.setMessage("File parsing complete");
		this.addMessage("File parsing complete");
	}
	
	public ArrayList<ModuleEntry> getModules() {
		return this.modules;
	}
	
	public ArrayList<BlockEntry> getBlocks() {
		return this.blocks;
	}
	
	protected HashMap<Integer, Long> getModuleLimits() {
		HashMap<Integer, Long> moduleLimits = new HashMap<Integer, Long>();
		for (ModuleEntry module: this.modules) {
			int containing_id = module.getContainingId();
			Stream<ModuleEntry> selectedModules = this.modules.stream()
				.filter(m -> m.getContainingId() == containing_id);
			Stream<Long> limits = selectedModules.map(m -> m.getEnd());
			Long maxLimit = limits.max(Long::compare).get();
			moduleLimits.put(module.getId(), maxLimit);
		}
		return moduleLimits;
	}
}