package lightkeeper.model;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import docking.widgets.table.AbstractSortedTableModel;
import generic.stl.Pair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperEventListener;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.io.block.LightKeeperBlockEntry;
import lightkeeper.io.module.LightKeeperModuleEntry;

public class LightKeeperCoverageModel extends AbstractSortedTableModel<LightKeeperCoverageModelRow> implements LightKeeperEventListener {
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };

	protected LightKeeperPlugin plugin;
	protected ArrayList<LightKeeperCoverageModelRow> rows = new ArrayList<LightKeeperCoverageModelRow>();
	protected Set<AddressRange> hits = new HashSet<AddressRange>();
	
	private List<LightKeeperEventListener> listeners = new ArrayList<LightKeeperEventListener>();
	
	public void addListener(LightKeeperEventListener listener) {
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
	
	public LightKeeperCoverageModel(LightKeeperPlugin plugin) {
		super();
		this.plugin = plugin;
	}

	public void update(TaskMonitor monitor, LightKeeperFile file) throws CancelledException, IOException
	{
		monitor.checkCanceled();
		rows = new ArrayList<LightKeeperCoverageModelRow>();
		LightKeeperModuleEntry module = this.getModule(monitor, file);
		monitor.checkCanceled();
		
		this.processEntries(monitor, file, module);
		monitor.setMessage("Processing complete");
		this.addMessage("Processing complete");
		monitor.checkCanceled();
		
		fireTableDataChanged();
	}
	
	public LightKeeperModuleEntry getModule (TaskMonitor monitor, LightKeeperFile file) throws CancelledException, IOException {
		FlatProgramAPI api = this.plugin.getApi();
		File programFile = api.getProgramFile();
		String programFileName = programFile.getName();
		this.addMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		monitor.setMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		
		ArrayList<LightKeeperModuleEntry> modules = file.getModules();
		for (int i = 0; i < modules.size(); i++)
		{
			monitor.checkCanceled();
			LightKeeperModuleEntry module = modules.get(i);
			File f = new File(module.getPath());
			String fileName = f.getName();
			if (fileName.equals(programFileName))
			{
				return module;
			}
		}
		throw new IOException(String.format("Failed to find matching module entry for '%s'", programFileName));
	}
	
	public void processEntries(TaskMonitor monitor, LightKeeperFile file, LightKeeperModuleEntry module) throws CancelledException, IOException {
		FlatProgramAPI api = this.plugin.getApi();
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		this.addMessage(String.format("Base address: %x", baseAddress.getOffset()));
		HashMap<Function, Set<LightKeeperBlockEntry>> functions = new HashMap<Function, Set<LightKeeperBlockEntry>>();
		Set<LightKeeperBlockEntry> unassigned = new HashSet<LightKeeperBlockEntry>();
		
		ArrayList<LightKeeperBlockEntry> blocks = file.getBlocks();
		for (int i = 0; i < blocks.size(); i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing block %d / %d", i, blocks.size()));
			LightKeeperBlockEntry block = blocks.get(i);
			if (block.getModule() != module.getId())
				continue;
			
			if (block.getEnd() > module.getSize())
				throw new IOException(String.format("Block offset: %x greater than module size: %d", block.getEnd(), module.getSize()));
			
			Address addr = baseAddress.add(block.getStart());
			Function function = api.getFunctionContaining(addr);
			if (function == null) {
				this.addMessage(String.format("No function found at: %x", addr.getOffset()));
				unassigned.add(block);
			} else {
				this.addMessage(String.format("Found function: '%s' at: %x", function.getName(), addr.getOffset()));
				Set<LightKeeperBlockEntry> set = functions.get(function);
				if (set == null) {
					set = new HashSet<LightKeeperBlockEntry>();
					functions.put(function, set);
				}
				set.add(block);
			}
		}
		this.processFunctions(monitor, functions);
		this.processUnassigned(monitor, unassigned);
	}
	
	public void processFunctions(TaskMonitor monitor, HashMap<Function, Set<LightKeeperBlockEntry>> functions) throws CancelledException {
		
		Iterator<Function> functionIterator = functions.keySet().iterator();
		int i = 0;
		while (functionIterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			Function function = functionIterator.next();
			monitor.setMessage(String.format("Processing function (%s) %d / %d", function.getName(), i, functions.keySet().size()));
			this.addMessage(String.format("Processing function (%s) %d / %d", function.getName(), i, functions.keySet().size()));
			AddressSetView body = function.getBody();
			Set<LightKeeperBlockEntry> blocks = functions.get(function);
			
			Pair<Integer, Integer> codeBlockInfo = this.processCodeBlocks(monitor, function, blocks);
			Pair<Integer, Integer> instructionInfo = this.processInstructions(monitor, function, blocks);
			long functionSize = body.getMaxAddress().subtract(body.getMinAddress());
			
			LightKeeperCoverageModelRow row = new LightKeeperCoverageModelRow(function.getName(), body.getMinAddress().getOffset(), 
					codeBlockInfo.first, codeBlockInfo.second, instructionInfo.first, instructionInfo.second, functionSize);
			this.rows.add(row);
		}
	}
	
	public Pair<Integer, Integer> processCodeBlocks(TaskMonitor monitor, Function function, Set<LightKeeperBlockEntry> blocks) throws CancelledException {
		FlatProgramAPI api = this.plugin.getApi();
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		BasicBlockModel bbm = new BasicBlockModel(api.getCurrentProgram());
		AddressSetView body = function.getBody();
		CodeBlockIterator codeBlockIterator = bbm.getCodeBlocksContaining(body, monitor);
		int codeBlocks = 0;
		int hitCodeBlocks = 0;
		while (codeBlockIterator.hasNext()) {
			monitor.checkCanceled();
			codeBlocks++;
			
			monitor.setMessage(String.format("Processing function blocks (%s) %d", function.getName(), codeBlocks));
			this.addMessage(String.format("Processing function blocks (%s) %d", function.getName(), codeBlocks));
			
			CodeBlock cb = codeBlockIterator.next();
			long start = cb.getMinAddress().subtract(baseAddress);
			long end = cb.getMaxAddress().subtract(baseAddress);
			
			Iterator<LightKeeperBlockEntry> blockIterator = blocks.iterator();				
			while (blockIterator.hasNext()) {			
				monitor.checkCanceled();
				
				LightKeeperBlockEntry block = blockIterator.next();
				if (block.contains(start, end)) {
					hitCodeBlocks++;
					cb.getAddressRanges().forEach(r -> this.hits.add(r));
				}
			}
		}
		return new Pair<Integer, Integer>(Integer.valueOf(codeBlocks), Integer.valueOf(hitCodeBlocks));
	}
	
	public Pair<Integer, Integer> processInstructions(TaskMonitor monitor, Function function, Set<LightKeeperBlockEntry> blocks) throws CancelledException {
		FlatProgramAPI api = this.plugin.getApi();
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		Listing listing = api.getCurrentProgram().getListing();
		AddressSetView body = function.getBody();
		InstructionIterator instructionIterator = listing.getInstructions(body, true);
		int instructions = 0;
		int hitInstructions = 0;
		while (instructionIterator.hasNext()) {
			monitor.checkCanceled();
			instructions++;
			monitor.setMessage(String.format("Processing function instructions (%s) %d", function.getName(), instructions));
			this.addMessage(String.format("Processing function instructions (%s) %d", function.getName(), instructions));
			
			Instruction instruction = instructionIterator.next();
			Iterator<LightKeeperBlockEntry> blockIterator = blocks.iterator();
			while (blockIterator.hasNext()) {
				monitor.checkCanceled();
				LightKeeperBlockEntry block = blockIterator.next();
				long start = instruction.getMinAddress().subtract(baseAddress);
				long end = instruction.getMaxAddress().subtract(baseAddress);
				if (block.contains(start, end))
					hitInstructions++;
			}
		}
		return new Pair<Integer, Integer>(Integer.valueOf(instructions), Integer.valueOf(hitInstructions));
	}
	
	public void processUnassigned(TaskMonitor monitor, Set<LightKeeperBlockEntry> blocks) throws CancelledException {
		FlatProgramAPI api = this.plugin.getApi();
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		Iterator<LightKeeperBlockEntry> iterator = blocks.iterator();
		int i = 0;
		while (iterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing unassigned block %d / %d", i, blocks.size()));
			this.addMessage(String.format("Processing unassigned block %d / %d", i, blocks.size()));
			LightKeeperBlockEntry block = iterator.next();
			Address addr = baseAddress.add(block.getStart());
			String name = String.format("_unknown_%x", addr.getOffset());
			LightKeeperCoverageModelRow row = new LightKeeperCoverageModelRow(name, addr.getOffset(), 0, 0, 0, 0, 0);
			this.rows.add(row);
		}
	}
	
	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public int getColumnCount() { 
		return columnNames.length;
	}
	
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public String getName() {
		return "Coverage Data";
	}

	@Override
	public List<LightKeeperCoverageModelRow> getModelData() {
		return this.rows;
	}

	@Override
	public Object getColumnValueForRow(LightKeeperCoverageModelRow row, int columnIndex) {
		switch(columnIndex) {
			case 0:
				return String.format("%.2f", row.getCoverage());
			case 1:
				return row.getName();
			case 2:
				return String.format("%x", row.getAddress());
			case 3:
				return row.getBlocks();
			case 4:
				return row.getInstructions();
			case 5:
				return row.getFunctionSize();
			default:
				throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
	}
	
	public Set<AddressRange> getHits() {
		return this.hits;
	}

}
