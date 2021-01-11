package lightkeeper.model;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

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

public class LightKeeperCoverageModelBuilder implements LightKeeperEventListener {
	protected LightKeeperPlugin plugin;
	protected FlatProgramAPI api;
	protected TaskMonitor monitor;
	protected LightKeeperFile file;
	
	protected LightKeeperModuleEntry module;
	protected HashMap<Function, Set<LightKeeperBlockEntry>> functions = new HashMap<Function, Set<LightKeeperBlockEntry>>();
	protected Set<LightKeeperBlockEntry> unassigned = new HashSet<LightKeeperBlockEntry>();
	
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
	
	
	public LightKeeperCoverageModelBuilder(LightKeeperPlugin plugin) {
		this.plugin = plugin;		
	}
	
	public void build(TaskMonitor taskMonitor, LightKeeperFile lightKeeperFile) throws CancelledException, IOException
	{
		this.api = plugin.getApi();
		this.monitor = taskMonitor;
		this.file = lightKeeperFile;
		
		monitor.checkCanceled();		
		this.module = this.getModule();
		monitor.checkCanceled();
		
		this.processEntries();
		this.processFunctions();
		this.processUnassigned();
		monitor.setMessage("Processing complete");
		this.addMessage("Processing complete");
		monitor.checkCanceled();		
	}
	
	public LightKeeperModuleEntry getModule () throws CancelledException, IOException {		
		File programFile = api.getProgramFile();
		String programFileName = programFile.getName();
		this.addMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		monitor.setMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		
		ArrayList<LightKeeperModuleEntry> modules = file.getModules();
		for (int i = 0; i < modules.size(); i++)
		{
			monitor.checkCanceled();
			LightKeeperModuleEntry currentModule = modules.get(i);
			File f = new File(currentModule.getPath());
			String fileName = f.getName();
			if (fileName.equals(programFileName))
			{
				return currentModule;
			}
		}
		throw new IOException(String.format("Failed to find matching module entry for '%s'", programFileName));
	}
	
	public void processEntries() throws CancelledException, IOException {		
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		this.addMessage(String.format("Base address: %x", baseAddress.getOffset()));
		
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
	}
	
	public void processFunctions() throws CancelledException {
		
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
			
			LightKeeperFraction codeBlockInfo = this.processCodeBlocks(function, blocks);
			LightKeeperFraction instructionInfo = this.processInstructions(function, blocks);
			long functionSize = body.getMaxAddress().subtract(body.getMinAddress());
			
			LightKeeperCoverageModelRow row = new LightKeeperCoverageModelRow(function.getName(), body.getMinAddress().getOffset(), 
					codeBlockInfo, instructionInfo, functionSize);
			this.rows.add(row);
		}
	}
	
	public LightKeeperFraction processCodeBlocks(Function function, Set<LightKeeperBlockEntry> blocks) throws CancelledException {		
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
		return new LightKeeperFraction(hitCodeBlocks, codeBlocks);
	}
	
	public LightKeeperFraction processInstructions(Function function, Set<LightKeeperBlockEntry> blocks) throws CancelledException {		
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
		return new LightKeeperFraction(hitInstructions, instructions);
	}
	
	public void processUnassigned() throws CancelledException {		
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		Iterator<LightKeeperBlockEntry> iterator = unassigned.iterator();
		int i = 0;
		while (iterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			this.addMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			LightKeeperBlockEntry block = iterator.next();
			Address addr = baseAddress.add(block.getStart());
			String name = String.format("_unknown_%x", addr.getOffset());
			LightKeeperFraction zeroFraction = new LightKeeperFraction(0, 0);
			LightKeeperCoverageModelRow row = new LightKeeperCoverageModelRow(name, addr.getOffset(), zeroFraction, zeroFraction, 0);
			this.rows.add(row);
		}
	}
	
	public ArrayList<LightKeeperCoverageModelRow> getRows() {
		return this.rows;
	}
	
	public Set<AddressRange> getHits() {
		return this.hits;
	}
}
