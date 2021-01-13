package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
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
import lightkeeper.model.LightKeeperCoverageRangeCollection;

public class LightKeeperCoverageTableModelBuilder implements LightKeeperEventListener {
	protected LightKeeperPlugin plugin;
	protected FlatProgramAPI api;
	protected TaskMonitor monitor;
	protected LightKeeperCoverageRangeCollection modelRanges;
	
	protected HashMap<Function, Set<AddressRange>> functions = new HashMap<Function, Set<AddressRange>>();
	protected Set<AddressRange> unassigned = new HashSet<AddressRange>();
	
	protected ArrayList<LightKeeperCoverageTableModelRow> rows = new ArrayList<LightKeeperCoverageTableModelRow>();
	
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
	
	
	public LightKeeperCoverageTableModelBuilder(LightKeeperPlugin plugin) {
		this.plugin = plugin;		
	}
	
	public void build(TaskMonitor taskMonitor, LightKeeperCoverageRangeCollection ranges) throws CancelledException
	{
		this.api = plugin.getApi();
		this.monitor = taskMonitor;
		this.modelRanges = ranges;
		monitor.checkCanceled();
		
		this.processEntries();
		this.processFunctions();
		this.processUnassigned();
		monitor.setMessage("Processing complete");
		this.addMessage("Processing complete");
		monitor.checkCanceled();		
	}
	
	public void processEntries() throws CancelledException {
		ArrayList<AddressRange> ranges = modelRanges.getRanges();
		for (int i = 0; i < ranges.size(); i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing block %d / %d", i, ranges.size()));
			AddressRange range = ranges.get(i);
			
			Function function = api.getFunctionContaining(range.getMinAddress());
			if (function == null) {
				this.addMessage(String.format("No function found at: %x", range.getMinAddress().getOffset()));
				unassigned.add(range);
			} else {
				this.addMessage(String.format("Found function: '%s' at: %x", function.getName(), range.getMinAddress().getOffset()));
				Set<AddressRange> set = functions.get(function);
				if (set == null) {
					set = new HashSet<AddressRange>();
					functions.put(function, set);
				}
				set.add(range);
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
			Set<AddressRange> ranges = functions.get(function);
			
			LightKeeperFraction codeBlockInfo = this.processCodeBlocks(function, ranges);
			LightKeeperFraction instructionInfo = this.processInstructions(function, ranges);
			long functionSize = body.getMaxAddress().subtract(body.getMinAddress());
			
			LightKeeperCoverageTableModelRow row = new LightKeeperCoverageTableModelRow(function.getName(), body.getMinAddress().getOffset(), 
					codeBlockInfo, instructionInfo, functionSize);
			this.rows.add(row);
		}
	}
	
	public LightKeeperFraction processCodeBlocks(Function function, Set<AddressRange> ranges) throws CancelledException {		
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
			
			Iterator<AddressRange> rangeIterator = ranges.iterator();				
			while (rangeIterator.hasNext()) {			
				monitor.checkCanceled();
				
				AddressRange range = rangeIterator.next();
				if (range.getMinAddress().compareTo(cb.getMinAddress()) < 0)
					continue;
				
				if (range.getMaxAddress().compareTo(cb.getMaxAddress()) > 0)
					continue;
				
				hitCodeBlocks++;								
			}
		}
		return new LightKeeperFraction(hitCodeBlocks, codeBlocks);
	}
	
	public LightKeeperFraction processInstructions(Function function, Set<AddressRange> ranges) throws CancelledException {		
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
			Iterator<AddressRange> rangeIterator = ranges.iterator();
			while (rangeIterator.hasNext()) {
				monitor.checkCanceled();
				AddressRange range = rangeIterator.next();
				
				if (instruction.getMinAddress().compareTo(range.getMinAddress()) < 0)
					continue;
				
				if (instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0)
					continue;
				
				
				hitInstructions++;										
			}
		}
		return new LightKeeperFraction(hitInstructions, instructions);
	}
	
	public void processUnassigned() throws CancelledException {		
		Iterator<AddressRange> iterator = unassigned.iterator();
		int i = 0;
		while (iterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			this.addMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			AddressRange range = iterator.next();
			Address addr = range.getMinAddress();
			String name = String.format("_unknown_%x", addr.getOffset());
			LightKeeperFraction zeroFraction = new LightKeeperFraction(0, 0);
			LightKeeperCoverageTableModelRow row = new LightKeeperCoverageTableModelRow(name, addr.getOffset(), zeroFraction, zeroFraction, 0);
			this.rows.add(row);
		}
	}
	
	public ArrayList<LightKeeperCoverageTableModelRow> getRows() {
		return this.rows;
	}
}
