package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortStateEditor;
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
import lightkeeper.model.LightKeeperCoverageModelListener;
import lightkeeper.model.LightKeeperCoverageRangeCollection;

public class LightKeeperCoverageTableModel extends AbstractSortedTableModel<LightKeeperCoverageTableModelRow> implements LightKeeperEventListener {	
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
	
	protected ArrayList<LightKeeperCoverageModelListener> modelListeners = new ArrayList<LightKeeperCoverageModelListener>();
	
	public void addModelListener(LightKeeperCoverageModelListener listener) {
		modelListeners.add(listener);
	}
	
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };

	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageRangeCollection modelRanges;
	protected ArrayList<LightKeeperCoverageTableModelRow> rows = new ArrayList<LightKeeperCoverageTableModelRow>();
	
	public LightKeeperCoverageTableModel(LightKeeperPlugin plugin) {
		super();
		this.plugin = plugin;		
		TableSortStateEditor tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(0);
		tableSortStateEditor.addSortedColumn(2);
		this.setTableSortState(tableSortStateEditor.createTableSortState());
	}
	
	public void load(LightKeeperCoverageRangeCollection ranges) {
		this.modelRanges = ranges;
	}

	public void update(TaskMonitor monitor) throws CancelledException
	{
		if (this.modelRanges == null)
			return;
		
		monitor.checkCanceled();
		
		this.processRanges(monitor);
		
		monitor.setMessage("Processing complete");
		this.addMessage("Processing complete");
		monitor.checkCanceled();	
		this.notifyUpdate(monitor);
	}
	
	public void processRanges(TaskMonitor monitor) throws CancelledException {
		this.rows = new ArrayList<LightKeeperCoverageTableModelRow>();
		HashMap<Function, Set<AddressRange>> functions = new HashMap<Function, Set<AddressRange>>();
		Set<AddressRange> unassigned = new HashSet<AddressRange>();
		FlatProgramAPI api = this.plugin.getApi();
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
		this.processFunctions(monitor, functions);
		this.processUnassigned(monitor, unassigned);
	}
	
	public void processFunctions(TaskMonitor monitor, HashMap<Function, Set<AddressRange>> functions) throws CancelledException {
		
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
			
			LightKeeperFraction codeBlockInfo = this.processCodeBlocks(monitor, function, ranges);
			LightKeeperFraction instructionInfo = this.processInstructions(monitor, function, ranges);
			long functionSize = body.getMaxAddress().subtract(body.getMinAddress());
			
			LightKeeperCoverageTableModelRow row = new LightKeeperCoverageTableModelRow(function.getName(), body.getMinAddress().getOffset(), 
					codeBlockInfo, instructionInfo, functionSize);
			this.rows.add(row);
		}
	}
	
	public LightKeeperFraction processCodeBlocks(TaskMonitor monitor, Function function, Set<AddressRange> ranges) throws CancelledException {
		FlatProgramAPI api = this.plugin.getApi();
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
	
	public LightKeeperFraction processInstructions(TaskMonitor monitor, Function function, Set<AddressRange> ranges) throws CancelledException {
		FlatProgramAPI api = this.plugin.getApi();
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
	
	public void processUnassigned(TaskMonitor monitor, Set<AddressRange> unassigned) throws CancelledException {		
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
	
	public void clear(TaskMonitor monitor) throws CancelledException{
		this.modelRanges = null;
		this.rows = new ArrayList<LightKeeperCoverageTableModelRow>();
		this.notifyUpdate(monitor);
	}
	
	protected void notifyUpdate(TaskMonitor monitor) throws CancelledException {
		this.fireTableDataChanged();
		for (LightKeeperCoverageModelListener listener: this.modelListeners) {
			listener.modelChanged(monitor);
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
	public List<LightKeeperCoverageTableModelRow> getModelData() {
		return this.rows;
	}

	@Override
	public Object getColumnValueForRow(LightKeeperCoverageTableModelRow row, int columnIndex) {
		switch(columnIndex) {
			case 0:
				return row.getCoverage();
			case 1:
				return row.getName();
			case 2:
				return String.format("0x%x", row.getAddress());
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
}
