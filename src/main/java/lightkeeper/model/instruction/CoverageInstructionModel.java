package lightkeeper.model.instruction;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.EventListener;
import lightkeeper.model.CoverageModelListener;
import lightkeeper.model.CoverageFileRanges;

public class CoverageInstructionModel implements EventListener {
	private List<EventListener> eventListeners = new ArrayList<EventListener>();
	
	public void addListener(EventListener listener) {
		this.eventListeners.add(listener);
	}
	
	@Override
	public void addMessage(String message) {
		this.eventListeners.forEach(l -> l.addMessage(message));
	}
	
	@Override
	public void addErrorMessage(String message) {
		this.eventListeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		this.eventListeners.forEach(l -> l.addException(exc));		
	}
	
	protected ArrayList<CoverageModelListener> modelListeners = new ArrayList<CoverageModelListener>();
	
	public void addModelListener(CoverageModelListener listener) {
		modelListeners.add(listener);
	}
	
	protected LightKeeperPlugin plugin;
	protected CoverageFileRanges modelRanges;
	protected Set<AddressRange> hits = new HashSet<AddressRange>();
	
	
	public CoverageInstructionModel(LightKeeperPlugin plugin) {
		this.plugin = plugin;	
	}
	
	public void load(CoverageFileRanges ranges) {
		this.modelRanges = ranges;
	}

	public void update(TaskMonitor monitor) throws CancelledException
	{
		this.hits = new HashSet<AddressRange>();
		if (this.modelRanges == null)
			return;
		
		FlatProgramAPI api = this.plugin.getApi();
		Listing listing = api.getCurrentProgram().getListing();
		
		for(AddressRange range: this.modelRanges.getRanges()) {
			monitor.checkCanceled();
			InstructionIterator iterator = listing.getInstructions(range.getMinAddress(), true);
			while (iterator.hasNext()) {
				Instruction instruction = iterator.next();
				
				if (instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0)
					break;
				
				Address instructionStart = instruction.getAddress();
				long length = instruction.getLength();
				if (length > 0)
					length--;
				Address instructionEnd = instructionStart.add(length);
				AddressRange instructionRange = new AddressRangeImpl(instructionStart, instructionEnd);
				this.hits.add(instructionRange);
			}
		}
		this.notifyUpdate(monitor);
	}
	
	public void clear(TaskMonitor monitor) throws CancelledException {
		this.modelRanges = null;
		this.hits = new HashSet<AddressRange>();
		this.notifyUpdate(monitor);
	}
	
	protected void notifyUpdate(TaskMonitor monitor) throws CancelledException {
		for (CoverageModelListener listener: this.modelListeners) {
			listener.modelChanged(monitor);
		}
	}
	
	public Set<AddressRange> getHits() {
		return this.hits;
	} 
}
