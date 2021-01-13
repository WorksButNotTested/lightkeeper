package lightkeeper.model.instruction;

import java.util.ArrayList;
import java.util.HashSet;
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
import lightkeeper.model.LightKeeperCoverageRangeCollection;

public class LightKeeperCoverageInstructionModel {
	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageRangeCollection modelRanges;
	protected Set<AddressRange> hits = new HashSet<AddressRange>();
	protected ArrayList<LightKeeperCoverageInstructionModelListener> listeners = new ArrayList<LightKeeperCoverageInstructionModelListener>();
	
	public LightKeeperCoverageInstructionModel(LightKeeperPlugin plugin) {
		this.plugin = plugin;	
	}
	
	public void load(LightKeeperCoverageRangeCollection ranges) {
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
		listeners.forEach(l -> l.instructionsChanged());
	}
	
	public void addInstructionModelListener(LightKeeperCoverageInstructionModelListener listener) {
		listeners.add(listener);
	}
	
	public void clear() {
		this.modelRanges = null;
		this.hits = new HashSet<AddressRange>();
		listeners.forEach(l -> l.instructionsChanged());
	}
	
	public Set<AddressRange> getHits() {
		return this.hits;
	} 
}
