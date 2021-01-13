package lightkeeper.model.instruction;

import java.util.HashSet;

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
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.AbstractCoverageModel;
import lightkeeper.model.CoverageFileRanges;
import lightkeeper.model.CoverageModel;

public class CoverageInstructionModel extends AbstractCoverageModel<CoverageFileRanges, HashSet<AddressRange>> implements ICoverageModelListener {
	protected CoverageModel coverage;
	protected CoverageFileRanges modelRanges;
	protected HashSet<AddressRange> hits = new HashSet<AddressRange>();
	
	
	public CoverageInstructionModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		super(plugin);
		this.coverage = coverage;
	}
	
	@Override
	public void load(CoverageFileRanges ranges) {
		this.modelRanges = ranges;
	}

	@Override
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
	
	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		this.modelRanges = null;
		this.hits = new HashSet<AddressRange>();
		this.notifyUpdate(monitor);
	}
	
	@Override
	public HashSet<AddressRange> getModelData() {
		return this.hits;
	} 
	
	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		CoverageFileRanges ranges = this.coverage.getModelData();
		this.load(ranges);
		this.update(monitor);
	}
}
