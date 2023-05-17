package lightkeeper.model.instruction;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.AbstractCoverageModel;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageModel;

public class CoverageInstructionModel extends AbstractCoverageModel<Set<AddressRange>, Set<AddressRange>>
		implements ICoverageModelListener {
	protected CoverageModel coverage;
	protected Set<AddressRange> modelRanges;
	protected Set<AddressRange> hits = new HashSet<>();

	public CoverageInstructionModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		super(plugin);
		this.coverage = coverage;
	}

	@Override
	public void load(Set<AddressRange> ranges) {
		modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException {
		hits = new HashSet<>();
		if (modelRanges == null) {
			return;
		}

		var api = plugin.getApi();
		var listing = api.getCurrentProgram().getListing();

		for (AddressRange range : modelRanges) {
			monitor.checkCancelled();
			var iterator = listing.getInstructions(range.getMinAddress(), true);
			while (iterator.hasNext()) {
				var instruction = iterator.next();

				if (instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0) {
					break;
				}

				var instructionStart = instruction.getAddress();
				long length = instruction.getLength();
				if (length > 0) {
					length--;
				}
				var instructionEnd = instructionStart.add(length);
				AddressRange instructionRange = new AddressRangeImpl(instructionStart, instructionEnd);
				hits.add(instructionRange);
			}
		}
		notifyUpdate(monitor);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		modelRanges = null;
		hits = new HashSet<>();
		notifyUpdate(monitor);
	}

	@Override
	public Set<AddressRange> getModelData() {
		return hits;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var ranges = coverage.getModelData();
		load(ranges);
		update(monitor);
	}
}
