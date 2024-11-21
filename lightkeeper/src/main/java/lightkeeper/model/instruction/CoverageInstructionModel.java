package lightkeeper.model.instruction;

import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.AbstractCoverageModel;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageModel;

public class CoverageInstructionModel extends AbstractCoverageModel<AddressSet, AddressSet>
		implements ICoverageModelListener {
	protected CoverageModel coverage;
	protected AddressSet modelRanges;
	protected AddressSet hits = new AddressSet();

	public CoverageInstructionModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		super(plugin);
		this.coverage = coverage;
	}

	@Override
	public void load(AddressSet ranges) {
		modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException {
		hits = new AddressSet();
		if (modelRanges == null) {
			return;
		}

		var instructions = plugin.getApi().getCurrentProgram().getListing().getInstructions(modelRanges, true);
		instructions.forEach(i -> hits.add(new AddressRangeImpl(i.getMinAddress(), i.getMaxAddress())));
		notifyUpdate(monitor);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		modelRanges = null;
		hits = new AddressSet();
		notifyUpdate(monitor);
	}

	@Override
	public AddressSet getModelData() {
		return hits;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var ranges = coverage.getModelData();
		load(ranges);
		update(monitor);
	}
}
