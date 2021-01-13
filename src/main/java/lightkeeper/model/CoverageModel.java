package lightkeeper.model;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.ranges.CoverageFileRanges;

public class CoverageModel extends AbstractCoverageModel<CoverageFileRanges, CoverageFileRanges> {
	protected CoverageFileRanges modelRanges;

	public CoverageModel(LightKeeperPlugin plugin) {
		super(plugin);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		modelRanges = null;
		modelRanges = new CoverageFileRanges(plugin);
		notifyUpdate(monitor);
	}

	@Override
	public void load(CoverageFileRanges ranges) {
		modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException
	{
		notifyUpdate(monitor);
	}

	@Override
	public CoverageFileRanges getModelData() {
		return modelRanges;
	}
}
