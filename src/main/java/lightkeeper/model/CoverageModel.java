package lightkeeper.model;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;

public class CoverageModel extends AbstractCoverageModel<CoverageFileRanges, CoverageFileRanges> {
	protected CoverageFileRanges modelRanges;
	
	public CoverageModel(LightKeeperPlugin plugin) {
		super(plugin);	
	}
	
	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		this.modelRanges = null;
		this.modelRanges = new CoverageFileRanges(this.plugin);
		this.notifyUpdate(monitor);
	}
	
	@Override
	public void load(CoverageFileRanges ranges) {
		this.modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException
	{
		this.notifyUpdate(monitor);
	}

	@Override
	public CoverageFileRanges getModelData() {
		return this.modelRanges;
	}
}
