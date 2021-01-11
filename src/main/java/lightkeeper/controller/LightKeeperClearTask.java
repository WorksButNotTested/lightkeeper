package lightkeeper.controller;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import lightkeeper.model.LightKeeperCoverageModel;

public class LightKeeperClearTask extends Task {
	protected LightKeeperController controller;
	protected LightKeeperCoverageModel model;			

	public LightKeeperClearTask(LightKeeperController controller, LightKeeperCoverageModel model) {
		super("Clear Coverage Data", true, true, true);
		this.controller = controller;
		this.model = model;		
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Clearing");
		controller.addMessage("Clearing");		
		monitor.setProgress(0);
		this.model.clear();
		controller.addMessage("Completed");
		monitor.setProgress(100);
	}
}
