package lightkeeper.controller;

import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import lightkeeper.model.LightKeeperCoverageModel;

public class LightKeeperRefreshTask extends Task {
	protected LightKeeperController controller;
	protected LightKeeperCoverageModel model;			

	public LightKeeperRefreshTask(LightKeeperController controller, LightKeeperCoverageModel model) {
		super("Refresh Coverage Data", true, true, true);
		this.controller = controller;
		this.model = model;		
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Refreshing");
		controller.addMessage("Refreshing");
		try {			
			monitor.setProgress(0);
			this.model.update(monitor);			
			controller.addMessage("Completed");
			monitor.setProgress(100);
		} catch (IOException e) {
			controller.addException(e);
		}
	}
}
