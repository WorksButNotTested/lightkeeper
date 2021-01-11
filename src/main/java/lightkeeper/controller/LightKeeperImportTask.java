package lightkeeper.controller;

import java.io.File;
import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.model.LightKeeperCoverageModel;

public class LightKeeperImportTask extends Task {
	protected LightKeeperController controller;
	protected LightKeeperCoverageModel model;		
	protected File file;

	public LightKeeperImportTask(LightKeeperController controller, LightKeeperCoverageModel model, File file) {
		super("Import Coverage Data", true, true, true);
		this.controller = controller;
		this.model = model;				
		this.file = file;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage(String.format("Importing: %s",this.file.getAbsolutePath()));
		controller.addMessage(String.format("Importing: %s",this.file.getAbsolutePath()));
		try {
			monitor.setMaximum(15);
			monitor.setProgress(0);
			
			LightKeeperFile dataFile = new LightKeeperFile(this.file, monitor);
			dataFile.addListener(this.controller);
			dataFile.read();
			
			controller.addMessage(String.format("Imported: %s",this.file.getAbsolutePath()));			
			this.model.update(monitor, dataFile);			
			controller.addMessage("Completed");
		} catch (IOException e) {
			controller.addException(e);
		}
	}
}
