package lightkeeper;

import java.io.File;

import ghidra.app.services.ConsoleService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class LightKeeperImportTask extends Task {
	protected File file;
	
	public LightKeeperImportTask(File file) {
		super("Import Coverage Data", true, true, true);
		this.file = file;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Importing: " + this.file.getAbsolutePath());
		try {
			monitor.setMaximum(15);
			monitor.setProgress(0);
			for (int i = 0; i < 15; i++)
			{
				monitor.checkCanceled();
				Thread.sleep(200);
				monitor.setProgress(i + 1);
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
