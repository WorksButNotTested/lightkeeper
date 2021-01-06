package lightkeeper.data;

import java.io.File;
import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;
import lightkeeper.io.LightKeeperFile;

public class LightKeeperImportTask extends Task {
	protected File file;
	protected ILightKeeperTaskEventListener listener;

	public LightKeeperImportTask(File file, ILightKeeperTaskEventListener listener) {
		super("Import Coverage Data", true, true, true);
		this.file = file;
		this.listener = listener;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage(String.format("Importing: %s",this.file.getAbsolutePath()));
		listener.addMessage(String.format("Importing: %s",this.file.getAbsolutePath()));
		try {
			monitor.setMaximum(15);
			monitor.setProgress(0);
			LightKeeperFile.read(this.file, this.listener, monitor);
			for (int i = 0; i < 15; i++)
			{
				listener.addMessage(String.format("Processing: %d / 15", i));
				monitor.checkCanceled();
				Thread.sleep(200);
				monitor.setProgress(i + 1);
			}
			listener.addMessage(String.format("Imported: %s",this.file.getAbsolutePath()));
		} catch (InterruptedException e) { 
			this.listener.addException(e);
		} catch (IOException e) {
			this.listener.addException(e);
		}
	}
}
