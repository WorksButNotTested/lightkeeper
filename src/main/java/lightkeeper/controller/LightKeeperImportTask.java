package lightkeeper.controller;

import java.io.File;
import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.model.LightKeeperCoverageModel;

public class LightKeeperImportTask extends Task {
	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageModel model;
	protected File file;
	protected ILightKeeperTaskEventListener listener;

	public LightKeeperImportTask(LightKeeperPlugin plugin, LightKeeperCoverageModel model, File file, ILightKeeperTaskEventListener listener) {
		super("Import Coverage Data", true, true, true);
		this.plugin = plugin;
		this.model = model;
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
			LightKeeperFile dataFile = LightKeeperFile.read(this.file, this.listener, monitor);
			for (int i = 0; i < 15; i++)
			{
				listener.addMessage(String.format("Processing: %d / 15", i));
				monitor.checkCanceled();
				Thread.sleep(200);
				monitor.setProgress(i + 1);
			}
			listener.addMessage(String.format("Imported: %s",this.file.getAbsolutePath()));
			
			this.model.update(this.listener, monitor, this.plugin.getApi(), dataFile);	
		} catch (InterruptedException e) { 
			this.listener.addException(e);
		} catch (IOException e) {
			this.listener.addException(e);
		}
	}
}
