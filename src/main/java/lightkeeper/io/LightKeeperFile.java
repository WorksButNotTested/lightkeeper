package lightkeeper.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;

public class LightKeeperFile {		
	private LightKeeperFile (File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {		
		FileInputStream stream = new FileInputStream(file);
		LightKeeperByteProvider provider = new LightKeeperByteProvider(stream, file.length());
		LightKeeperReader reader = new LightKeeperReader(provider);
		monitor.checkCanceled();
		
		monitor.setMessage("Reading header");
		String header = reader.readLine();
		listener.addMessage(header);
		monitor.checkCanceled();
	}
	
	public static LightKeeperFile read(File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {
		return new LightKeeperFile(file, listener, monitor);
	}	
}
