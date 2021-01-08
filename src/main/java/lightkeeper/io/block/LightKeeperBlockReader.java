package lightkeeper.io.block;

import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;
import lightkeeper.io.LightKeeperReader;

public class LightKeeperBlockReader {
	protected ILightKeeperTaskEventListener listener;
	protected TaskMonitor monitor;
	protected LightKeeperReader reader;

	public LightKeeperBlockReader(ILightKeeperTaskEventListener listener, TaskMonitor monitor, LightKeeperReader reader) {
		this.listener = listener;
		this.monitor = monitor;
		this.reader = reader;
	}
	
	public LightKeeperBlockEntry read() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		long start = this.reader.readNextUnsignedInt();
		int size = this.reader.readNextUnsignedShort();
		int module = this.reader.readNextUnsignedShort();
		
		LightKeeperBlockEntry block = new LightKeeperBlockEntry(start, size, module);
		listener.addMessage(String.format("Read Block: %s", block));
		this.monitor.checkCanceled();
		return block;		
	}
}
