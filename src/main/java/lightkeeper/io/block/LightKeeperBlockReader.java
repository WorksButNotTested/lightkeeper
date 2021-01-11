package lightkeeper.io.block;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.LightKeeperEventListener;
import lightkeeper.io.LightKeeperReader;

public class LightKeeperBlockReader implements LightKeeperEventListener {	
	protected TaskMonitor monitor;
	protected LightKeeperReader reader;
	
	private List<LightKeeperEventListener> listeners = new ArrayList<LightKeeperEventListener>();
	
	public LightKeeperBlockReader(TaskMonitor monitor, LightKeeperReader reader) {		
		this.monitor = monitor;
		this.reader = reader;
	}
	
	public void addListener(LightKeeperEventListener listener) {
		this.listeners.add(listener);
	}
	
	@Override
	public void addMessage(String message) {
		this.listeners.forEach(l -> l.addMessage(message));
	}
	
	@Override
	public void addErrorMessage(String message) {
		this.listeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		this.listeners.forEach(l -> l.addException(exc));		
	}
	
	
	public LightKeeperBlockEntry read() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		long start = this.reader.readNextUnsignedInt();
		int size = this.reader.readNextUnsignedShort();
		int module = this.reader.readNextUnsignedShort();
		
		LightKeeperBlockEntry block = new LightKeeperBlockEntry(start, size, module);
		this.addMessage(String.format("Read Block: %s", block));
		this.monitor.checkCanceled();
		return block;		
	}
}
