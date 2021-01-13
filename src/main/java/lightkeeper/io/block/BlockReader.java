package lightkeeper.io.block;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.EventListener;
import lightkeeper.io.BinaryLineReader;

public class BlockReader implements EventListener {	
	protected TaskMonitor monitor;
	protected BinaryLineReader reader;
	
	private List<EventListener> listeners = new ArrayList<EventListener>();
	
	public BlockReader(TaskMonitor monitor, BinaryLineReader reader) {		
		this.monitor = monitor;
		this.reader = reader;
	}
	
	public void addListener(EventListener listener) {
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
	
	
	public BlockEntry read() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		long start = this.reader.readNextUnsignedInt();
		int size = this.reader.readNextUnsignedShort();
		int module = this.reader.readNextUnsignedShort();
		
		BlockEntry block = new BlockEntry(start, size, module);
		this.addMessage(String.format("Read Block: %s", block));
		this.monitor.checkCanceled();
		return block;		
	}
}
