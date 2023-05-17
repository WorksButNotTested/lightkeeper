package lightkeeper.io.block;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.IEventListener;
import lightkeeper.io.BinaryLineReader;

public class BlockReader implements IEventListener {
	protected TaskMonitor monitor;
	protected BinaryLineReader reader;

	private List<IEventListener> listeners = new ArrayList<>();

	public BlockReader(TaskMonitor monitor, BinaryLineReader reader) {
		this.monitor = monitor;
		this.reader = reader;
	}

	public void addListener(IEventListener listener) {
		listeners.add(listener);
	}

	@Override
	public void addMessage(String message) {
		listeners.forEach(l -> l.addMessage(message));
	}

	@Override
	public void addErrorMessage(String message) {
		listeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		listeners.forEach(l -> l.addException(exc));
	}

	public BlockEntry read() throws CancelledException, IOException {
		monitor.checkCancelled();
		var start = reader.readNextUnsignedInt();
		var size = reader.readNextUnsignedShort();
		var module = reader.readNextUnsignedShort();

		var block = new BlockEntry(start, size, module);
		addMessage(String.format("Read Block: %s", block));
		monitor.checkCancelled();
		return block;
	}
}
