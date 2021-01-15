package lightkeeper.model;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.IEventListener;

public interface ICoverageModel<T,U> extends IEventListener {
	void addModelListener(ICoverageModelListener listener);
	void load(T ranges);
	void update(TaskMonitor monitor) throws CancelledException;
	void clear(TaskMonitor monitor) throws CancelledException;
	U getModelData();
}
