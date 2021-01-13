package lightkeeper.model;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.IEventListener;

public interface ICoverageModel<T,U> extends IEventListener {
	public void addModelListener(ICoverageModelListener listener);
	public void load(T ranges);
	public void update(TaskMonitor monitor) throws CancelledException;
	public void clear(TaskMonitor monitor) throws CancelledException;
	public U getModelData();
}
