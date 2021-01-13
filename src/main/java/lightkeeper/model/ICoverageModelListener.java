package lightkeeper.model;

import java.util.EventListener;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface ICoverageModelListener extends EventListener{
	void modelChanged(TaskMonitor monitor)  throws CancelledException;
}