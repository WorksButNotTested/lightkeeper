package lightkeeper.model;

import java.util.EventListener;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface CoverageModelListener extends EventListener{
    public void modelChanged(TaskMonitor monitor)  throws CancelledException;
}