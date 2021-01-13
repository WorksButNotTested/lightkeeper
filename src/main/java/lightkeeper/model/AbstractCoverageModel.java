package lightkeeper.model;

import java.util.ArrayList;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.IEventListener;

public abstract class AbstractCoverageModel<T,U> implements ICoverageModel<T, U> {
	private ArrayList<IEventListener> eventListeners = new ArrayList<IEventListener>();
	
	public void addListener(IEventListener listener) {
		this.eventListeners.add(listener);
	}
	
	@Override
	public void addMessage(String message) {
		this.eventListeners.forEach(l -> l.addMessage(message));
	}
	
	@Override
	public void addErrorMessage(String message) {
		this.eventListeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		this.eventListeners.forEach(l -> l.addException(exc));		
	}
	
	protected ArrayList<ICoverageModelListener> modelListeners = new ArrayList<ICoverageModelListener>();
	
	public void addModelListener(ICoverageModelListener listener) {
		modelListeners.add(listener);
	}
	
	protected LightKeeperPlugin plugin;
	
	protected AbstractCoverageModel(LightKeeperPlugin plugin) {
		this.plugin = plugin;	
	}
	
	public abstract void clear(TaskMonitor monitor) throws CancelledException;
	
	protected void notifyUpdate(TaskMonitor monitor) throws CancelledException {
		for (ICoverageModelListener listener: this.modelListeners) {
			listener.modelChanged(monitor);
		}
	}
	
	public abstract void load(CoverageFileRanges ranges);

	public abstract void update(TaskMonitor monitor) throws CancelledException;

	public abstract U getModelData();

	public abstract void load(T data);
}
