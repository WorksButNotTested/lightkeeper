package lightkeeper.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.IEventListener;

public abstract class AbstractCoverageModel<T, U> {

	private List<IEventListener> eventListeners = new ArrayList<>();

	public void addListener(IEventListener listener) {
		this.eventListeners.add(listener);
	}

	public void addMessage(String message) {
		this.eventListeners.forEach(l -> l.addMessage(message));
	}

	public void addErrorMessage(String message) {
		this.eventListeners.forEach(l -> l.addErrorMessage(message));
	}

	public void addException(Exception exc) {
		this.eventListeners.forEach(l -> l.addException(exc));
	}

	protected ArrayList<ICoverageModelListener> modelListeners = new ArrayList<>();

	public void addModelListener(ICoverageModelListener listener) {
		modelListeners.add(listener);
	}

	protected LightKeeperPlugin plugin;

	protected AbstractCoverageModel(LightKeeperPlugin plugin) {
		this.plugin = plugin;
	}

	public abstract void clear(TaskMonitor monitor) throws CancelledException;

	protected void notifyUpdate(TaskMonitor monitor) throws CancelledException {
		for (ICoverageModelListener listener : this.modelListeners) {
			listener.modelChanged(monitor);
		}
	}

	public abstract void load(T ranges) throws IOException;

	public abstract void update(TaskMonitor monitor) throws CancelledException, IOException;

	public abstract U getModelData();

}
