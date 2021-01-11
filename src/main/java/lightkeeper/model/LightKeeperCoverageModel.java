package lightkeeper.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortStateEditor;
import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperEventListener;
import lightkeeper.io.LightKeeperFile;

public class LightKeeperCoverageModel extends AbstractSortedTableModel<LightKeeperCoverageModelRow> implements LightKeeperEventListener {
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };

	protected LightKeeperPlugin plugin;
	protected LightKeeperFile file;
	protected LightKeeperCoverageModelBuilder builder;
	
	private List<LightKeeperEventListener> listeners = new ArrayList<LightKeeperEventListener>();
	
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
	
	public LightKeeperCoverageModel(LightKeeperPlugin plugin) {
		super();
		this.plugin = plugin;		
		this.builder = new LightKeeperCoverageModelBuilder(plugin);
		TableSortStateEditor tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(0);
		tableSortStateEditor.addSortedColumn(2);
		this.setTableSortState(tableSortStateEditor.createTableSortState());
	}
	
	public void load(LightKeeperFile lightKeeperFile) {
		this.file = lightKeeperFile;
	}

	public void update(TaskMonitor monitor) throws CancelledException, IOException
	{
		if (this.file == null)
			return;
		
		this.builder = new LightKeeperCoverageModelBuilder(this.plugin);
		builder.addListener(this);
		builder.build(monitor, this.file);
		monitor.checkCanceled();		
		fireTableDataChanged();
	}
	
	public void clear() {
		this.file = null;
		this.builder = new LightKeeperCoverageModelBuilder(this.plugin);
		fireTableDataChanged();
	}
	
	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public int getColumnCount() { 
		return columnNames.length;
	}
	
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public String getName() {
		return "Coverage Data";
	}

	@Override
	public List<LightKeeperCoverageModelRow> getModelData() {
		return this.builder.getRows();
	}

	@Override
	public Object getColumnValueForRow(LightKeeperCoverageModelRow row, int columnIndex) {
		switch(columnIndex) {
			case 0:
				return String.format("%.2f", row.getCoverage());
			case 1:
				return row.getName();
			case 2:
				return String.format("%x", row.getAddress());
			case 3:
				return row.getBlocks();
			case 4:
				return row.getInstructions();
			case 5:
				return row.getFunctionSize();
			default:
				throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
	}
	
	public Set<AddressRange> getHits() {
		return this.builder.getHits();
	}

}
