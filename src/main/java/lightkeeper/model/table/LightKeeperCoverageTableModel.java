package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortStateEditor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperEventListener;
import lightkeeper.model.LightKeeperCoverageRangeCollection;

public class LightKeeperCoverageTableModel extends AbstractSortedTableModel<LightKeeperCoverageTableModelRow> implements LightKeeperEventListener {
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };

	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageRangeCollection modelRanges;
	protected LightKeeperCoverageTableModelBuilder builder;
	
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
	
	public LightKeeperCoverageTableModel(LightKeeperPlugin plugin) {
		super();
		this.plugin = plugin;		
		this.builder = new LightKeeperCoverageTableModelBuilder(plugin);
		TableSortStateEditor tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(0);
		tableSortStateEditor.addSortedColumn(2);
		this.setTableSortState(tableSortStateEditor.createTableSortState());
	}
	
	public void load(LightKeeperCoverageRangeCollection ranges) {
		this.modelRanges = ranges;
	}

	public void update(TaskMonitor monitor) throws CancelledException
	{
		if (this.modelRanges == null)
			return;
		
		this.builder = new LightKeeperCoverageTableModelBuilder(this.plugin);
		builder.addListener(this);
		builder.build(monitor, this.modelRanges);
		monitor.checkCanceled();		
		fireTableDataChanged();
	}
	
	public void clear() {
		this.modelRanges = null;
		this.builder = new LightKeeperCoverageTableModelBuilder(this.plugin);
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
	public List<LightKeeperCoverageTableModelRow> getModelData() {
		return this.builder.getRows();
	}

	@Override
	public Object getColumnValueForRow(LightKeeperCoverageTableModelRow row, int columnIndex) {
		switch(columnIndex) {
			case 0:
				return row.getCoverage();
			case 1:
				return row.getName();
			case 2:
				return String.format("0x%x", row.getAddress());
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
}
