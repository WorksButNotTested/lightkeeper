package lightkeeper.model.table;

import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.TableSortStateEditor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.model.ICoverageModelListener;

public class CoverageTable extends AbstractSortedTableModel<CoverageTableRow> implements ICoverageModelListener {
	protected CoverageTableModel model;

	private String[] columnNames = { "Coverage %", "Address", "Blocks Hit", "Instructions Hit",
			"Function Size", "Function Name" };

	public CoverageTable(CoverageTableModel model) {
		this.model = model;
		var tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(0, SortDirection.DESCENDING);
		tableSortStateEditor.addSortedColumn(2);
		setTableSortState(tableSortStateEditor.createTableSortState());
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public String getName() {
		return "Coverage Data";
	}

	@Override
	public List<CoverageTableRow> getModelData() {
		return model.getModelData();
	}

	@Override
	public Object getColumnValueForRow(CoverageTableRow row, int columnIndex) {
		switch (columnIndex) {
		case 0:
			return row.getCoverage();	
		case 1:
			return String.format("0x%08x", row.getAddress());
		case 2:
			return row.getBlocks();
		case 3:
			return row.getInstructions();
		case 4:
			return row.getFunctionSize();
		case 5:
			return row.getName();			
		default:
			throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		fireTableDataChanged();
	}
}
