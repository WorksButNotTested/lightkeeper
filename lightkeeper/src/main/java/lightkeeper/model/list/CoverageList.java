package lightkeeper.model.list;

import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.TableSortStateEditor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageListRow;
import lightkeeper.model.coverage.CoverageModel;

public class CoverageList extends AbstractSortedTableModel<CoverageListRow> implements ICoverageModelListener {
	protected CoverageModel model;

	private String[] columnNames = { "", "File", "Unique Matched", "Matched Blocks", "Total Blocks" };

	public CoverageList(CoverageModel model) {
		this.model = model;
		var tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(1, SortDirection.ASCENDING);
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
		return "Coverage Files";
	}

	@Override
	public List<CoverageListRow> getModelData() {
		return this.model.getFileData();
	}

	@Override
	public Object getColumnValueForRow(CoverageListRow row, int columnIndex) {
		switch (columnIndex) {
		case 0:
			return row.getState();
		case 1:
			return row.getName();
		case 2:
			return row.getUniqueMatchedBlocks();
		case 3:
			return row.getMatchedBlocks();
		case 4:
			return row.getTotalBlocks();
		default:
			throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		fireTableDataChanged();
	}
}
