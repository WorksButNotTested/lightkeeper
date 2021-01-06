package lightkeeper.data;

import javax.swing.table.AbstractTableModel;

public class LightKeeperModel extends AbstractTableModel {
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };

	@Override
	public int getRowCount() {
		return 0;
	}

	@Override
	public int getColumnCount() {
		// TODO Auto-generated method stub
		return columnNames.length;
	}
	
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		// TODO Auto-generated method stub
		return null;
	}
}
