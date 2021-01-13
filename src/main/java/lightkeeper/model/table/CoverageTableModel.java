package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.TableSortStateEditor;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.IEventListener;
import lightkeeper.model.CoverageModel;
import lightkeeper.model.ICoverageModel;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.ranges.CoverageFileRanges;

public class CoverageTableModel extends AbstractSortedTableModel<CoverageTableRow> implements ICoverageModel<CoverageFileRanges, ArrayList<CoverageTableRow>>, ICoverageModelListener {
	private ArrayList<IEventListener> listeners = new ArrayList<>();

	public void addListener(IEventListener listener) {
		listeners.add(listener);
	}

	@Override
	public void addMessage(String message) {
		listeners.forEach(l -> l.addMessage(message));
	}

	@Override
	public void addErrorMessage(String message) {
		listeners.forEach(l -> l.addErrorMessage(message));
	}

	@Override
	public void addException(Exception exc) {
		listeners.forEach(l -> l.addException(exc));
	}

	protected ArrayList<ICoverageModelListener> modelListeners = new ArrayList<>();

	@Override
	public void addModelListener(ICoverageModelListener listener) {
		modelListeners.add(listener);
	}

	private String[] columnNames = {
			"Coverage %",
			"Function Name",
			"Address",
			"Blocks Hit",
			"Instructions Hit",
			"Function Size"
	};

	protected LightKeeperPlugin plugin;
	protected CoverageModel coverage;
	protected CoverageFileRanges modelRanges;
	protected ArrayList<CoverageTableRow> rows = new ArrayList<>();

	public CoverageTableModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		this.plugin = plugin;
		this.coverage = coverage;
		var tableSortStateEditor = new TableSortStateEditor();
		tableSortStateEditor.addSortedColumn(0, SortDirection.DESCENDING);
		tableSortStateEditor.addSortedColumn(2);
		setTableSortState(tableSortStateEditor.createTableSortState());
	}

	@Override
	public void load(CoverageFileRanges ranges) {
		modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException
	{
		if (modelRanges == null) {
			return;
		}

		monitor.checkCanceled();

		processRanges(monitor);

		monitor.setMessage("Processing complete");
		addMessage("Processing complete");
		monitor.checkCanceled();
		notifyUpdate(monitor);
	}

	public void processRanges(TaskMonitor monitor) throws CancelledException {
		rows = new ArrayList<>();
		var functions = new HashMap<Function, Set<AddressRange>>();
		Set<AddressRange> unassigned = new HashSet<>();
		var api = plugin.getApi();
		var ranges = modelRanges.getRanges();
		for (var i = 0; i < ranges.size(); i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing block %d / %d", i, ranges.size()));
			var range = ranges.get(i);

			var function = api.getFunctionContaining(range.getMinAddress());
			if (function == null) {
				addMessage(String.format("No function found at: %x", range.getMinAddress().getOffset()));
				unassigned.add(range);
			} else {
				addMessage(String.format("Found function: '%s' at: %x", function.getName(), range.getMinAddress().getOffset()));
				var set = functions.get(function);
				if (set == null) {
					set = new HashSet<>();
					functions.put(function, set);
				}
				set.add(range);
			}
		}
		processFunctions(monitor, functions);
		processUnassigned(monitor, unassigned);
	}

	public void processFunctions(TaskMonitor monitor, HashMap<Function, Set<AddressRange>> functions) throws CancelledException {

		var functionIterator = functions.keySet().iterator();
		var i = 0;
		while (functionIterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			var function = functionIterator.next();
			monitor.setMessage(String.format("Processing function (%s) %d / %d", function.getName(), i, functions.size()));
			addMessage(String.format("Processing function (%s) %d / %d", function.getName(), i, functions.size()));
			var body = function.getBody();
			var ranges = functions.get(function);

			var codeBlockInfo = processCodeBlocks(monitor, function, ranges);
			var instructionInfo = processInstructions(monitor, function, ranges);
			var functionSize = body.getMaxAddress().subtract(body.getMinAddress());

			var row = new CoverageTableRow(function.getName(), body.getMinAddress().getOffset(),
					codeBlockInfo, instructionInfo, functionSize);
			rows.add(row);
		}
	}

	public CoverageFraction processCodeBlocks(TaskMonitor monitor, Function function, Set<AddressRange> ranges) throws CancelledException {
		var api = plugin.getApi();
		var bbm = new BasicBlockModel(api.getCurrentProgram());
		var body = function.getBody();
		var codeBlockIterator = bbm.getCodeBlocksContaining(body, monitor);
		var codeBlocks = 0;
		var hitCodeBlocks = 0;
		while (codeBlockIterator.hasNext()) {
			monitor.checkCanceled();
			codeBlocks++;

			monitor.setMessage(String.format("Processing function blocks (%s) %d", function.getName(), codeBlocks));
			addMessage(String.format("Processing function blocks (%s) %d", function.getName(), codeBlocks));

			var cb = codeBlockIterator.next();

			var rangeIterator = ranges.iterator();
			while (rangeIterator.hasNext()) {
				monitor.checkCanceled();

				var range = rangeIterator.next();
				if (range.getMinAddress().compareTo(cb.getMinAddress()) < 0) {
					continue;
				}

				if (range.getMaxAddress().compareTo(cb.getMaxAddress()) > 0) {
					continue;
				}

				hitCodeBlocks++;
			}
		}
		return new CoverageFraction(hitCodeBlocks, codeBlocks);
	}

	public CoverageFraction processInstructions(TaskMonitor monitor, Function function, Set<AddressRange> ranges) throws CancelledException {
		var api = plugin.getApi();
		var listing = api.getCurrentProgram().getListing();
		var body = function.getBody();
		var instructionIterator = listing.getInstructions(body, true);
		var instructions = 0;
		var hitInstructions = 0;
		while (instructionIterator.hasNext()) {
			monitor.checkCanceled();
			instructions++;
			monitor.setMessage(String.format("Processing function instructions (%s) %d", function.getName(), instructions));
			addMessage(String.format("Processing function instructions (%s) %d", function.getName(), instructions));

			var instruction = instructionIterator.next();
			var rangeIterator = ranges.iterator();
			while (rangeIterator.hasNext()) {
				monitor.checkCanceled();
				var range = rangeIterator.next();

				if (instruction.getMinAddress().compareTo(range.getMinAddress()) < 0) {
					continue;
				}

				if (instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0) {
					continue;
				}


				hitInstructions++;
			}
		}
		return new CoverageFraction(hitInstructions, instructions);
	}

	public void processUnassigned(TaskMonitor monitor, Set<AddressRange> unassigned) throws CancelledException {
		var iterator = unassigned.iterator();
		var i = 0;
		while (iterator.hasNext()) {
			i++;
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			addMessage(String.format("Processing unassigned block %d / %d", i, unassigned.size()));
			var range = iterator.next();
			var addr = range.getMinAddress();
			var name = String.format("_unknown_%x", addr.getOffset());
			var zeroFraction = new CoverageFraction(0, 0);
			var row = new CoverageTableRow(name, addr.getOffset(), zeroFraction, zeroFraction, 0);
			rows.add(row);
		}
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException{
		modelRanges = null;
		rows = new ArrayList<>();
		notifyUpdate(monitor);
	}

	protected void notifyUpdate(TaskMonitor monitor) throws CancelledException {
		fireTableDataChanged();
		for (ICoverageModelListener listener: modelListeners) {
			listener.modelChanged(monitor);
		}
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
	public ArrayList<CoverageTableRow> getModelData() {
		return rows;
	}

	@Override
	public Object getColumnValueForRow(CoverageTableRow row, int columnIndex) {
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

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var ranges = coverage.getModelData();
		load(ranges);
		update(monitor);
	}
}
