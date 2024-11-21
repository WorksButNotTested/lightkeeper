package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.AbstractCoverageModel;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageModel;

public class CoverageTableModel extends AbstractCoverageModel<AddressSet, List<CoverageTableRow>>
		implements ICoverageModelListener {
	protected CoverageModel coverage;
	protected AddressSet modelRanges;
	protected List<CoverageTableRow> rows = new ArrayList<>();

	public CoverageTableModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		super(plugin);
		this.coverage = coverage;
	}

	@Override
	public void load(AddressSet ranges) {
		modelRanges = ranges;
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException {
		if (modelRanges == null) {
			return;
		}

		monitor.checkCancelled();

		processRanges(monitor);

		monitor.setMessage("Processing complete");
		addMessage("Processing complete");
		monitor.checkCancelled();
		notifyUpdate(monitor);
	}

	public void processRanges(TaskMonitor monitor) throws CancelledException {
		rows = new ArrayList<>();
		Set<Function>  functions = new HashSet<>();

		var api = plugin.getApi();

		var i = 0;
		var numRanges = modelRanges.getNumAddressRanges();
		for (var range : modelRanges) {
			i++;
			monitor.checkCancelled();
			monitor.setMessage(String.format("Processing block %d / %d", i, numRanges));

			var function = api.getFunctionContaining(range.getMinAddress());
			if (function == null) {
				addMessage(String.format("No function found at: %x", range.getMinAddress().getOffset()));
				processUnassigned(monitor, range);
			} else if (!functions.contains(function)) {
				addMessage(String.format("Found function: '%s' at: %x", function.getName(),
						range.getMinAddress().getOffset()));
				functions.add(function);

				if (function.isThunk()) {
					addMessage(String.format("Skipping thunk function: '%s'", function.getName()));
				} else {
					processFunction(monitor, function);
				}
			}
		}
	}

	public void processFunction(TaskMonitor monitor, Function function)
			throws CancelledException {
		var body = function.getBody();
		var codeBlockInfo = processCodeBlocks(monitor, function);
		var instructionInfo = processInstructions(monitor, function);
		var row = new CoverageTableRow(function.getName(), body.getMinAddress().getOffset(), codeBlockInfo,
				instructionInfo, body.getNumAddresses());
		rows.add(row);
	}

	public CoverageFraction processCodeBlocks(TaskMonitor monitor, Function function)
			throws CancelledException {
		var bbm = new BasicBlockModel(plugin.getApi().getCurrentProgram());
		var body = function.getBody();
		var codeBlocks = StreamSupport.stream(
						bbm.getCodeBlocksContaining(body, monitor)
						.spliterator(), false).count();
		var hitCodeBlocks = StreamSupport.stream(
						bbm.getCodeBlocksContaining(body.intersect(modelRanges), monitor)
						.spliterator(), false).count();
		return new CoverageFraction(hitCodeBlocks, codeBlocks);
	}

	public CoverageFraction processInstructions(TaskMonitor monitor, Function function) {
		var listing = plugin.getApi().getCurrentProgram().getListing();
		var body = function.getBody();
		var instructions = StreamSupport.stream(
						listing.getInstructions(body, true)
						.spliterator(), false).count();
		var hitInstructions = StreamSupport.stream(
						listing.getInstructions(body.intersect(modelRanges), true)
						.spliterator(), false).count();
		return new CoverageFraction(hitInstructions, instructions);
	}

	public void processUnassigned(TaskMonitor monitor, AddressRange range) throws CancelledException {
		var addr = range.getMinAddress();
		var name = String.format("_unknown_%x", addr.getOffset());
		var zeroFraction = new CoverageFraction(0, 0);
		var row = new CoverageTableRow(name, addr.getOffset(), zeroFraction, zeroFraction, 0);
		rows.add(row);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		modelRanges = null;
		rows = new ArrayList<>();
		notifyUpdate(monitor);
	}

	@Override
	public List<CoverageTableRow> getModelData() {
		return rows;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var ranges = coverage.getModelData();
		load(ranges);
		update(monitor);
	}
}
