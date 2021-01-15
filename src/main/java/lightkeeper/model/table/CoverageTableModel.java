package lightkeeper.model.table;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.AbstractCoverageModel;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageModel;

public class CoverageTableModel extends AbstractCoverageModel<HashSet<AddressRange>, ArrayList<CoverageTableRow>> implements ICoverageModelListener {	
	protected CoverageModel coverage;
	protected ArrayList<AddressRange> modelRanges;
	protected ArrayList<CoverageTableRow> rows = new ArrayList<>();

	public CoverageTableModel(LightKeeperPlugin plugin, CoverageModel coverage) {
		super(plugin);
		this.coverage = coverage;	
	}

	@Override
	public void load(HashSet<AddressRange> ranges) {
		modelRanges = new ArrayList<>(ranges);
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
		for (var i = 0; i < modelRanges.size(); i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing block %d / %d", i, modelRanges.size()));
			var range = modelRanges.get(i);

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
			var addressRanges = StreamSupport.stream(body.getAddressRanges().spliterator(), false);
			var sizes = addressRanges.map(r -> r.getMaxAddress().subtract(r.getMinAddress()) + 1);			
			var functionSize = sizes.reduce(0L, (subTotal, s) -> subTotal + s);		
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
				break;
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
				break;
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
	
	@Override
	public ArrayList<CoverageTableRow> getModelData() {
		return rows;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var ranges = coverage.getModelData();
		load(ranges);
		update(monitor);
	}
}
