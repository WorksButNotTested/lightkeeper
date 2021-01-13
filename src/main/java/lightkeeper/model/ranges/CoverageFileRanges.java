package lightkeeper.model.ranges;

import java.io.File;
import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.block.BlockEntry;
import lightkeeper.io.file.DynamoRioFile;
import lightkeeper.io.module.ModuleEntry;

public class CoverageFileRanges {
	protected LightKeeperPlugin plugin;
	protected ArrayList<AddressRange> ranges = new ArrayList<>();

	public CoverageFileRanges(LightKeeperPlugin plugin) {
		this.plugin = plugin;
	}

	public void read(TaskMonitor monitor, DynamoRioFile file) throws AddressOverflowException, CancelledException {
		ranges = new ArrayList<>();
		var api = plugin.getApi();
		var programFile = api.getProgramFile();
		var programFileName = programFile.getName();
		var selectedModules = file.getModules().stream()
				.filter(m -> new File(m.getPath()).getName().equals(programFileName));
		Set<Integer> ids = selectedModules.map(ModuleEntry::getId).collect(Collectors.toSet());

		var baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		for (BlockEntry block: file.getBlocks()) {
			monitor.checkCanceled();
			if (!ids.contains(block.getModule())) {
				continue;
			}
			var start = baseAddress.add(block.getStart());
			AddressRange range = new AddressRangeImpl(start, block.getSize());
			ranges.add(range);
		}
	}

	public ArrayList<AddressRange> getRanges() {
		return ranges;
	}
}
