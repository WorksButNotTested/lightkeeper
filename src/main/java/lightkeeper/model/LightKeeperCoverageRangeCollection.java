package lightkeeper.model;

import java.io.File;
import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.io.block.LightKeeperBlockEntry;
import lightkeeper.io.module.LightKeeperModuleEntry;

public class LightKeeperCoverageRangeCollection {
	protected LightKeeperPlugin plugin;
	protected ArrayList<AddressRange> ranges = new ArrayList<AddressRange>();
	
	public LightKeeperCoverageRangeCollection(LightKeeperPlugin plugin) {
		this.plugin = plugin;
	}
	
	public void read(TaskMonitor monitor, LightKeeperFile file) throws AddressOverflowException, CancelledException {
		this.ranges = new ArrayList<AddressRange>();
		FlatProgramAPI api = plugin.getApi();
		File programFile = api.getProgramFile();
		String programFileName = programFile.getName();
		Stream<LightKeeperModuleEntry> selectedModules = file.getModules().stream()
			.filter(m -> new File(m.getPath()).getName().equals(programFileName));
		Set<Integer> ids = selectedModules.map(m -> m.getId()).collect(Collectors.toSet());
		
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		for (LightKeeperBlockEntry block: file.getBlocks()) {
			monitor.checkCanceled();
			if (!ids.contains(block.getModule()))
				continue;
			Address start = baseAddress.add(block.getStart());
			AddressRange range = new AddressRangeImpl(start, block.getSize());
			this.ranges.add(range);
		}
	}
	
	public ArrayList<AddressRange> getRanges() {
		return this.ranges;
	}
}
