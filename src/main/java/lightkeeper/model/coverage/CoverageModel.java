package lightkeeper.model.coverage;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
import lightkeeper.model.AbstractCoverageModel;

public class CoverageModel extends AbstractCoverageModel<DynamoRioFile, HashSet<AddressRange>> {
	protected ArrayList<DynamoRioFile> files = new ArrayList<>();
	protected HashMap<DynamoRioFile, HashSet<AddressRange>> map = new HashMap<>();
	protected HashSet<AddressRange> ranges = new HashSet<>();


	public CoverageModel(LightKeeperPlugin plugin) {
		super(plugin);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		files = new ArrayList<>();
		map = new HashMap<>();
		ranges = new HashSet<>();
		notifyUpdate(monitor);
	}

	@Override
	public void load(DynamoRioFile file) {
		files.add(file);
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException
	{
		try
		{
			ranges = new HashSet<>();
			for (DynamoRioFile file: files) {
				if (map.containsKey(file)) {
					continue;
				}

				var fileRanges = new HashSet<AddressRange>();
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
				map.put(file, fileRanges);
			}

			var rangeStream = map.values().stream().flatMap(HashSet::stream);
			ranges.addAll(rangeStream.collect(Collectors.toList()));

			notifyUpdate(monitor);
		}
		catch (AddressOverflowException e) {
			addException(e);
		}
	}

	@Override
	public HashSet<AddressRange> getModelData() {
		return ranges;
	}
}
