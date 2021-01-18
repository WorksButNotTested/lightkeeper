package lightkeeper.model.coverage;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

public class CoverageModel extends AbstractCoverageModel<DynamoRioFile, Set<AddressRange>> {
	protected List<CoverageListRow> rows = new ArrayList<>();
	protected Map<DynamoRioFile, HashSet<AddressRange>> map = new HashMap<>();
	protected Set<AddressRange> ranges = new HashSet<>();

	public CoverageModel(LightKeeperPlugin plugin) {
		super(plugin);
	}

	@Override
	public void clear(TaskMonitor monitor) throws CancelledException {
		rows = new ArrayList<>();
		map = new HashMap<>();
		ranges = new HashSet<>();
		notifyUpdate(monitor);
	}

	@Override
	public void load(DynamoRioFile file) {
		var row = new CoverageListRow(CoverageListState.ADDED, file);
		rows.add(row);
	}

	@Override
	public void update(TaskMonitor monitor) throws CancelledException, IOException {
		try {
			ranges = new HashSet<>();
			for (CoverageListRow row : rows) {
				var state = row.getState();
				if (state == CoverageListState.IGNORED) {
					continue;
				}

				var file = row.getFile();
				if (map.containsKey(file)) {
					continue;
				}

				var fileRanges = new HashSet<AddressRange>();
				var api = plugin.getApi();
				var programFileName = api.getCurrentProgram().getName();
				var md5 = api.getCurrentProgram().getExecutableMD5();
				var selectedModules = file.getModules().stream()
						.filter(m -> new File(m.getPath()).getName().equals(programFileName))
						.collect(Collectors.toList());

				var misMatch = selectedModules.stream().filter(m -> m.getChecksum() != null)
						.filter(m -> !m.getChecksum().equalsIgnoreCase(md5)).findFirst();
				if (misMatch.isPresent()) {
					var module = misMatch.get();
					throw new IOException(String.format("Module entry '%s' has invalid checksum '%s'", module.getPath(),
							module.getChecksum()));
				}

				Set<Integer> ids = selectedModules.stream().map(ModuleEntry::getId).collect(Collectors.toSet());

				var baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
				for (BlockEntry block : file.getBlocks()) {
					monitor.checkCanceled();
					if (!ids.contains(block.getModule())) {
						continue;
					}
					var start = baseAddress.add(block.getStart());
					AddressRange range = new AddressRangeImpl(start, block.getSize());
					fileRanges.add(range);
				}
				map.put(file, fileRanges);
			}

			var added = rows.stream().filter(r -> r.state == CoverageListState.ADDED).map(r -> map.get(r.file))
					.flatMap(HashSet::stream).collect(Collectors.toSet());

			var subtracted = rows.stream().filter(r -> r.state == CoverageListState.SUBTRACTED)
					.map(r -> map.get(r.file)).flatMap(HashSet::stream).collect(Collectors.toSet());

			added.removeAll(subtracted);
			ranges = added;

			notifyUpdate(monitor);
		} catch (AddressOverflowException e) {
			addException(e);
		}
	}

	public List<CoverageListRow> getFileData() {
		return rows;
	}

	@Override
	public Set<AddressRange> getModelData() {
		return ranges;
	}
}
