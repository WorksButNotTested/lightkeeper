package lightkeeper.io.module;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.controller.IEventListener;
import lightkeeper.io.BinaryLineReader;

public class ModuleReader {
	// Columns: id, containing_id, start, end, entry, offset, path
	protected final String COLUMN_2_HDR_WIN = "Columns: id, base, end, entry, checksum, timestamp, path";
	protected final Pattern COLUMN_2_HDR_WIN_FMT = Pattern.compile(
			"^\\s*(?<id>\\d+), (0x)?(?<start>[0-9a-fA-F]+), (0x)?(?<end>[0-9a-fA-F]+), (0x)?(?<entry>[0-9a-fA-F]+), (0x)?(?<checksum>[0-9a-fA-F]+), (0x)?(?<timestamp>[0-9a-fA-F]+), (?<path>.+)$");

	protected final String COLUMN_2_HDR_LINUX = "Columns: id, base, end, entry, path";
	protected final Pattern COLUMN_2_HDR_LINUX_FMT = Pattern.compile(
			"^\\s*(?<id>\\d+), (0x)?(?<start>[0-9a-fA-F]+), (0x)?(?<end>[0-9a-fA-F]+), (0x)?(?<entry>[0-9a-fA-F]+), (?<path>.+)$");

	protected final String COLUMN_3_HDR_WIN = "Columns: id, containing_id, start, end, entry, checksum, timestamp, path";
	protected final Pattern COLUMN_3_HDR_WIN_FMT = null;

	protected final String COLUMN_3_HDR_LINUX = "Columns: id, containing_id, start, end, entry, path";
	protected final Pattern COLUMN_3_HDR_LINUX_FMT = null;

	protected final String COLUMN_4_HDR_WIN = "Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path";
	protected final Pattern COLUMN_4_HDR_WIN_FMT = null;

	protected final String COLUMN_4_HDR_LINUX = "Columns: id, containing_id, start, end, entry, offset, path";
	protected final Pattern COLUMN_4_HDR_LINUX_FMT = Pattern.compile(
			"^\\s*(?<id>\\d+), \\s*(?<containingid>\\d+), (0x)?(?<start>[0-9a-fA-F]+), (0x)?(?<end>[0-9a-fA-F]+), (0x)?(?<entry>[0-9a-fA-F]+), (0x)?(?<offset>[0-9a-fA-F]+), (?<path>.+)$");

	protected final Pattern NULL_CHECKSUM = Pattern.compile("0+");

	private List<IEventListener> listeners = new ArrayList<>();
	protected TaskMonitor monitor;
	protected BinaryLineReader reader;
	protected String columnHeader;
	protected final ArrayList<ModuleTriplet> formats = new ArrayList<>();
	protected ModuleTriplet selectedModuleTriplet;

	private static class ModuleTriplet {
		protected int version;
		protected String header;
		protected Pattern regex;
		protected boolean hasContainingId;
		protected boolean hasChecksumTimeStamp;

		public ModuleTriplet(int version, String header, Pattern regex, boolean hasContainingId,
				boolean hasChecksumTimeStamp) {
			this.version = version;
			this.header = header;
			this.regex = regex;
			this.hasContainingId = hasContainingId;
			this.hasChecksumTimeStamp = hasChecksumTimeStamp;
		}
	}

	public ModuleReader(TaskMonitor monitor, BinaryLineReader reader, int tableVersion)
			throws CancelledException, IOException {
		this.monitor = monitor;
		this.reader = reader;

		formats.add(new ModuleTriplet(2, COLUMN_2_HDR_WIN, COLUMN_2_HDR_WIN_FMT, false, true));
		formats.add(new ModuleTriplet(2, COLUMN_2_HDR_LINUX, COLUMN_2_HDR_LINUX_FMT, false, false));
		formats.add(new ModuleTriplet(3, COLUMN_3_HDR_WIN, COLUMN_3_HDR_WIN_FMT, true, true));
		formats.add(new ModuleTriplet(3, COLUMN_3_HDR_LINUX, COLUMN_3_HDR_LINUX_FMT, true, false));
		formats.add(new ModuleTriplet(4, COLUMN_4_HDR_WIN, COLUMN_4_HDR_WIN_FMT, true, true));
		formats.add(new ModuleTriplet(4, COLUMN_4_HDR_LINUX, COLUMN_4_HDR_LINUX_FMT, true, false));

		readColumnHeader();

		formats.removeIf(t -> t.version != tableVersion);
		formats.removeIf(t -> !t.header.equals(columnHeader));

		if (formats.size() != 1) {
			throw new IOException(
					String.format("Failed to find valid header: '%s' for version: %d", columnHeader, tableVersion));
		}

		selectedModuleTriplet = formats.get(0);
		if (selectedModuleTriplet.regex == null) {
			throw new IOException(String.format("Unsupported pattern: '%s'", formats.get(0).header));
		}
	}

	public void addListener(IEventListener listener) {
		listeners.add(listener);
	}

	protected void addMessage(String message) {
		listeners.forEach(l -> l.addMessage(message));
	}

	private void readColumnHeader() throws CancelledException, IOException {
		monitor.checkCancelled();
		monitor.setMessage("Reading Column Header");
		columnHeader = reader.readLine();
		addMessage(columnHeader);
	}

	public ModuleEntry read() throws CancelledException, IOException {
		monitor.checkCancelled();
		var moduleLine = reader.readLine();
		addMessage(moduleLine);

		var moduleMatcher = selectedModuleTriplet.regex.matcher(moduleLine);
		if (!moduleMatcher.matches()) {
			throw new IOException(String.format("Invalid module: '%s'", moduleMatcher));
		}

		var idString = moduleMatcher.group("id");
		int id = parseNumber(idString, Integer::parseInt, String.format("Invalid id: %s", idString));

		var containingId = id;
		if (selectedModuleTriplet.hasContainingId) {
			var containingIdString = moduleMatcher.group("containingid");
			containingId = parseNumber(containingIdString, Integer::parseInt,
					String.format("Invalid containing_id: %s", containingIdString));
		}

		var startString = moduleMatcher.group("start");
		long start = parseNumber(startString, s -> Long.parseLong(s, 16),
				String.format("Invalid start: %s", startString));

		var endString = moduleMatcher.group("end");
		long end = parseNumber(endString, s -> Long.parseLong(s, 16), String.format("Invalid start: %s", endString));

		var entryString = moduleMatcher.group("entry");
		long entry = parseNumber(entryString, s -> Long.parseLong(s, 16),
				String.format("Invalid entry: %s", entryString));

		String checksum = null;
		var timeStamp = 0L;
		if (selectedModuleTriplet.hasChecksumTimeStamp) {
			String checkSumField = moduleMatcher.group("checksum");
			if (!NULL_CHECKSUM.matcher(checkSumField).matches())
				checksum = moduleMatcher.group("checksum");

			var timeStampString = moduleMatcher.group("timestamp");
			timeStamp = parseNumber(timeStampString, s -> Long.parseLong(s, 16),
					String.format("Invalid time stamp: %s", timeStampString));
		}

		var pathString = moduleMatcher.group("path");

		var module = new ModuleEntry(id, containingId, start, end, entry, checksum, timeStamp, pathString);
		addMessage(String.format("Read Module: %s", module));
		monitor.checkCancelled();
		return module;
	}

	private <T> T parseNumber(String numberString, Function<String, T> convert, String failMessage) throws IOException {
		try {
			var result = convert.apply(numberString);
			return result;
		} catch (NumberFormatException e) {
			throw new IOException(failMessage, e);
		}
	}
}
