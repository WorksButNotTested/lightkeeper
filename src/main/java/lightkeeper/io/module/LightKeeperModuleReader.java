package lightkeeper.io.module;

import java.io.IOException;
import java.util.ArrayList;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;
import lightkeeper.io.LightKeeperReader;

public class LightKeeperModuleReader {
	protected final String COLUMN_2_HDR_WIN = "Columns: id, base, end, entry, checksum, timestamp, path";
	protected final Pattern COLUMN_2_HDR_WIN_FMT = Pattern.compile("^\\s*(?<id>\\d+), (?<start>[0-9a-fA-F]+), (?<end>[0-9a-fA-F]+), (?<entry>[0-9a-fA-F]+), (?<checksum>[0-9a-fA-F]+), (?<timestamp>[0-9a-fA-F]+), (?<path>.+)$");
	
	protected final String COLUMN_2_HDR_LINUX = "Columns: id, base, end, entry, path";
	protected final Pattern COLUMN_2_HDR_LINUX_FMT = null;
	
	protected final String COLUMN_3_HDR_WIN = "Columns: id, containing_id, start, end, entry, checksum, timestamp, path";
	protected final Pattern COLUMN_3_HDR_WIN_FMT = null;
	
	protected final String COLUMN_3_HDR_LINUX = "Columns: id, containing_id, start, end, entry, path";
	protected final Pattern COLUMN_3_HDR_LINUX_FMT = null;
	
	
	protected final String COLUMN_4_HDR_WIN = "Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path";
	protected final Pattern COLUMN_4_HDR_WIN_FMT = null;
	
	protected final String COLUMN_4_HDR_LINUX = "Columns: id, containing_id, start, end, entry, offset, path";
	protected final Pattern COLUMN_4_HDR_LINUX_FMT = null;
	
	protected ILightKeeperTaskEventListener listener;
	protected TaskMonitor monitor;
	protected LightKeeperReader reader;
	protected String columnHeader;
	protected final ArrayList<ModuleTriplet> formats = new ArrayList<ModuleTriplet>();
	protected Pattern selectedPattern;
	
	private static class ModuleTriplet
	{
		protected int version;
		protected String header;
		protected Pattern regex;
		
		public ModuleTriplet (int version, String header, Pattern regex) {
			this.version = version;
			this.header = header;
			this.regex = regex;			
		}
	}
	
	public LightKeeperModuleReader(ILightKeeperTaskEventListener listener, TaskMonitor monitor, LightKeeperReader reader, int tableVersion) throws CancelledException, IOException {
		this.listener = listener;
		this.monitor = monitor;
		this.reader = reader;
		
		formats.add(new ModuleTriplet (2, COLUMN_2_HDR_WIN, COLUMN_2_HDR_WIN_FMT));
		formats.add(new ModuleTriplet (2, COLUMN_2_HDR_LINUX, COLUMN_2_HDR_LINUX_FMT));
		formats.add(new ModuleTriplet (2, COLUMN_3_HDR_WIN, COLUMN_3_HDR_WIN_FMT));
		formats.add(new ModuleTriplet (2, COLUMN_3_HDR_LINUX, COLUMN_3_HDR_LINUX_FMT));
		formats.add(new ModuleTriplet (2, COLUMN_4_HDR_WIN, COLUMN_4_HDR_WIN_FMT));
		formats.add(new ModuleTriplet (2, COLUMN_4_HDR_LINUX, COLUMN_4_HDR_LINUX_FMT));
		
		this.readColumnHeader();
		
		formats.removeIf(t -> t.version != tableVersion);
		formats.removeIf(t -> !t.header.equals(this.columnHeader));
		
		if (formats.size() != 1)
			throw new IOException(String.format("Failed to find valid header: '%s' for version: %d", this.columnHeader, tableVersion));
		
		this.selectedPattern = formats.get(0).regex;
		if (this.selectedPattern == null)
			throw new IOException (String.format("Unsupported pattern: '%s'", formats.get(0).header));
	}
	
	private void readColumnHeader() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		this.monitor.setMessage("Reading Column Header");
		this.columnHeader = this.reader.readLine();
		this.listener.addMessage(columnHeader);
	}	
	
	public LightKeeperModuleEntry read() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		String moduleLine = this.reader.readLine();
		listener.addMessage(moduleLine);
		Matcher moduleMatcher = this.selectedPattern.matcher(moduleLine);
		if (!moduleMatcher.matches())
			throw new IOException(String.format("Invalid module: '%s'", moduleMatcher));
		String idString = moduleMatcher.group("id");
		int id = parseNumber(idString, Integer::parseInt, String.format("Invalid id: %s", idString));
		String startString = moduleMatcher.group("start");
		long start = parseNumber(startString, (s) -> Long.parseLong(s, 16), String.format("Invalid start: %s", startString));
		String endString = moduleMatcher.group("end");
		long end = parseNumber(endString, (s) -> Long.parseLong(s, 16), String.format("Invalid start: %s", endString));
		String entryString = moduleMatcher.group("entry");
		long entry = parseNumber(entryString, (s) -> Long.parseLong(s, 16), String.format("Invalid entry: %s", entryString));
		String checksumString = moduleMatcher.group("checksum");
		long checksum = parseNumber(checksumString, (s) -> Long.parseLong(s, 16), String.format("Invalid checksum: %s", checksumString));
		String timeStampString = moduleMatcher.group("timestamp");
		long timeStamp = parseNumber(timeStampString, (s) -> Long.parseLong(s, 16), String.format("Invalid time stamp: %s", timeStampString));
		String pathString = moduleMatcher.group("path");
		LightKeeperModuleEntry module = new LightKeeperModuleEntry(id, start, end, entry, checksum, timeStamp, pathString);
		listener.addMessage(String.format("Read Module: %s", module));
		this.monitor.checkCanceled();
		return module;		
	}
	
	private <T> T parseNumber(String numberString, Function<String, T> convert, String failMessage) throws IOException {
		try {
			T result = convert.apply(numberString);
			return result;
		} catch (NumberFormatException e) {
			throw new IOException(failMessage, e);
		}
	}
}
