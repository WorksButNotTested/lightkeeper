package lightkeeper.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;

public class LightKeeperFile {		
	private final String HEADER = "DRCOV VERSION: 2";
	private final Pattern FLAVOUR_REGEX = Pattern.compile("^DRCOV FLAVOR: (?<flavour>.*)$");
	private final Pattern TABLE_REGEX = Pattern.compile("^Module Table: (version (?<version>\\d+), count )?(?<count>\\d+)$");

	private String flavour;
	private int tableVersion;
	private int tableCount;
	
	private LightKeeperFile (File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {		
		FileInputStream stream = new FileInputStream(file);
		LightKeeperByteProvider provider = new LightKeeperByteProvider(stream, file.length());
		LightKeeperReader reader = new LightKeeperReader(provider);
		monitor.checkCanceled();
		
		monitor.setMessage("Reading header");
		String headerLine = reader.readLine();
		listener.addMessage(headerLine);		
		if (!headerLine.equals(HEADER))		
			throw new IOException(String.format("Invalid header: '%s' expected '%s'", headerLine, HEADER));			
		monitor.checkCanceled();
		
		monitor.setMessage("Reading flavour");
		String flavourLine = reader.readLine();
		listener.addMessage(flavourLine);
		Matcher flavourMatcher = FLAVOUR_REGEX.matcher(flavourLine);
		if (!flavourMatcher.matches())
			throw new IOException(String.format("Invalid flavour: '%s'", flavourLine));
		this.flavour = flavourMatcher.group("flavour");
		listener.addMessage(String.format("Detected flavour: %s", this.flavour));
		monitor.checkCanceled();
		
		monitor.setMessage("Reading table");
		String tableLine = reader.readLine();
		listener.addMessage(tableLine);
		Matcher tableMatcher = TABLE_REGEX.matcher(tableLine);
		if (!tableMatcher.matches())
			throw new IOException(String.format("Invalid table header: '%s'", tableLine));
		
		String version = tableMatcher.group("version");
		if (version == null)
			this.tableVersion = 1;
		else
			this.tableVersion = Integer.parseInt(version);
		
		listener.addMessage(String.format("Detected table version: %d", this.tableVersion));
		
		String count = tableMatcher.group("count");
		this.tableCount = Integer.parseInt(count);
		listener.addMessage(String.format("Detected table count: %d", this.tableCount));		
		monitor.checkCanceled();
	}
	
	public static LightKeeperFile read(File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {
		return new LightKeeperFile(file, listener, monitor);
	}	
}
