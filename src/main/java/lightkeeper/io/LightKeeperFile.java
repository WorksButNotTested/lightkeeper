package lightkeeper.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;

public class LightKeeperFile {		
	private final String HEADER = "DRCOV VERSION: 2";
	private final Pattern FLAVOUR_REGEX = Pattern.compile("^DRCOV FLAVOR: (?<flavour>.*)$");
	private final Pattern TABLE_REGEX = Pattern.compile("^Module Table: (version (?<version>\\d+), count )?(?<count>\\d+)$");
		
	ILightKeeperTaskEventListener listener;
	TaskMonitor monitor;
	LightKeeperReader reader;	

	private String flavour;
	private int tableVersion;
	private int tableCount;
	private ArrayList<LightKeeperModuleEntry> modules = new ArrayList<LightKeeperModuleEntry>();
	
	private LightKeeperFile (File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {
		this.listener = listener;
		this.monitor = monitor;
		FileInputStream stream = new FileInputStream(file);
		LightKeeperByteProvider provider = new LightKeeperByteProvider(stream, file.length());
		this.reader = new LightKeeperReader(provider);
				
		this.readHeader();
		this.readFlavour();
		this.readTable();		
		this.readModules();
	}
	
	private void readHeader() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		this.monitor.setMessage("Reading header");
		String headerLine = this.reader.readLine();
		listener.addMessage(headerLine);		
		if (!headerLine.equals(HEADER))		
			throw new IOException(String.format("Invalid header: '%s' expected '%s'", headerLine, HEADER));			
		this.monitor.checkCanceled();
	}
	
	private void readFlavour() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		this.monitor.setMessage("Reading flavour");
		String flavourLine = this.reader.readLine();
		listener.addMessage(flavourLine);
		Matcher flavourMatcher = FLAVOUR_REGEX.matcher(flavourLine);
		if (!flavourMatcher.matches())
			throw new IOException(String.format("Invalid flavour: '%s'", flavourLine));
		this.flavour = flavourMatcher.group("flavour");
		listener.addMessage(String.format("Detected flavour: %s", this.flavour));
		this.monitor.checkCanceled();
	}
	
	private void readTable() throws CancelledException, IOException {
		this.monitor.checkCanceled();
		this.monitor.setMessage("Reading table");
		String tableLine = reader.readLine();
		this.listener.addMessage(tableLine);
		Matcher tableMatcher = TABLE_REGEX.matcher(tableLine);
		if (!tableMatcher.matches())
			throw new IOException(String.format("Invalid table header: '%s'", tableLine));
		
		String version = tableMatcher.group("version");
		if (version == null)
			this.tableVersion = 1;
		else
			this.tableVersion = Integer.parseInt(version);
		
		this.listener.addMessage(String.format("Detected table version: %d", this.tableVersion));
			
		String count = tableMatcher.group("count");
		this.tableCount = Integer.parseInt(count);
		this.listener.addMessage(String.format("Detected table count: %d", this.tableCount));		
		this.monitor.checkCanceled();
	}
	
	private void readModules() throws CancelledException, IOException {
		LightKeeperModuleReader moduleReader = new LightKeeperModuleReader(this.listener, this.monitor, this.reader, this.tableVersion);
		for (int i = 0; i < tableCount; i++)
		{
			this.monitor.checkCanceled();
			this.monitor.setMessage(String.format("Reading module: %d", i));
			LightKeeperModuleEntry entry = moduleReader.read();
			modules.add(entry);
		}
	}
	
	public static LightKeeperFile read(File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {
		return new LightKeeperFile(file, listener, monitor);
	}	
}