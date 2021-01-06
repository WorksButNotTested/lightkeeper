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
	private final Pattern FLAVOUR_REGEX = Pattern.compile("^DRCOV FLAVOR: (.*)$");
	
	private String flavour;
	
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
		Matcher matcher = FLAVOUR_REGEX.matcher(flavourLine);
		if (!matcher.matches())
			throw new IOException(String.format("Invalid flavour: '%s'", flavourLine));
		this.flavour = matcher.group(1);
		listener.addMessage(String.format("Detected flavour: %s", this.flavour));			
		monitor.checkCanceled();
	}
	
	public static LightKeeperFile read(File file, ILightKeeperTaskEventListener listener, TaskMonitor monitor) throws IOException, CancelledException {
		return new LightKeeperFile(file, listener, monitor);
	}	
}
