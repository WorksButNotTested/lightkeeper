package lightkeeper.model;

import java.util.ArrayList;

import ghidra.program.model.address.AddressRange;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.LightKeeperFile;

public class LightKeeperCoverageFile {
	protected LightKeeperPlugin plugin;
	protected ArrayList<AddressRange> ranges = new ArrayList<AddressRange>();
	
	public LightKeeperCoverageFile(LightKeeperPlugin plugin) {
		this.plugin = plugin;
	}
	
	public void read(LightKeeperFile file) {
		
	}
	
	public ArrayList<AddressRange> getRanges() {
		return this.ranges;
	}
}
