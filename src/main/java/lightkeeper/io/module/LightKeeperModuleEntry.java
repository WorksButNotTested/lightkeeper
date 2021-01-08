package lightkeeper.io.module;

public class LightKeeperModuleEntry {
	protected int id;
	protected long start;
	protected long end;
	protected long entry;
	protected long checksum;
	protected long timeStamp;
	protected String path;
	
	public LightKeeperModuleEntry(int id, long start, long end, long entry, long checksum, long timeStamp, String path){		
		this.id = id;
		this.start = start;
		this.end = end;
		this.entry = entry;
		this.checksum = checksum;
		this.timeStamp = timeStamp;
		this.path = path;
	}
	
	@Override
	public String toString() {
		String str = String.format("id: %d, start: %x, end: %x, entry: %x, checksum: %x, timestamp: %x, path: %s", id, start, end, entry, checksum, timeStamp, path);
		return str;
	}
}
