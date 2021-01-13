package lightkeeper.io.module;

public class ModuleEntry {
	protected int id;
	protected int containingId;
	protected long start;
	protected long end;
	protected long entry;
	protected long checksum;
	protected long timeStamp;
	protected String path;
	
	public ModuleEntry(int id, int containingId, long start, long end, long entry, long checksum, long timeStamp, String path){		
		this.id = id;
		this.containingId = containingId;
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
	
	public int getId() {
		return this.id;
	}
	
	public int getContainingId() {
		return this.containingId;
	}
	
	public long getStart() {
		return this.start;
	}
	
	public long getEnd() {
		return this.end;
	}
	
	public String getPath() {
		return this.path;
	}
}
