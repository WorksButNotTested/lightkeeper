package lightkeeper.io.module;

public class ModuleEntry {
	protected int id;
	protected int containingId;
	protected long start;
	protected long end;
	protected long entry;
	protected String checksum;
	protected long timeStamp;
	protected String path;

	public ModuleEntry(int id, int containingId, long start, long end, long entry, String checksum, long timeStamp, String path){
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
		var str = String.format("id: %d, start: %x, end: %x, entry: %x, checksum: %s, timestamp: %x, path: %s", id, start, end, entry, checksum, timeStamp, path);
		return str;
	}

	public int getId() {
		return id;
	}

	public int getContainingId() {
		return containingId;
	}

	public long getStart() {
		return start;
	}

	public long getEnd() {
		return end;
	}
	
	public String getChecksum() {
		return this.checksum;
	}

	public String getPath() {
		return path;
	}
}
