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
	protected long offset;
	protected long preferredBase;

	public ModuleEntry(int id, int containingId, long start, long end, long entry, long offset, long preferredBase, String checksum, long timeStamp,
			String path) {
		this.id = id;
		this.containingId = containingId;
		this.start = start;
		this.end = end;
		this.entry = entry;
		this.offset = offset;
		this.preferredBase = preferredBase;
		this.checksum = checksum;
		this.timeStamp = timeStamp;
		this.path = path;
	}

	@Override
	public String toString() {
		var str = String.format("id: %d, containintID: %d start: %x, end: %x, entry: %x, preferredBase: %x,  checksum: %s, timestamp: %x, path: %s", id,
				containingId, start, end, entry, preferredBase, checksum, timeStamp, path);
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
	
	public long getOffset() {
    return offset;
	}

	public long getPreferredBase() {
    return preferredBase;
	}
}
