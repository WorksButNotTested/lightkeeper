package lightkeeper.io.block;

public class BlockEntry {
	protected long start;
	protected int size;
	protected int module;

	public BlockEntry(long start, int size, int module) {
		this.start = start;
		this.size = size;
		this.module = module;
	}

	@Override
	public String toString() {
		var str = String.format("start: %x, size: %d, module: %d", start, size, module);
		return str;
	}

	public long getStart() {
		return start;
	}

	public int getSize() {
		return size;
	}

	public long getEnd() {
		return start + size;
	}

	public int getModule() {
		return module;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}

		if (!(o instanceof BlockEntry)) {
			return false;
		}

		var e = (BlockEntry) o;
		if (e.getModule() != getModule()) {
			return false;
		}

		if (e.getStart() != getStart()) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		var hash = 17;
		hash = hash * 23 + Integer.valueOf(module).hashCode();
		hash = hash * 23 + Long.valueOf(start).hashCode();
		return hash;
	}
}
