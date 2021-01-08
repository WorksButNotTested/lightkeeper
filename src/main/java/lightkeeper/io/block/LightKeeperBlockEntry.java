package lightkeeper.io.block;

public class LightKeeperBlockEntry {
	protected long start;
	protected int size;
	protected int module;
	
	public LightKeeperBlockEntry(long start, int size, int module) {
		this.start = start;
		this.size = size;
		this.module = module;
	}
	
	@Override
	public String toString() {
		String str = String.format("start: %x, size: %d, module: %d", this.start, this.size, this.module);
		return str;
	}
}
