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
	
	public long getStart() {
		return this.start;
	}
	
	public int getSize() {
		return this.size;
	}
	
	public long getEnd() {
		return this.start + this.size;
	}
	
	public int getModule() {
		return this.module;
	}
	
	public boolean contains(long rangeStart, long rangeEnd) {
		if (rangeStart < this.getStart())
			return false;
		
		if (rangeEnd > this.getEnd())
			return false;
		
		return true;
	}
	
	@Override
    public boolean equals(Object o) {    
        if (o == this) { 
            return true; 
        } 
  
        if (!(o instanceof LightKeeperBlockEntry)) { 
            return false; 
        } 
            
        LightKeeperBlockEntry e = (LightKeeperBlockEntry) o; 
        if (e.getModule() != this.getModule())
        	return false;
        
        if (e.getStart() != this.getStart())
    		return false;
        
        return true; 
    } 
	
	@Override
    public int hashCode() {
		int hash = 17;
		hash = hash * 23 + Integer.valueOf(this.module).hashCode();
		hash = hash * 23 + Long.valueOf(this.start).hashCode();
		return hash;
	}
}
