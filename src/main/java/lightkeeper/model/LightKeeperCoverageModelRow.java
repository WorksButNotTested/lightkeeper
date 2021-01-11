package lightkeeper.model;

public class LightKeeperCoverageModelRow {
	protected String name;
	protected long address;
	protected long blocks;
	protected long blocksHit;
	protected long instructions;
	protected long instructionsHit;
	protected long functionSize;
	
	
	public LightKeeperCoverageModelRow (String name, long address, long blocks, long blocksHit, long instructions, long instructionsHit, long functionSize) {
		this.name = name;
		this.address = address;
		this.blocks = blocks;
		this.blocksHit = blocksHit;
		this.instructions = instructions;
		this.instructionsHit = instructionsHit;
		this.functionSize = functionSize;			
	}
	
	public double getCoverage() {
		if (instructions == 0)
			return 0;
		return (double)(this.instructionsHit * 100) / this.instructions;
	}
	
	public long getAddress() {
		return this.address;
	}
	
	public String getName() {
		return this.name;
	}
			
	public LightKeeperFraction getBlocks() {
		return new LightKeeperFraction(this.blocksHit, this.blocks);
	}
	
	public LightKeeperFraction getInstructions() {
		return new LightKeeperFraction(this.instructionsHit, this.instructions);
	}
	
	public long getFunctionSize() {
		return this.functionSize;
	}
}
