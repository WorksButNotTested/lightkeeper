package lightkeeper.model;

public class LightKeeperCoverageModelRow {
	protected String name;
	protected long address;
	protected LightKeeperFraction blocks;
	protected LightKeeperFraction instructions;
	protected long functionSize;
	
	
	public LightKeeperCoverageModelRow (String name, long address, LightKeeperFraction blocks, LightKeeperFraction instructions, long functionSize) {
		this.name = name;
		this.address = address;
		this.blocks = blocks;
		this.instructions = instructions;
		this.functionSize = functionSize;			
	}
	
	public double getCoverage() {
		return this.instructions.toPercentage();
	}
	
	public long getAddress() {
		return this.address;
	}
	
	public String getName() {
		return this.name;
	}
			
	public LightKeeperFraction getBlocks() {
		return this.blocks;
	}
	
	public LightKeeperFraction getInstructions() {
		return this.instructions;
	}
	
	public long getFunctionSize() {
		return this.functionSize;
	}
}