package lightkeeper.model;

import java.util.Comparator;

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
	
	public static Comparator<LightKeeperCoverageModelRow> getComparer(int columnIndex) {
		switch(columnIndex) {
			case 0:
				return Comparator.comparingDouble(LightKeeperCoverageModelRow::getCoverage);
			case 1:
				return Comparator.comparingLong(LightKeeperCoverageModelRow::getAddress);
			case 2:
				return Comparator.comparing(LightKeeperCoverageModelRow::getName);
			case 3:			
				return Comparator.comparing(t -> t.getBlocks());
			case 4:
				return Comparator.comparing(t -> t.getInstructions());
			case 5:
				return Comparator.comparingLong(LightKeeperCoverageModelRow::getFunctionSize);
			default:
				throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
		
	}
}
