package lightkeeper.model.table;

public class CoverageTableRow {
	protected String name;
	protected long address;
	protected CoverageFraction blocks;
	protected CoverageFraction instructions;
	protected long functionSize;
	
	
	public CoverageTableRow (String name, long address, CoverageFraction blocks, CoverageFraction instructions, long functionSize) {
		this.name = name;
		this.address = address;
		this.blocks = blocks;
		this.instructions = instructions;
		this.functionSize = functionSize;			
	}
	
	public CoveragePercentage getCoverage() {
		return new CoveragePercentage(this.instructions);
	}
	
	public long getAddress() {
		return this.address;
	}
	
	public String getName() {
		return this.name;
	}
			
	public CoverageFraction getBlocks() {
		return this.blocks;
	}
	
	public CoverageFraction getInstructions() {
		return this.instructions;
	}
	
	public long getFunctionSize() {
		return this.functionSize;
	}
}
