package lightkeeper.model;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.table.AbstractTableModel;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.ILightKeeperTaskEventListener;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.io.block.LightKeeperBlockEntry;
import lightkeeper.io.module.LightKeeperModuleEntry;

public class LightKeeperCoverageModel extends AbstractTableModel {
	
	public static class LightKeeperCoverageModelRow {
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
		
		public float getCoverage() {
			return (float)(this.instructionsHit * 100) / this.instructions;
		}
		
		public long getAddress() {
			return this.address;
		}
		
		public String getName() {
			return this.name;
		}
		
		public long getBlocks() {
			return this.blocks;
		}
		
		public long getBlocksHit() {
			return this.blocksHit;
		}
		
		public long getInstructions() {
			return this.instructions;
		}
		
		public long getInstructionsHit() {
			return this.instructionsHit;
		}
		
		public long getFunctionSize() {
			return this.functionSize;
		}
	}
	
	private String[] columnNames = {
		"Coverage %",
		"Function Name",
		"Address",
		"Blocks Hit",
		"Instructions Hit",
		"Function Size"
    };
	
	protected ArrayList<LightKeeperCoverageModelRow> rows = new ArrayList<LightKeeperCoverageModelRow>();	
	
	public void update(ILightKeeperTaskEventListener listener, TaskMonitor monitor, FlatProgramAPI api, LightKeeperFile file) throws CancelledException, IOException
	{
		monitor.checkCanceled();
		LightKeeperModuleEntry module = this.getModule(listener, monitor, api, file);
		monitor.checkCanceled();
		
		this.processEntries(listener, monitor, api, file, module);
		
		LightKeeperCoverageModelRow row = new LightKeeperCoverageModelRow("TEST", 0xdeadface, 10, 5, 200, 10, 123);
		rows.add(row);
		fireTableDataChanged();
	}
	
	public LightKeeperModuleEntry getModule (ILightKeeperTaskEventListener listener, TaskMonitor monitor, FlatProgramAPI api, LightKeeperFile file) throws CancelledException, IOException {
		File programFile = api.getProgramFile();
		String programFileName = programFile.getName();
		listener.addMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		monitor.setMessage(String.format("Searching for basic blocks for: %s", programFile.getPath()));
		
		ArrayList<LightKeeperModuleEntry> modules = file.getModules();
		for (int i = 0; i < modules.size(); i++)
		{
			monitor.checkCanceled();
			LightKeeperModuleEntry module = modules.get(i);
			File f = new File(module.getPath());
			String fileName = f.getName();
			if (fileName.equals(programFileName))
			{
				return module;
			}
		}
		throw new IOException(String.format("Failed to find matching module entry for '%s'", programFileName));
	}
	
	public void processEntries(ILightKeeperTaskEventListener listener, TaskMonitor monitor, FlatProgramAPI api, LightKeeperFile file, LightKeeperModuleEntry module) throws CancelledException, IOException {
		Address baseAddress = api.getCurrentProgram().getAddressMap().getImageBase();
		listener.addMessage(String.format("Base address: %x", baseAddress.getOffset()));
		
		ArrayList<LightKeeperBlockEntry> blocks = file.getBlocks();
		for (int i = 0; i < blocks.size(); i++)
		{
			monitor.checkCanceled();
			monitor.setMessage(String.format("Processing block %d / %d", i, blocks.size()));
			LightKeeperBlockEntry block = blocks.get(i);
			if (block.getModule() != module.getId())
				continue;
			
			if (block.getEnd() > module.getSize())
				throw new IOException(String.format("Block offset: %x greater than module size: %d", block.getEnd(), module.getSize()));
			
			Address addr = baseAddress.add(block.getStart());
			Function function = api.getFunctionContaining(addr);
			if (function == null) {
				listener.addMessage(String.format("No function found at: %x", addr.getOffset()));
			} else {
				listener.addMessage(String.format("Found function: '%s' at: %x", function.getName(), addr.getOffset()));
			}
		}
	}

	@Override
	public int getRowCount() {
		return rows.size();
	}

	@Override
	public int getColumnCount() { 
		return columnNames.length;
	}
	
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		LightKeeperCoverageModelRow row = rows.get(rowIndex);
		switch(columnIndex) {
			case 0:
				return String.format("%.2f", row.getCoverage());
			case 1:
				return String.format("%x", row.getAddress());
			case 2:
				return row.getName();
			case 3:
				return String.format("%d / %d", row.getBlocksHit(), row.getBlocks());
			case 4:
				return String.format("%d / %d", row.getInstructionsHit(), row.getInstructions());
			case 5:
				return row.getFunctionSize();
			default:
				throw new IndexOutOfBoundsException(String.format("Column index: %d out of range", columnIndex));
		}
	}
}
