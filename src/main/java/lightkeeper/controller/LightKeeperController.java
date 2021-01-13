package lightkeeper.controller;

import java.awt.Color;
import java.io.File;
import java.io.IOException;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.LightKeeperFile;
import lightkeeper.model.LightKeeperCoverageRangeCollection;
import lightkeeper.model.instruction.LightKeeperCoverageInstructionModel;
import lightkeeper.model.instruction.LightKeeperCoverageInstructionModelListener;
import lightkeeper.model.table.LightKeeperCoverageTableModel;
import lightkeeper.model.table.LightKeeperCoverageTableModelRow;

public class LightKeeperController implements LightKeeperEventListener {
	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageTableModel tableModel;	
	protected LightKeeperCoverageInstructionModel instructionModel;
	
	public LightKeeperController(LightKeeperPlugin plugin, LightKeeperCoverageTableModel tableModel, LightKeeperCoverageInstructionModel instructionModel) {
		this.plugin = plugin;
		this.tableModel = tableModel;
		this.instructionModel = instructionModel;
		this.instructionModel.addInstructionModelListener(new LightKeeperCoverageInstructionModelListener() {
			@Override
			public void instructionsChanged() {
				Task task = new Task("Clear Coverage Data", true, true, true){
					@Override
					public void run(TaskMonitor monitor) throws CancelledException {
						colour(monitor);
					}
				};
				TaskLauncher.launch(task);
			}
		});
	}
	
	public void goTo(int row) {
		CodeViewerService codeViewerService = plugin.getTool().getService(CodeViewerService.class);
		if (codeViewerService == null)
			return;
		
		LightKeeperCoverageTableModelRow modelRow = this.tableModel.getModelData().get(row);
		long addr = modelRow.getAddress();
		
		FlatProgramAPI api = this.plugin.getApi();
		Program program = api.getCurrentProgram();
		 
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace addressSpace = addressFactory.getDefaultAddressSpace();
		Address address = addressSpace.getAddress(addr);		
		ProgramLocation programLocation = new ProgramLocation(program, address);
		codeViewerService.goTo(programLocation, true);
	}
	
	public void colour(TaskMonitor monitor) throws CancelledException {
		ColorizingService colorService = plugin.getTool().getService(ColorizingService.class);
		if (colorService == null)
			return;
		
		boolean completed = false;
		FlatProgramAPI api = plugin.getApi();
		if (api == null)
			return;
		
		Program program = api.getCurrentProgram();		
		int transaction = program.startTransaction("Light Keeper");
		try {
			colorService.clearAllBackgroundColors();
			for (AddressRange range: instructionModel.getHits())
			{
				monitor.checkCanceled();
				Address min = range.getMinAddress();
				Address max = range.getMaxAddress();
				colorService.setBackgroundColor(min, max, Color.GREEN);
			}			
			completed = true;
		} finally {
			program.endTransaction(transaction, completed);
		}	
	}	
	
	public void addMessage(String message) {
		Swing.runLater(() -> {
			ConsoleService consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null)
				return;
			
			consoleService.addMessage("Light Keeper", message);
		});
	}
	
	public void addErrorMessage(String message) {
		Swing.runLater(() -> {
			ConsoleService consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null)
				return;
			
			consoleService.addErrorMessage("Light Keeper", message);
		});
	}
		
	public void addException(Exception exc) {
		Swing.runLater(() -> {
			ConsoleService consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null)
				return;
			
			consoleService.addException("Light Keeper", exc);
		});
	}
	
	public void importCoverage(TaskMonitor monitor, File file) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage(String.format("Importing: %s",file.getAbsolutePath()));
		this.addMessage(String.format("Importing: %s",file.getAbsolutePath()));
		try {			
			monitor.setProgress(0);
			
			LightKeeperFile dataFile = new LightKeeperFile(file);
			dataFile.addListener(this);
			dataFile.read(monitor);
			
			LightKeeperCoverageRangeCollection coverageFile = new LightKeeperCoverageRangeCollection(plugin);
			coverageFile.read(monitor, dataFile);
			
			this.addMessage(String.format("Imported: %s",file.getAbsolutePath()));
			this.tableModel.load(coverageFile);
			this.tableModel.update(monitor);
			this.instructionModel.load(coverageFile);
			this.instructionModel.update(monitor);
			this.addMessage("Completed");
			monitor.setProgress(100);
		} catch (IOException e) {
			this.addException(e);
		} catch (AddressOverflowException e) {
			this.addException(e);
		}
	}
	
	public void clearCoverage(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Clearing");
		this.addMessage("Clearing");		
		monitor.setProgress(0);
		this.tableModel.clear();
		this.instructionModel.clear();
		this.addMessage("Completed");
		monitor.setProgress(100);
	}
	
	public void refreshCoverage(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Refreshing");
		this.addMessage("Refreshing");
		monitor.setProgress(0);
		this.tableModel.update(monitor);	
		this.instructionModel.update(monitor);	
		this.addMessage("Completed");
		monitor.setProgress(100);
	}	
}
