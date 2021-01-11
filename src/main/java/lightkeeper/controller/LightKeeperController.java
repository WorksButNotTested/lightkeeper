package lightkeeper.controller;

import java.awt.Color;
import java.io.File;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.LightKeeperCoverageModel;
import lightkeeper.model.LightKeeperCoverageModelRow;

public class LightKeeperController implements LightKeeperEventListener {
	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageModel model;	
	
	public LightKeeperController(LightKeeperPlugin plugin, LightKeeperCoverageModel model) {
		this.plugin = plugin;
		this.model = model;
	}
	
	public void goTo(int row) {
		CodeViewerService codeViewerService = plugin.getTool().getService(CodeViewerService.class);
		if (codeViewerService == null)
			return;
		
		LightKeeperCoverageModelRow modelRow = this.model.getModelData().get(row);
		long addr = modelRow.getAddress();
		
		FlatProgramAPI api = this.plugin.getApi();
		Program program = api.getCurrentProgram();
		 
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace addressSpace = addressFactory.getDefaultAddressSpace();
		Address address = addressSpace.getAddress(addr);		
		ProgramLocation programLocation = new ProgramLocation(program, address);
		codeViewerService.goTo(programLocation, true);
	}
	
	public void colour(Iterable<AddressRange> ranges) {			
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
			ranges.forEach(r -> colorService.setBackgroundColor(r.getMinAddress(), r.getMaxAddress(), Color.RED));
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
	
	public LightKeeperImportTask createImportTask(File file) {
		LightKeeperImportTask task = new LightKeeperImportTask(this, this.model, file);
		return task;
	}
}
