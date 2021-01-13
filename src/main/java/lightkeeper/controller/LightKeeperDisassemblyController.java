package lightkeeper.controller;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangLayoutController;
import ghidra.app.decompiler.component.DecompilerHighlightService;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.LightKeeperCoverageModelListener;
import lightkeeper.model.instruction.LightKeeperCoverageInstructionModel;

@SuppressWarnings("deprecation")
public class LightKeeperDisassemblyController {
	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageInstructionModel model;	
	
	public LightKeeperDisassemblyController(LightKeeperPlugin plugin, LightKeeperCoverageInstructionModel model) {
		this.plugin = plugin;
		this.model = model;
		
		this.model.addModelListener(new LightKeeperCoverageModelListener() {
			@Override
			public void modelChanged(TaskMonitor monitor) throws CancelledException {
				instructionModelChanged(monitor);				
			}
		});			
	}
	
	public void instructionModelChanged(TaskMonitor monitor) throws CancelledException {
		DecompilerHighlightService highlightService = plugin.getTool().getService(DecompilerHighlightService.class);
		if (highlightService == null)
			return;
		
		ClangLayoutController controller = highlightService.getLayoutModel();
		controller.addLayoutModelListener(new LayoutModelListener() {
			
			@Override
			public void modelSizeChanged(IndexMapper indexMapper) {
				updatedModel(controller);				
			}
			
			@Override
			public void dataChanged(BigInteger start, BigInteger end) {
				updatedModel(controller);			
			}
		});
		
		updateCoverage(monitor, controller);
	}
		
	public void updateCoverage(TaskMonitor monitor, ClangLayoutController controller) throws CancelledException {			
		FlatProgramAPI api = plugin.getApi();
		if (api == null)
			return;
		
		Program program = api.getCurrentProgram();						
					
		for (ClangLine line: controller.getLines())
		{
			for (ClangToken token: line.getAllTokens())
			{
				monitor.checkCanceled();
				Address address = DecompilerUtils.getClosestAddress(program, token);
				if (address == null)
					continue;
				for (AddressRange range: model.getHits())
				{
					monitor.checkCanceled();
					if (!range.contains(address))
						continue;
					
					token.setHighlight(Color.GREEN);	
				}											
			}
		}					
	}
	
	public void updatedModel(ClangLayoutController controller) {
		Task task = new Task("Clear Coverage Data", true, true, true){
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				updateCoverage(monitor, controller);
			}
		};
		TaskLauncher.launch(task);
	}
}
