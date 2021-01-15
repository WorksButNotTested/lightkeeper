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
import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.instruction.CoverageInstructionModel;

@SuppressWarnings("deprecation")
public class DisassemblyController implements ICoverageModelListener{
	protected LightKeeperPlugin plugin;
	protected CoverageInstructionModel model;

	public DisassemblyController(LightKeeperPlugin plugin, CoverageInstructionModel model) {
		this.plugin = plugin;
		this.model = model;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		var highlightService = plugin.getTool().getService(DecompilerHighlightService.class);
		if (highlightService == null) {
			return;
		}

		var controller = highlightService.getLayoutModel();
		controller.addLayoutModelListener(new LayoutModelListener() {

			@Override
			public void modelSizeChanged(IndexMapper indexMapper) {
				updateCoverageTask(controller);
			}

			@Override
			public void dataChanged(BigInteger start, BigInteger end) {
				updateCoverageTask(controller);
			}
		});

		updateCoverage(monitor, controller);
	}

	public void updateCoverage(TaskMonitor monitor, ClangLayoutController controller) throws CancelledException {
		var api = plugin.getApi();
		if (api == null) {
			return;
		}

		var program = api.getCurrentProgram();

		for (ClangLine line: controller.getLines())
		{
			for (ClangToken token: line.getAllTokens())
			{
				monitor.checkCanceled();
				var address = DecompilerUtils.getClosestAddress(program, token);
				if (address == null) {
					continue;
				}
				for (AddressRange range: model.getModelData())
				{
					monitor.checkCanceled();
					if (!range.contains(address)) {
						continue;
					}

					token.setHighlight(Color.YELLOW);
				}
			}
		}
	}

	public void updateCoverageTask(ClangLayoutController controller) {
		Task task = new Task("Clear Coverage Data", true, true, true){
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				updateCoverage(monitor, controller);
			}
		};
		TaskLauncher.launch(task);
	}
}
