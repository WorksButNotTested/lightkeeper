package lightkeeper.controller;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.instruction.CoverageInstructionModel;

public class DisassemblyController implements ICoverageModelListener {
	protected LightKeeperPlugin plugin;
	protected CoverageInstructionModel model;

	public DisassemblyController(LightKeeperPlugin plugin, CoverageInstructionModel model) {
		this.plugin = plugin;
		this.model = model;
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {

		DecompilerProvider dprov = (DecompilerProvider) plugin.getTool().getComponentProvider("Decompiler");
		if (dprov != null) {
			DecompilerActionContext context = (DecompilerActionContext) dprov.getActionContext(null);
			if (context != null) {
				DecompilerPanel dpanel = context.getDecompilerPanel();
				LayoutModel controller = dpanel.getFieldPanel().getLayoutModel();
				controller.addLayoutModelListener(new LayoutModelListener() {

					@Override
					public void modelSizeChanged(IndexMapper indexMapper) {
						updateCoverageTask(dpanel);
					}

					@Override
					public void dataChanged(BigInteger start, BigInteger end) {
						updateCoverageTask(dpanel);
					}
				});
				updateCoverage(monitor, dpanel);
			}
		}
	}

	public void updateCoverage(TaskMonitor monitor, DecompilerPanel dpanel) throws CancelledException {
		var api = plugin.getApi();
		if (api == null) {
			return;
		}

		var program = api.getCurrentProgram();

		for (ClangLine line : dpanel.getLines()) {
			for (ClangToken token : line.getAllTokens()) {
				monitor.checkCancelled();
				var address = DecompilerUtils.getClosestAddress(program, token);
				if (address == null) {
					continue;
				}
				for (AddressRange range : model.getModelData()) {
					monitor.checkCancelled();
					if (!range.contains(address)) {
						continue;
					}

					token.setHighlight(Color.GREEN);
				}
			}
		}
	}

	public void updateCoverageTask(DecompilerPanel dpanel) {
		Task task = new Task("Clear Coverage Data", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				updateCoverage(monitor, dpanel);
			}
		};
		TaskLauncher.launch(task);
	}
}
