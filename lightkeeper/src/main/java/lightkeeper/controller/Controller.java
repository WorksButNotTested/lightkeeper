package lightkeeper.controller;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.io.file.DynamoRioFile;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.coverage.CoverageListRow;
import lightkeeper.model.coverage.CoverageListState;
import lightkeeper.model.coverage.CoverageModel;
import lightkeeper.model.instruction.CoverageInstructionModel;
import lightkeeper.model.table.CoverageTableModel;
import lightkeeper.model.table.CoverageTableRow;

public class Controller implements IEventListener, ICoverageModelListener {
	protected LightKeeperPlugin plugin;
	protected CoverageModel model;
	protected CoverageTableModel tableModel;
	protected CoverageInstructionModel instructionModel;

	public Controller(LightKeeperPlugin plugin, CoverageModel model, CoverageTableModel tableModel,
			CoverageInstructionModel instructionModel) {
		this.plugin = plugin;
		this.model = model;
		this.tableModel = tableModel;
		this.instructionModel = instructionModel;
	}

	public void goTo(CoverageTableRow row) {
		var codeViewerService = plugin.getTool().getService(CodeViewerService.class);
		if (codeViewerService == null) {
			return;
		}

		var addr = row.getAddress();

		var api = plugin.getApi();
		var program = api.getCurrentProgram();

		var addressFactory = program.getAddressFactory();
		var addressSpace = addressFactory.getDefaultAddressSpace();
		var address = addressSpace.getAddress(addr);
		var programLocation = new ProgramLocation(program, address);
		codeViewerService.goTo(programLocation, true);
	}

	public void colour(TaskMonitor monitor) throws CancelledException {
		var colorService = plugin.getTool().getService(ColorizingService.class);
		if (colorService == null) {
			return;
		}

		var completed = false;
		var api = plugin.getApi();
		if (api == null) {
			return;
		}

		var program = api.getCurrentProgram();
		var transaction = program.startTransaction("Light Keeper");
		try {
			colorService.clearAllBackgroundColors();
			for (AddressRange range : instructionModel.getModelData()) {
				monitor.checkCancelled();
				var min = range.getMinAddress();
				var max = range.getMaxAddress();
				colorService.setBackgroundColor(min, max, Color.GREEN);
			}
			completed = true;
		} finally {
			program.endTransaction(transaction, completed);
		}
	}

	@Override
	public void addMessage(String message) {
		Swing.runLater(() -> {
			var consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null) {
				return;
			}

			consoleService.addMessage("Light Keeper", message);
		});
	}

	@Override
	public void addErrorMessage(String message) {
		Swing.runLater(() -> {
			var consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null) {
				return;
			}

			consoleService.addErrorMessage("Light Keeper", message);
		});
	}

	@Override
	public void addException(Exception exc) {
		Swing.runLater(() -> {
			var consoleService = plugin.getTool().getService(ConsoleService.class);
			if (consoleService == null) {
				return;
			}

			consoleService.addException("Light Keeper", exc);
		});
	}

	public void importCoverage(TaskMonitor monitor, List<File> files) throws CancelledException {
		monitor.checkCancelled();
		try {
			for (File file : files) {
				monitor.setMessage(String.format("Importing: %s", file.getAbsolutePath()));
				addMessage(String.format("Importing: %s", file.getAbsolutePath()));
				monitor.setProgress(0);

				var dataFile = new DynamoRioFile(file);

				dataFile.addListener(this);
				dataFile.read(monitor);

				addMessage(String.format("Imported: %s", file.getAbsolutePath()));
				model.load(dataFile);
			}

			model.update(monitor);
			addMessage("Completed");
			monitor.setProgress(100);
		} catch (IOException e) {
			this.addException(e);
		}
	}

	public void clearCoverage(TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		monitor.setMessage("Clearing");
		addMessage("Clearing");
		monitor.setProgress(0);
		model.clear(monitor);
		addMessage("Completed");
		monitor.setProgress(100);
	}

	public void refreshCoverage(TaskMonitor monitor) throws CancelledException {
		try {
			monitor.checkCancelled();
			monitor.setMessage("Refreshing");
			addMessage("Refreshing");
			monitor.setProgress(0);
			model.update(monitor);
			addMessage("Completed");
			monitor.setProgress(100);
		} catch (IOException e) {
			this.addException(e);
		}
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		colour(monitor);
	}

	public void toggleCoverageFiles(TaskMonitor monitor, List<Integer> rows) throws CancelledException {
		try {
			for (int row : rows) {
				model.getFileData().get(row).toggle();
			}
			model.update(monitor);
		} catch (IOException e) {
			this.addException(e);
		}
	}

	public void setCoverageFiles(TaskMonitor monitor, List<Integer> rows, CoverageListState state)
			throws CancelledException {
		boolean changed = false;
		try {
			for (int row : rows) {
				CoverageListRow listRow = model.getFileData().get(row);
				if (listRow.getState() != state) {
					listRow.setState(state);
					changed = true;
				}
			}

			if (changed)
				model.update(monitor);
		} catch (IOException e) {
			this.addException(e);
		}
	}

}
