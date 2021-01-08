package lightkeeper.view;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ConsoleService;
import ghidra.util.task.TaskLauncher;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperImportTask;
import resources.Icons;

public class LightKeeperImportAction extends DockingAction {
	protected LightKeeperPlugin plugin;
	protected LightKeeperProvider provider;
	
	public LightKeeperImportAction(LightKeeperPlugin plugin, LightKeeperProvider provider) {
		super("Import Coverage Data", plugin.getName());
		this.plugin = plugin;
		this.provider = provider;
		this.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		File f = LightKeeperFileChooser.selectFile(provider.getComponent());
		if (f == null) {
			return;
		}
		
		
		ConsoleService console = plugin.getTool().getService(ConsoleService.class);
		console.addMessage("Light Keeper", String.format("Importing File: %s", f.getAbsolutePath()));
		LightKeeperTaskEventListener listener = new LightKeeperTaskEventListener(console);
		LightKeeperImportTask task = new LightKeeperImportTask(this.plugin, this.provider.getModel(), f, listener);
		TaskLauncher.launch(task);
		console.addErrorMessage("Light Keeper", "Completed");
	}
}
