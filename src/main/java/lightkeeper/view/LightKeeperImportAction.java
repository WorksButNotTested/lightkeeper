package lightkeeper.view;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.task.TaskLauncher;
import lightkeeper.controller.LightKeeperController;
import lightkeeper.controller.LightKeeperImportTask;
import resources.Icons;

public class LightKeeperImportAction extends DockingAction {
	protected LightKeeperController controller;
	protected LightKeeperProvider provider;
	
	public LightKeeperImportAction(LightKeeperController controller, LightKeeperProvider provider) {
		super("Import Coverage Data", "Light Keeper");
		this.controller = controller;
		this.provider = provider;
		this.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		File file = LightKeeperFileChooser.selectFile(provider.getComponent());
		if (file == null) {
			return;
		}
				
		LightKeeperImportTask task = controller.createImportTask(file);
		TaskLauncher.launch(task);		
	}
}
