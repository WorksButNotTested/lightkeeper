package lightkeeper;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
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
		boolean commit = false;
		int transaction = plugin.program.startTransaction("Create Plate Comments");
		try {
			File f = LightKeeperFileChooser.selectFile(provider.getComponent());
			if (f == null)
			{
				return;
			}
			System.out.println("Importing File: " + f.getAbsolutePath());
			commit = true;
		}
		finally {
			plugin.program.endTransaction(transaction, commit);	
		}
	}
}
