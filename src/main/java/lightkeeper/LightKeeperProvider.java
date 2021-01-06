package lightkeeper;

import java.awt.BorderLayout;
import java.io.File;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import resources.Icons;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider {

	private LightKeeperModel model;
	private GTable table;
	private JPanel panel;

	public LightKeeperProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		buildPanel();
		createActions();
		setIcon(ResourceManager.loadImage("images/lighthouse.png"));
	}

	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		model = new LightKeeperModel();
		table = new GTable();
		table.setModel(model);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		panel.add(new JScrollPane(table));
		setVisible(true);
	}

	private void createActions() {
		DockingAction aboutAction = new DockingAction("About", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "About", "Light Keeper");
			}
		};
		aboutAction.setMenuBarData(
				new MenuData(new String[] {"About"},null,null));
		
		dockingTool.addLocalAction(this, aboutAction);
		
		DockingAction importAction = new DockingAction("Import coverage data",getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				LightKeeperProvider provider = (LightKeeperProvider)context.getComponentProvider();
				provider.importCoverage();
			}
		};
		
		importAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		dockingTool.addLocalAction(this, importAction);
		importAction.setEnabled(true);
	}
	
	private void importCoverage() {
		File f = LightKeeperFileChooser.selectFile(panel);
		if (f == null)
		{
			return;
		}
		System.out.println("Importing File: " + f.getAbsolutePath());
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
