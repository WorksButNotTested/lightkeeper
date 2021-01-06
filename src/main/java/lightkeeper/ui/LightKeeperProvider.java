package lightkeeper.ui;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.GTable;
import ghidra.util.Msg;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.data.LightKeeperModel;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider {

	protected LightKeeperPlugin plugin;
	protected LightKeeperModel model;
	protected GTable table;
	protected JPanel panel;

	public LightKeeperProvider(LightKeeperPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
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
		
		LightKeeperImportAction importAction = new LightKeeperImportAction (this.plugin, this);
		importAction.setEnabled(true);
		dockingTool.addLocalAction(this, importAction);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
