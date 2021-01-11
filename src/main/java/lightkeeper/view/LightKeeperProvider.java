package lightkeeper.view;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.GTable;
import docking.widgets.table.TableSortStateEditor;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.LightKeeperCoverageModel;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider implements TableModelListener {

	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageModel model;
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
		model = new LightKeeperCoverageModel();
		TableSortStateEditor sortStateEditor = new TableSortStateEditor();
		sortStateEditor.addSortedColumn(0);
		model.setTableSortState(sortStateEditor.createTableSortState());
		model.addTableModelListener(this);
		
		table = new GTable();
		table.setModel(model);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);		
		table.setUserSortingEnabled(true);		
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

	@Override
	public void tableChanged(TableModelEvent arg0) {
		this.table.repaint();		
		this.repaintColours();
	}
	
	protected void repaintColours() {
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
			this.model.getHits().forEach(r -> colorService.setBackgroundColor(r.getMinAddress(), r.getMaxAddress(), Color.RED));
			completed = true;
		} finally {
			program.endTransaction(transaction, completed);
		}	
	}
	
	public LightKeeperCoverageModel getModel() {
		return this.model;
	}
}
