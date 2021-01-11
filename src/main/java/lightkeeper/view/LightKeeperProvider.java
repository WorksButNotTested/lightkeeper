package lightkeeper.view;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

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
import ghidra.util.Msg;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperController;
import lightkeeper.model.LightKeeperCoverageModel;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider implements TableModelListener {

	protected LightKeeperPlugin plugin;
	protected LightKeeperCoverageModel model;
	protected LightKeeperController controller;
	protected GTable table;
	protected JPanel panel;

	public LightKeeperProvider(LightKeeperPlugin plugin, LightKeeperController controller, LightKeeperCoverageModel model, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		this.controller = controller;
		this.model = model;		
		buildPanel();
		createActions();
		setIcon(ResourceManager.loadImage("images/lighthouse.png"));
	}

	private void buildPanel() {
		panel = new JPanel(new BorderLayout());		
		TableSortStateEditor sortStateEditor = new TableSortStateEditor();
		sortStateEditor.addSortedColumn(0);
		model.setTableSortState(sortStateEditor.createTableSortState());
		model.addTableModelListener(this);
		
		table = new GTable();
		table.setModel(model);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);		
		table.setUserSortingEnabled(true);
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e){
		        if(e.getClickCount()==2){
		        	int row = table.getSelectedRow();
		        	if (row == -1)
		        		return;
		        		        
		        	controller.goTo(row);    				
		        }
		    }
		});
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
		
		LightKeeperImportAction importAction = new LightKeeperImportAction (this.controller, this);
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
		this.controller.colour();		
	}
	
	public LightKeeperCoverageModel getModel() {
		return this.model;
	}
}
