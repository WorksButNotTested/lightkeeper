package lightkeeper.view;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

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
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTable;
import docking.widgets.table.TableSortStateEditor;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.LightKeeperClearTask;
import lightkeeper.controller.LightKeeperController;
import lightkeeper.controller.LightKeeperImportTask;
import lightkeeper.controller.LightKeeperRefreshTask;
import lightkeeper.model.LightKeeperCoverageModel;
import resources.Icons;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider implements TableModelListener {

	private static File lastFile = null;
	
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
		        if(e.getClickCount() == 2){
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
				new MenuData(new String[] {"About"},Icons.HELP_ICON,"Help"));
		
		dockingTool.addLocalAction(this, aboutAction);
		
		GhidraFileChooser chooser = new GhidraFileChooser(panel);		
		chooser.setTitle("Import Coverage Data");
		chooser.setApproveButtonText("Import");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		
		DockingAction importAction = new DockingAction("Import Coverage Data", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (lastFile == null) {
					chooser.setSelectedFile(new File (System.getProperty("user.dir")));
				} else {
					chooser.setSelectedFile(lastFile);
				}
				
				File file = chooser.getSelectedFile();
				if (file == null)
					return;
				
				if (!file.exists())
					return;
				
				lastFile = file;
													
				LightKeeperImportTask task = controller.createImportTask(file);
				TaskLauncher.launch(task);		
			}
		};
		importAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));		
		importAction.setEnabled(true);
		importAction.setMenuBarData(
				new MenuData(new String[] {"Import"}, Icons.ADD_ICON, "Action"));
		dockingTool.addLocalAction(this, importAction);
		
		DockingAction refreshAction = new DockingAction("Refresh", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {		
				if (lastFile == null)
					return;
				LightKeeperRefreshTask task = controller.createRefreshTask();
				TaskLauncher.launch(task);		
			}
		};
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));		
		refreshAction.setEnabled(true);
		refreshAction.setMenuBarData(
				new MenuData(new String[] {"Refresh"}, Icons.REFRESH_ICON, "Action"));
		dockingTool.addLocalAction(this, refreshAction);
		
		DockingAction clearAction = new DockingAction("Clear", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {						
				LightKeeperClearTask task = controller.createClearTask();
				TaskLauncher.launch(task);		
			}
		};
		clearAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));		
		clearAction.setEnabled(true);
		clearAction.setMenuBarData(
				new MenuData(new String[] {"Clear"}, Icons.DELETE_ICON, "Action"));
		dockingTool.addLocalAction(this, clearAction);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void tableChanged(TableModelEvent arg0) {
		this.table.repaint();		
		this.controller.colour(this.model.getHits());		
	}	
}
