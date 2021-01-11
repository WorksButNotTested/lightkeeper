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
import lightkeeper.controller.LightKeeperController;
import lightkeeper.controller.LightKeeperImportTask;
import lightkeeper.model.LightKeeperCoverageModel;
import resources.Icons;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider implements TableModelListener {

	private static File lastFile = new File (System.getProperty("user.dir"));
	
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
				new MenuData(new String[] {"About"},null,null));
		
		dockingTool.addLocalAction(this, aboutAction);
		
		GhidraFileChooser chooser = new GhidraFileChooser(panel);
		chooser.setSelectedFile(lastFile);
		chooser.setTitle("Import Coverage Data");
		chooser.setApproveButtonText("Import");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		
		DockingAction importAction = new DockingAction("Import Coverage Data", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {						
				File file = chooser.getSelectedFile();
				if (file == null)
					return;
				
				if (!file.exists())
					return;
				
				lastFile = new File (file.getParent());
													
				LightKeeperImportTask task = controller.createImportTask(file);
				TaskLauncher.launch(task);		
			}
		};
		importAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));		
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
		this.controller.colour(this.model.getHits());		
	}	
}
