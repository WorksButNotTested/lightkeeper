package lightkeeper.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.TableSortState;
import docking.widgets.table.TableSortStateEditor;
import docking.widgets.table.ColumnSortState.SortDirection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.controller.Controller;
import lightkeeper.model.coverage.CoverageListState;
import lightkeeper.model.list.CoverageList;
import lightkeeper.model.table.CoverageTable;
import lightkeeper.model.table.CoverageTableModel;
import lightkeeper.model.table.CoverageTableRow;
import resources.Icons;
import resources.ResourceManager;

public class LightKeeperProvider extends ComponentProvider implements TableModelListener {

	private static File lastFile = null;

	protected LightKeeperPlugin plugin;
	protected CoverageTableModel model;
	protected CoverageTable table;
	protected CoverageList list;
	protected Controller controller;
	protected GFilterTable<CoverageTableRow> filteredTableView;
	protected GTable listView;
	protected JPanel panel;

	public LightKeeperProvider(LightKeeperPlugin plugin, Controller controller, CoverageTableModel model,
			CoverageTable table, CoverageList list, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		this.controller = controller;
		this.model = model;
		this.table = table;
		this.list = list;
		buildPanel();
		createActions();
		setIcon(ResourceManager.loadImage("images/lighthouse.png"));
	}
	
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		table.addTableModelListener(this);
		var tableSortEditor = new TableSortStateEditor();
		tableSortEditor.addSortedColumn(0, SortDirection.DESCENDING);
		tableSortEditor.addSortedColumn(1, SortDirection.ASCENDING);
		TableSortState state = tableSortEditor.createTableSortState();		
		table.setTableSortState(state);

		filteredTableView = new GFilterTable<CoverageTableRow>(table);
		var tableView = filteredTableView.getTable();
		tableView.setUserSortingEnabled(true);
		tableView.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		tableView.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					var row = filteredTableView.getSelectedRowObject();
					if (row == null) {
						return;
					}

					controller.goTo(row);
				}
			}
		});		        
		tableView.getColumnModel().getColumn(1).setCellRenderer(new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				var component = super.getTableCellRendererComponent(data);
				var tableMonoFont = new Font("monospaced", Font.PLAIN, this.getFont().getSize());
				component.setFont(tableMonoFont);
				
				TableColumn tableColumn = tableView.getColumnModel().getColumn(1);			
				int itemWidth = component.getPreferredSize().width + tableView.getIntercellSpacing().width;		
				if (itemWidth > tableColumn.getPreferredWidth()) {
					
					tableView.getTableHeader().setResizingColumn(tableColumn);
					tableColumn.setWidth(itemWidth);
					
				}
				
				return component;
			}
		});
		tableView.setDefaultRenderer(Object.class, new GTableCellRenderer() {
				
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				int row = data.getRowViewIndex();

				var component = super.getTableCellRendererComponent(data);
				var modelRow = model.getModelData().get(row);
				var coverage = modelRow.getCoverage().getDouble();				
																			
				int column = data.getColumnViewIndex();
				if (coverage == 0.0d) {				
					var font = this.getFont();
					var italic = font.deriveFont(font.getStyle() | Font.ITALIC);
					component.setFont(italic);
				}
								
				switch(column) {
					case 0:
						setPercentageBackgroundColor(component, coverage);
					case 1:
					case 2:
					case 3:
					case 4:					
						TableColumn tableColumn = tableView.getColumnModel().getColumn(column);			
						int itemWidth = component.getPreferredSize().width + tableView.getIntercellSpacing().width;		
						if (itemWidth > tableColumn.getPreferredWidth()) {
							
							tableView.getTableHeader().setResizingColumn(tableColumn);
							tableColumn.setWidth(itemWidth);
							
						}
						break;
					default:
						break;
				}
				
				if (column != 0) {
					return component;
				}
													
				return component;

			}
			
			private void setPercentageBackgroundColor(Component component, double coverage) {
				if (coverage < 0.20d) {
					component.setBackground(Color.BLUE);					
					component.setForeground(Color.WHITE);
				} else if (coverage < 0.40d) {
					component.setBackground(Color.GREEN);
					component.setForeground(Color.BLACK);
				} else if (coverage < 0.60d) {
					component.setBackground(Color.YELLOW);
					component.setForeground(Color.BLACK);
				} else if (coverage < 0.80d) {
					component.setBackground(Color.ORANGE);
					component.setForeground(Color.BLACK);
				} else {
					component.setBackground(Color.RED);
					component.setForeground(Color.WHITE);
				}
			}				
		});		
		listView = new GTable() {
			@Override
			public void doLayout() {
				var iconWidth = new JLabel(Icons.ADD_ICON).getPreferredSize().width;
				TableColumn statusColumn = listView.getColumnModel().getColumn(0);
				statusColumn.setWidth(iconWidth);
				super.doLayout();
			}
		};
		listView.setModel(list);
		listView.setUserSortingEnabled(true);
		listView.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					var row = listView.getSelectedRow();
					if (row == -1) {
						return;
					}

					toggleRows(Arrays.asList(row));
				}
			}
		});
		listView.addKeyListener(new KeyListener() {
			@Override
			public void keyPressed(KeyEvent arg0) {
				int[] rows = listView.getSelectedRows();
				List<Integer> rowsList = new ArrayList<Integer>(rows.length);
				for (int i : rows) {
					rowsList.add(i);
				}
				switch (arg0.getKeyChar()) {
				case '+':
					setRows(rowsList, CoverageListState.ADDED);
					break;
				case '-':
					setRows(rowsList, CoverageListState.SUBTRACTED);
					break;
				case '\b':
				case KeyEvent.VK_DELETE:
					setRows(rowsList, CoverageListState.IGNORED);
					break;
				case '\n':
					toggleRows(rowsList);
					break;
				default:
					break;
				}
			}

			@Override
			public void keyReleased(KeyEvent arg0) {
			}

			@Override
			public void keyTyped(KeyEvent arg0) {
			}
		});
		listView.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable cellTable, Object value, boolean isSelected,
					boolean hasFocus, int row, int column) {
				var component = super.getTableCellRendererComponent(cellTable, value, isSelected, hasFocus, row,
						column);
				if (column != 0)
					return component;

				switch (list.getModelData().get(row).getState()) {
				case ADDED:
					return new JLabel(Icons.ADD_ICON);
				case SUBTRACTED:
					return new JLabel(Icons.DELETE_ICON);
				case IGNORED:
					return new JLabel();
				default:
					return new JLabel(Icons.HELP_ICON);
				}
			}
		});

		listView.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		TableColumn statusColumn = listView.getColumnModel().getColumn(0);
		listView.getTableHeader().setResizingColumn(statusColumn);

		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.setTabPlacement(SwingConstants.RIGHT);
		tabbedPane.addTab("View", null, filteredTableView, "Coverage Data Viewing");
		tabbedPane.addTab("Select", null, listView, "Coverage file selection");
		panel.add(tabbedPane);
		setVisible(true);
	}

	protected void setRows(List<Integer> rows, CoverageListState state) {
		Task task = new Task("Select Coverage Files", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				controller.setCoverageFiles(monitor, rows, state);
			}
		};
		TaskLauncher.launch(task);
	}

	protected void toggleRows(List<Integer> rows) {
		Task task = new Task("Select Coverage Files", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				controller.toggleCoverageFiles(monitor, rows);
			}
		};
		TaskLauncher.launch(task);
	}

	private String getVersionFromManifest() {
		String res = null;
		try {
			res = getClass().getPackage().getImplementationVersion();
		} catch (Exception e) {
		}
		return (res != null ? res : "version unknown");
	}

	private void createActions() {

		DockingAction aboutAction = new DockingAction("About", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				StringBuilder sb = new StringBuilder();
				sb.append("<html>");
				sb.append("Light Keeper: ");
				sb.append(getVersionFromManifest());
				sb.append("<div>");
				sb.append("Icons made by ");				
				sb.append("<a href=\"https://www.flaticon.com/authors/pixel-perfect\" title=\"Pixel Perfect\">");				
				sb.append("Pixel Perfect");
				sb.append("</a>");
				sb.append(" from ");
				sb.append("<a href=\"https://www.flaticon.com/\" title=\"Flaticon\">");
				sb.append("www.flaticon.com");
				sb.append("</div>");
				sb.append("</html>");
				
				Msg.showInfo(getClass(), panel, "About", sb.toString());
			}
		};
		aboutAction.setMenuBarData(new MenuData(new String[] { "About" }, Icons.HELP_ICON, "Help"));

		dockingTool.addLocalAction(this, aboutAction);

		var chooser = new GhidraFileChooser(panel);
		chooser.setTitle("Import Coverage Data");
		chooser.setApproveButtonText("Import");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setMultiSelectionEnabled(true);

		DockingAction importAction = new DockingAction("Import Coverage Data", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (lastFile == null) {
					chooser.setSelectedFile(new File(System.getProperty("user.dir")));
				} else {
					chooser.setSelectedFile(lastFile);
				}

				var files = chooser.getSelectedFiles();
				if (files.size() == 0) {
					return;
				}

				if (files.stream().filter(f -> !f.exists()).count() != 0) {
					return;
				}

				lastFile = files.get(0);

				Task task = new Task("Import Coverage Data", true, true, true) {
					@Override
					public void run(TaskMonitor monitor) throws CancelledException {
						controller.importCoverage(monitor, files);
					}
				};
				TaskLauncher.launch(task);
			}
		};
		importAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		importAction.setEnabled(true);
		importAction.setMenuBarData(new MenuData(new String[] { "Import" }, Icons.ADD_ICON, "Action"));
		dockingTool.addLocalAction(this, importAction);

		DockingAction refreshAction = new DockingAction("Refresh", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (lastFile == null) {
					return;
				}
				Task task = new Task("Refresh Coverage Data", true, true, true) {
					@Override
					public void run(TaskMonitor monitor) throws CancelledException {
						controller.refreshCoverage(monitor);
					}
				};
				TaskLauncher.launch(task);
			}
		};
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		refreshAction.setEnabled(true);
		refreshAction.setMenuBarData(new MenuData(new String[] { "Refresh" }, Icons.REFRESH_ICON, "Action"));
		dockingTool.addLocalAction(this, refreshAction);

		DockingAction clearAction = new DockingAction("Clear", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Task task = new Task("Clear Coverage Data", true, true, true) {
					@Override
					public void run(TaskMonitor monitor) throws CancelledException {
						controller.clearCoverage(monitor);
					}
				};
				TaskLauncher.launch(task);
			}
		};
		clearAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		clearAction.setEnabled(true);
		clearAction.setMenuBarData(new MenuData(new String[] { "Clear" }, Icons.DELETE_ICON, "Action"));
		dockingTool.addLocalAction(this, clearAction);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void tableChanged(TableModelEvent arg0) {		
		var tableView = filteredTableView.getTable();
		tableView.setPreferredScrollableViewportSize(tableView.getPreferredSize());
		tableView.setFillsViewportHeight(true);
		for(int i = 0; i < tableView.getColumnCount(); i++) {
			TableColumn tableColumn = tableView.getColumnModel().getColumn(i);
								
			Object value = tableColumn.getHeaderValue();
			TableCellRenderer renderer = tableColumn.getHeaderRenderer();
			if (renderer == null)
			{
				renderer = tableView.getTableHeader().getDefaultRenderer();
			}

			Component c = renderer.getTableCellRendererComponent(tableView, value, false, false, -1, i);
			int headerWidth = c.getPreferredSize().width;			
			tableView.getTableHeader().setResizingColumn(tableColumn);
			tableColumn.setWidth(headerWidth);
		}
		filteredTableView.repaint();
	}
}
