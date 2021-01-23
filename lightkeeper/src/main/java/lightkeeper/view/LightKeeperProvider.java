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
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableCellRenderer;
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

		filteredTableView = new GFilterTable<CoverageTableRow>(table);
		var tableView = filteredTableView.getTable();
		tableView.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		tableView.setUserSortingEnabled(true);
		tableView.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					var row = tableView.getSelectedRow();
					if (row == -1) {
						return;
					}

					controller.goTo(row);
				}
			}
		});
		tableView.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable cellTable, Object value, boolean isSelected,
					boolean hasFocus, int row, int column) {
				var component = super.getTableCellRendererComponent(cellTable, value, isSelected, hasFocus, row,
						column);
				var modelRow = model.getModelData().get(row);
				var coverage = modelRow.getCoverage().getDouble();
				if (coverage == 0.0d) {
					component.setForeground(Color.BLACK);
					var font = component.getFont();
					var newFont = font.deriveFont(font.getStyle() | Font.ITALIC);
					component.setFont(newFont);
				} else if (coverage < 0.20d) {
					component.setForeground(Color.BLUE);
				} else if (coverage < 0.40d) {
					component.setForeground(Color.GREEN);
				} else if (coverage < 0.60d) {
					component.setForeground(Color.YELLOW);
				} else if (coverage < 0.80d) {
					component.setForeground(Color.ORANGE);
				} else {
					component.setForeground(Color.RED);
				}
				return component;

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
		tabbedPane.addTab("View", null, new JScrollPane(filteredTableView), "Coverage Data Viewing");
		tabbedPane.addTab("Select", null, new JScrollPane(listView), "Coverage file selection");
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
				Msg.showInfo(getClass(), panel, "About", "Light Keeper: " + getVersionFromManifest());
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
		filteredTableView.repaint();
	}
}
