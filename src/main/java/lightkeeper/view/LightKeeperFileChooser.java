package lightkeeper.view;

import java.awt.Component;
import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

public class LightKeeperFileChooser extends GhidraFileChooser {
	
	private static File lastFile = new File (System.getProperty("user.dir"));
	
	private LightKeeperFileChooser(Component parent) {
		super(parent);
		this.setSelectedFile(lastFile);
		this.setTitle("Import Coverage Data");
		this.setApproveButtonText("Import");
		this.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
	}
	
	public static File selectFile (Component parent) {
		LightKeeperFileChooser lfc = new LightKeeperFileChooser (parent);
		
		File f = lfc.getSelectedFile();
		if (f == null)
			return null;
		
		if (!f.exists())
			return null;
		
		lastFile = new File (f.getParent());
		return f;
	}
}
