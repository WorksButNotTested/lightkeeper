package lightkeeper;

import ghidra.framework.plugintool.util.PluginPackage;

public class LightKeeperPluginPackage extends PluginPackage {

	public static final String NAME="LightKeeper";
	
	public LightKeeperPluginPackage() {
		super(NAME, null, "light keeper plugin package");
	}
}