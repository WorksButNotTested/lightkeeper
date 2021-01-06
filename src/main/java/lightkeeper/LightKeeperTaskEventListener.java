package lightkeeper;

import ghidra.app.services.ConsoleService;
import ghidra.util.Swing;

public class LightKeeperTaskEventListener implements ILightKeeperTaskEventListener
{
	protected ConsoleService console;
	public LightKeeperTaskEventListener(ConsoleService console) {
		this.console = console;
	}
	@Override
	public void addMessage(String message) {
		Swing.runLater(() -> {
			console.addMessage("Light Keeper", message);
		});
	}

	@Override
	public void addErrorMessage(String message) {
		Swing.runLater(() -> {
			console.addErrorMessage("Light Keeper", message);
		});
	}
}
