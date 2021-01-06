package lightkeeper;

public interface ILightKeeperTaskEventListener {
	public void addMessage(String message);
	public void addErrorMessage(String message);
	public void addException(Exception exc);
}
