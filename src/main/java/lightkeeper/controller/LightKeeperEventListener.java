package lightkeeper.controller;

public interface LightKeeperEventListener {
	void addMessage(String message);	
	void addErrorMessage(String message);		
	void addException(Exception exc);
}
