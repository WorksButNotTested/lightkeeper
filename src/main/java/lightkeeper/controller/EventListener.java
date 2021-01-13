package lightkeeper.controller;

public interface EventListener {
	void addMessage(String message);	
	void addErrorMessage(String message);		
	void addException(Exception exc);
}
