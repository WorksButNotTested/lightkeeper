package lightkeeper.controller;

public interface IEventListener {
	void addMessage(String message);
	void addErrorMessage(String message);
	void addException(Exception exc);
}
