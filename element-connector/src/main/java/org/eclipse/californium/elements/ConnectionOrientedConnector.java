package org.eclipse.californium.elements;


public interface ConnectionOrientedConnector extends Connector{
	
	void setConnectionEventHandler(ConnectionEventHandler eventHandler);
}
