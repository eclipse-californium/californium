package org.eclipse.californium.elements;


public interface ConnectionEventHandler {
	void connected(EndpointContext context);

	void disconnected(EndpointContext context);
}
