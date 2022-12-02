package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.elements.EndpointContext;

public interface ConnectionOrientedCoapStack extends CoapStack{

	void connected(EndpointContext context);
	
	void disconnected(EndpointContext context);
}
