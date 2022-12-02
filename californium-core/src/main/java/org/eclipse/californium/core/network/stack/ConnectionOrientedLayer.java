package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.elements.EndpointContext;

public interface ConnectionOrientedLayer extends Layer {

	void connected(EndpointContext context);
	
	void disconnected(EndpointContext context);
}
