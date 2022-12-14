package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.SignalingMessage;
import org.eclipse.californium.elements.EndpointContext;

public interface ConnectionOrientedCoapStack extends CoapStack{

	void connected(EndpointContext context);
	
	void disconnected(EndpointContext context);

	void receivedSignalingMessage(SignalingMessage message) ;

	void sendSignalingMessage(SignalingMessage message);
}
