package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.SignalingMessage;
import org.eclipse.californium.elements.EndpointContext;

public interface ConnectionOrientedLayer extends Layer {

	void connected(EndpointContext context);
	
	void disconnected(EndpointContext context);
	
	// TODO Dont know if this is something relating to ConnectionOrientedLayer ... 
	// RFC says :  Signaling messages are specifically introduced only for CoAP over reliable transports
	void sendSignalingMessage(SignalingMessage message);
	
	void receivedSignalingMessage(SignalingMessage message);
}
