package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.SignalingMessage;
import org.eclipse.californium.elements.EndpointContext;

public class AbstractConnectionOrientedLayer extends AbstractLayer implements ConnectionOrientedLayer{

	@Override
	public void setLowerLayer(Layer layer) {
		// TODO should we check we only use ConnectionOrientLayer ?
		super.setLowerLayer(layer);
	}
	
	@Override
	public void setUpperLayer(Layer layer) {
		// TODO should we check we only use ConnectionOrientLayer ?
		super.setUpperLayer(layer);
	}

	@Override
	public void sendSignalingMessage(SignalingMessage message) {
		if (lowerLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) lowerLayer).sendSignalingMessage(message);	
		}
	}

	@Override
	public void receivedSignalingMessage(SignalingMessage message) {
		if (upperLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) upperLayer).receivedSignalingMessage(message);
		}
	}

	@Override
	public void connected(EndpointContext  context) {
		if (upperLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) upperLayer).connected(context);
		}
	}

	@Override
	public void disconnected(EndpointContext context) {
		if (upperLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) upperLayer).disconnected(context);
		}
	}

}
