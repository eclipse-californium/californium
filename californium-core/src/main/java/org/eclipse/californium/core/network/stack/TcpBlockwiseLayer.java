/*******************************************************************************
 * Copyright (c) 2022 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;


import org.eclipse.californium.core.coap.SignalingMessage;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * @see BlockwiseLayer
 */
public class TcpBlockwiseLayer extends BlockwiseLayer implements ConnectionOrientedLayer {

	public TcpBlockwiseLayer(String tag, Configuration config, EndpointContextMatcher matchingStrategy) {
		super(tag,true,config,matchingStrategy);
	}
	
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
	public void connected(EndpointContext context) {
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

	@Override
	public void receivedSignalingMessage(SignalingMessage message) {
		if (upperLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) upperLayer).receivedSignalingMessage(message);;	
		}			
	}

	@Override
	public void sendSignalingMessage(SignalingMessage message) {
		if (lowerLayer instanceof ConnectionOrientedLayer) {
			((ConnectionOrientedLayer) lowerLayer).sendSignalingMessage(message);;	
		}
	}
}
