/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.UDPConnector;

import java.net.InetSocketAddress;
import java.util.List;

/**
 * 
 * Extends the CoapEndpoint and changes the stack to the OSCoreStack.
 *
 */
public class OSCoreEndpoint extends CoapEndpoint {

	/**
	 * Instantiates a new endpoint
	 * 
	 */
	public OSCoreEndpoint() {
		super(new UDPConnector(new InetSocketAddress(0)), false, NetworkConfig.getStandard(), null, null, null, null,
				null);
		this.coapstack = new OSCoreStack(this.config, new OutboxImpl());
	}

	/**
	 * Instantiates a new endpoint with the specified port and configuration.
	 * 
	 * @param db the OSCore context database
	 * @param port the UDP port
	 * @param config the network configuration
	 */
	public OSCoreEndpoint(int port, NetworkConfig config) {
		super(new UDPConnector(new InetSocketAddress(port)), false, config, null, null, null, null, null);
		this.coapstack = new OSCoreStack(this.config, new OutboxImpl());
	}

	/**
	 * Instantiates a new endpoint with the specified port and configuration.
	 * 
	 * @param db the OSCore context database
	 * @param addr the endpoint address
	 */
	public OSCoreEndpoint(InetSocketAddress addr) {
		super(new UDPConnector(addr), false, NetworkConfig.getStandard(), null, null, null, null, null);
		this.coapstack = new OSCoreStack(this.config, new OutboxImpl());
	}
}
