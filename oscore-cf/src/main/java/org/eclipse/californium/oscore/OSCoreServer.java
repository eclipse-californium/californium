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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.config.NetworkConfig;

public class OSCoreServer extends CoapServer {

	/**
	 * Constructs a default server. The server starts after the method
	 * {@link #start()} is called. If a server starts and has no specific ports
	 * assigned, it will bind to CoAp's default port 5683.
	 * 
	 * @param db the OSCore context database
	 */
	public OSCoreServer() {
		this(NetworkConfig.getStandard(), 5683);
	}

	/**
	 * Constructs a server that listens to the specified port(s) after method
	 * {@link #start()} is called.
	 * 
	 * @param db the OSCore context database
	 * @param ports the ports to bind to
	 */
	public OSCoreServer(int... ports) {
		this(NetworkConfig.getStandard(), ports);
	}

	/**
	 * Constructs a server with the specified configuration that listens to the
	 * specified ports after method {@link #start()} is called.
	 * 
	 * @param db the OSCore context database
	 * @param config the configuration, if <code>null</code> the configuration
	 *            returned by {@link NetworkConfig#getStandard()} is used.
	 * @param ports the ports to bind to
	 */
	public OSCoreServer(NetworkConfig config, int... ports) {
		super();

		// create endpoint for each port
		for (int port : ports) {
			addEndpoint(new OSCoreEndpoint(port, config));
		}
	}
}
