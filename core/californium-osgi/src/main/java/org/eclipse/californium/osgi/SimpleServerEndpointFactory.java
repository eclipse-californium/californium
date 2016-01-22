/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla - OSGi support
 ******************************************************************************/
package org.eclipse.californium.osgi;

import java.net.InetSocketAddress;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.ConnectorFactory;
import org.osgi.service.io.ConnectionFactory;


/**
 * A basic implementation for creating standard CoAP endpoints.
 * 
 * The factory can also create secure endpoints if it has been configured
 * with a secure {@link ConnectionFactory}.
 */
public class SimpleServerEndpointFactory implements EndpointFactory {

	private final Logger log = Logger.getLogger(SimpleServerEndpointFactory.class.getName());
	
	private ConnectorFactory secureConnectorFactory;
	
	/**
	 * Initializes the factory with collaborators.
	 * 
	 * @param secureConnectorFactory the factory to use for creating {@link Connector}s
	 * implementing DTLS for secure Endpoints or <code>null</code> if this factory
	 * does not support the creation of secure Endpoints.
	 */
	public SimpleServerEndpointFactory(ConnectorFactory secureConnectorFactory) {
		this.secureConnectorFactory = secureConnectorFactory;
	}
	
	@Override
	public final Endpoint getEndpoint(NetworkConfig config, InetSocketAddress address) {
		
		CoapEndpoint endpoint = new CoapEndpoint(address, config);
		return endpoint;
	}

	@Override
	public final Endpoint getSecureEndpoint(NetworkConfig config, InetSocketAddress address) {

		Endpoint endpoint = null;
		if (secureConnectorFactory != null) {
			endpoint = new CoapEndpoint(
					secureConnectorFactory.newConnector(address),
					config);
		} else {
			log.fine("A secure ConnectorFactory is required to create secure Endpoints.");
		}
		return endpoint;
	}

}
