/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Contributors:
 *    Kai Hudalla - OSGi support
 ******************************************************************************/
package org.eclipse.californium.osgi;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;


/**
 * A factory for creating {@link Endpoint}s.
 */
public interface EndpointFactory {

	/**
	 * Gets a communication endpoint bound to a given IP address and port.
	 * 
	 * The endpoints returned by this method are <em>not</em> started yet.
	 * 
	 * @param config the configuration properties to be used for creating the
	 * endpoint or {@code null} if default values should be used
	 * @param address the IP address and port to bind to
	 * @return the endpoint
	 * @since 3.0 (changed parameter to Configuration)
	 */
	Endpoint getEndpoint(Configuration config, InetSocketAddress address);

	/**
	 * Gets an Endpoint that uses DTLS for secure communication.
	 * 
	 * The endpoints returned by this method are <em>not</em> started yet.
	 * 
	 * @param config the configuration properties to be used for creating the
	 *            endpoint or {@code null}, if default values should be used
	 * @param address the address
	 * @return the secure endpoint or {@code null}, if this factory does not
	 *         support secure endpoints
	 * @since 3.0 (changed parameter to Configuration)
	 */
	Endpoint getSecureEndpoint(Configuration config, InetSocketAddress address);
}
