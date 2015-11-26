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
import java.util.Set;

import org.eclipse.californium.core.network.Endpoint;


public interface ServerEndpointRegistry {

	/**
	 * Gets the endpoint bound to a particular address.
	 * 
	 * @param address the address
	 * @return the endpoint or <code>null</code> if none of the
	 * server's endpoints is bound to the given address
	 */
	Endpoint getEndpoint(InetSocketAddress address);

	/**
	 * Gets the endpoint bound to a particular port.
	 * 
	 * @param port the port
	 * @return the endpoint or <code>null</code> if none of the
	 * server's endpoints is bound to the given port on any of its
	 * network interfaces
	 */
	Endpoint getEndpoint(int port);

	/**
	 * Gets all endpoints in the registry.
	 * 
	 * @return the registered endpoints. Removing or adding endpoints from/to
	 *         the returned set does not remove or add the endpoint to this
	 *         registry.
	 */
	Set<Endpoint> getAllEndpoints();
}
