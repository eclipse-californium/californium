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

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.ServerInterface;

/**
 * A factory for {@link ServerInterface} instances.
 * This factory is used by the {@link ManagedServer} in order to create a new server instance
 * when properties are updated via OSGi's Config Admin Service.
 */
interface ServerInterfaceFactory {
	
	/**
	 * Creates a new {@link ServerInterface} instance.
	 * 
	 * Can be overridden e.g. by test classes to use a mock instance instead of a <i>real</i> server.
	 * This default implementation returns a new instance of {@link CoapServer}.
	 * 
	 * @param config the network configuration to use for setting up the server's endpoint. If <code>null</code>
	 * the default network configuration is used.
	 * @return the new instance
	 */
	ServerInterface newServer(NetworkConfig config);
	
	/**
	 * Creates a new {@link ServerInterface} instance with multiple endpoints.
	 * 
	 * Can be overridden e.g. by test classes to use a mock instance instead of a <i>real</i> server.
	 * This default implementation returns a new instance of {@link CoapServer}.
	 * 
	 * @param config the network configuration to use for setting up the server's endpoints. If <code>null</code>
	 * the default network configuration is used.
	 * @param ports the ports to bind endpoints to
	 * @return the new instance
	 */
	ServerInterface newServer(NetworkConfig config, int... ports);
}
