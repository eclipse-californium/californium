/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.elements.Connector;

/**
 * Factory for CoapStack.
 * 
 * Either provided to the {@link CoapEndpoint.Builder} or set as
 * default {@link CoapEndpoint#setDefaultCoapStackFactory(CoapStackFactory)}.
 */
public interface CoapStackFactory {

	/**
	 * Create CoapStack.
	 * 
	 * @param protocol used protocol, values see
	 *            {@link Connector#getProtocol()}.
	 * @param config network configuration used for this coap stack
	 * @param outbox outbox to be used for this coap stack
	 * @return create coap stack-
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if protocol is not supported.
	 */
	CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox);
}
