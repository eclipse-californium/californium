/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add flexible correlation context matching
 *                                      (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isToBeSent to control
 *                                                    outgoing messages
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use inhibitNewConnection
 *                                                    to distinguish from 
 *                                                    none plain UDP contexts.
 *    Achim Kraus (Bosch Software Innovations GmbH) - check address for plain udp
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.util.Arrays;

/**
 * Endpoint context matcher for UDP.
 */
public class UdpEndpointContextMatcher implements EndpointContextMatcher {

	/**
	 * Create new instance of udp endpoint context matcher.
	 */
	public UdpEndpointContextMatcher() {
	}

	@Override
	public String getName() {
		return "udp plain";
	}

	@Override
	public byte[] getEndpointIdentifier(EndpointContext endpointContext) {
		InetSocketAddress socketAddress = endpointContext.getPeerAddress();
		byte[] address = socketAddress.getAddress().getAddress();
		int port = socketAddress.getPort();
		int portIndex = address.length;
		address = Arrays.copyOf(address, portIndex + 2);
		address[portIndex] = (byte) port;
		address[portIndex + 1] = (byte) (port >>> 8);
		return address;
	}

	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		if (!requestContext.getPeerAddress().equals(responseContext.getPeerAddress())) {
			return false;
		}
		return internalMatch(requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(EndpointContext messageContext, EndpointContext connectorContext) {
		return internalMatch(messageContext, connectorContext);
	}

	protected final boolean internalMatch(EndpointContext requestedContext, EndpointContext availableContext) {
		return (null == requestedContext) || !requestedContext.inhibitNewConnection() || (null != availableContext);
	}

}
