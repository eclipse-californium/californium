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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use UdpEndpointContext to prevent
 *                                                    matching with a DtlsEndpointContext
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Endpoint context matcher for UDP.
 * 
 * Optionally checks address for request-response matching.
 */
public class UdpEndpointContextMatcher extends KeySetEndpointContextMatcher {

	private static final String KEYS[] = { UdpEndpointContext.KEY_PLAIN };

	/**
	 * Enable address check for request-response matching.
	 */
	private final boolean checkAddress;

	/**
	 * Create new instance of udp endpoint context matcher with enabled address
	 * check.
	 */
	public UdpEndpointContextMatcher() {
		this(true);
	}

	/**
	 * Create new instance of udp endpoint context matcher.
	 * 
	 * @param checkAddress {@code true} with address check, {@code false},
	 *            without
	 */
	public UdpEndpointContextMatcher(boolean checkAddress) {
		super("udp plain", KEYS);
		this.checkAddress = checkAddress;
	}

	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		if (checkAddress && !requestContext.getPeerAddress().equals(responseContext.getPeerAddress())) {
			return false;
		}
		return super.isResponseRelatedToRequest(requestContext, responseContext);
	}
}
