/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add multicast support.
 *                                                    ignore address when matching 
 *                                                    multicast requests.
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Endpoint context matcher for UDP.
 * 
 * Optionally checks address for request-response matching.
 */
public class UdpEndpointContextMatcher extends DefinitionsEndpointContextMatcher {

	private static final Logger LOGGER = LoggerFactory.getLogger(UdpEndpointContextMatcher.class);

	private static final Definitions<Definition<?>> DEFINITIONS = new Definitions<>("udp context")
			.add(UdpEndpointContext.KEY_PLAIN);

	public static final String MULTICAST_IDENTITY = "MULTICAST";

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
		super(DEFINITIONS);
		this.checkAddress = checkAddress;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @since 3.0 return {@link #MULTICAST_IDENTITY} for multicast addresses.
	 */
	@Override
	public Object getEndpointIdentity(EndpointContext context) {
		Object identity = super.getEndpointIdentity(context);
		if (identity instanceof InetSocketAddress) {
			InetSocketAddress address = (InetSocketAddress) identity;
			if (NetworkInterfacesUtil.isMultiAddress(address.getAddress())) {
				return MULTICAST_IDENTITY;
			}
		}
		return identity;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @since 2.3 a response matches a multicast request even if the ports are
	 *        different and broadcast request are also supported.
	 */
	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		if (checkAddress) {
			InetSocketAddress peerAddress1 = requestContext.getPeerAddress();
			InetSocketAddress peerAddress2 = responseContext.getPeerAddress();
			if (!peerAddress1.equals(peerAddress2)
					&& !NetworkInterfacesUtil.isMultiAddress(peerAddress1.getAddress())) {
				LOGGER.info("request {}:{} doesn't match {}:{}!", peerAddress1.getAddress().getHostAddress(),
						peerAddress1.getPort(), peerAddress2.getAddress().getHostAddress(), peerAddress2.getPort());
				return false;
			}
		}
		return super.isResponseRelatedToRequest(requestContext, responseContext);
	}
}
