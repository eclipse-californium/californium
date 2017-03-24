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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Correlation context matcher for UDP.
 */
public final class UdpCorrelationContextMatcher implements CorrelationContextMatcher {

	private static final Logger LOG = Logger.getLogger(UdpCorrelationContextMatcher.class.getName());

	/**
	 * Create new instance of udp correlation context matcher.
	 */
	public UdpCorrelationContextMatcher() {
	}

	@Override
	public String getName() {
		return "udp correlation";
	}

	@Override
	public boolean isResponseRelatedToRequest(CorrelationContext requestContext, CorrelationContext responseContext) {
		LOG.log(Level.FINER, "matching inbound response context [{0}] against request context [{1}]",
				new Object[]{ responseContext, requestContext });
		return internalMatch(requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(CorrelationContext messageContext, CorrelationContext connectorContext) {
		LOG.log(Level.FINER, "matching outbound message context [{0}] against connector context [{1}]",
				new Object[]{ messageContext, connectorContext });
		return internalMatch(messageContext, connectorContext);
	}

	private static boolean internalMatch(CorrelationContext expected, CorrelationContext provided) {

		if (expected == null) {
			return true;
		} else if (provided == null) {
			return false;
		} else {
			Object expectedAddress = expected.get(UdpCorrelationContext.KEY_SOCKET_ADDRESS);
			Object providedAddress = provided.get(UdpCorrelationContext.KEY_SOCKET_ADDRESS);
			return expectedAddress == null || expectedAddress.equals(providedAddress);
		}
	}
}
