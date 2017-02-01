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
 *                                                    outgoing messages.
 *                                                    Use getMatchingKeys
 *                                                    (fix GitHub issue #104)
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Strict correlation context matcher. Uses strictly matching for DTLS including
 * the security epoch.
 */
public class StrictCorrelationContextMatcher implements CorrelationContextMatcher {

	@Override
	public String getName() {
		return "strict correlation";
	}

	@Override
	public boolean isResponseRelatedToRequest(CorrelationContext requestContext, CorrelationContext responseContext) {
		return internalMatch(requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(CorrelationContext messageContext, CorrelationContext connectorContext) {
		return internalMatch(messageContext, connectorContext);
	}

	private final boolean internalMatch(CorrelationContext requestedContext, CorrelationContext availableContext) {
		if (null == requestedContext) {
			return true;
		} else if (null == availableContext) {
			return false;
		}
		Set<String> keys = new CopyOnWriteArraySet<String>(requestedContext.getMatchingKeys());
		keys.addAll(availableContext.getMatchingKeys());
		return CorrelationContextUtil.match(getName(), keys, requestedContext, availableContext);
	}

}
