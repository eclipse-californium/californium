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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Strict correlation context matcher. Uses strictly matching for DTLS including
 * the security epoch.
 */
public class StrictCorrelationContextMatcher implements CorrelationContextMatcher {

	private static final Logger LOGGER = Logger.getLogger(RelaxedCorrelationContextMatcher.class.getName());

	@Override
	public String getName() {
		return "strict correlation";
	}

	@Override
	public boolean isResponseRelatedToRequest(CorrelationContext requestContext, CorrelationContext responseContext) {
		return internalMatch(requestContext, responseContext);
	}

	private final boolean internalMatch(CorrelationContext requestedContext, CorrelationContext availableContext) {
		if (null == requestedContext) {
			return true;
		} else if (null == availableContext) {
			return false;
		}
		if (requestedContext.get(DtlsCorrelationContext.KEY_SESSION_ID) != null) {
			boolean match = requestedContext.get(DtlsCorrelationContext.KEY_SESSION_ID).equals(
					availableContext.get(DtlsCorrelationContext.KEY_SESSION_ID))
					&& requestedContext.get(DtlsCorrelationContext.KEY_EPOCH).equals(
							availableContext.get(DtlsCorrelationContext.KEY_EPOCH))
					&& requestedContext.get(DtlsCorrelationContext.KEY_CIPHER).equals(
							availableContext.get(DtlsCorrelationContext.KEY_CIPHER));

			LOGGER.log(
					match ? Level.FINEST : Level.WARNING,
					"(D)TLS session {0}, {1}",
					new Object[] { requestedContext.get(DtlsCorrelationContext.KEY_SESSION_ID),
							availableContext.get(DtlsCorrelationContext.KEY_SESSION_ID) });
			LOGGER.log(
					match ? Level.FINEST : Level.WARNING,
					"(D)TLS epoch {0}, {1}",
					new Object[] { requestedContext.get(DtlsCorrelationContext.KEY_EPOCH),
							availableContext.get(DtlsCorrelationContext.KEY_EPOCH) });
			LOGGER.log(
					match ? Level.FINEST : Level.WARNING,
					"(D)TLS cipher {0}, {1}",
					new Object[] { requestedContext.get(DtlsCorrelationContext.KEY_CIPHER),
							availableContext.get(DtlsCorrelationContext.KEY_CIPHER) });
			return match;
		}
		return requestedContext.equals(availableContext);
	}

}
