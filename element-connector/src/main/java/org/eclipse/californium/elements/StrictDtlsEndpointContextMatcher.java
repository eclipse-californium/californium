/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Strict endpoint context matcher. Uses strictly matching for DTLS including
 * the security epoch.
 */
public class StrictDtlsEndpointContextMatcher extends KeySetEndpointContextMatcher {

	private static final String KEYS[] = { DtlsEndpointContext.KEY_SESSION_ID, DtlsEndpointContext.KEY_EPOCH,
			DtlsEndpointContext.KEY_CIPHER };

	/**
	 * Creates a new matcher.
	 * <p>
	 * Two contexts will be considered <em>matching</em> if they have the same value
	 * for properties
	 * <ul>
	 *   <li>{@link DtlsEndpointContext#KEY_SESSION_ID}</li>
	 *   <li>{@link DtlsEndpointContext#KEY_EPOCH}</li>
	 *   <li>{@link DtlsEndpointContext#KEY_CIPHER}</li>
	 * </ul>
	 * and have a matching virtualHost property according to
	 * {@link KeySetEndpointContextMatcher#isSameVirtualHost(EndpointContext, EndpointContext)}.
	 */
	public StrictDtlsEndpointContextMatcher() {
		super("strict context", KEYS, true);
	}
}
