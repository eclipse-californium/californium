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
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename StrictDtlsCorrelationContextMatcher
 *                                                    to StrictdDtlsEndpointContextMatcher.
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Strict endpoint context matcher. 
 * 
 * Uses strictly matching for DTLS including the security epoch.
 */
public class StrictDtlsEndpointContextMatcher extends KeySetEndpointContextMatcher {

	private static final String KEYS[] = { DtlsEndpointContext.KEY_SESSION_ID, DtlsEndpointContext.KEY_EPOCH,
			DtlsEndpointContext.KEY_CIPHER };

	public StrictDtlsEndpointContextMatcher() {
		super("strict correlation", KEYS);
	}
}
