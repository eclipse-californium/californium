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

/**
 * Relaxed endpoint context matcher. Matches DTLS without epoch.
 */
public class RelaxedDtlsEndpointContextMatcher extends KeySetEndpointContextMatcher {

	private static final String KEYS[] = { DtlsEndpointContext.KEY_SESSION_ID, DtlsEndpointContext.KEY_CIPHER };

	public RelaxedDtlsEndpointContextMatcher() {
		super("relaxed context", KEYS);
	}

}
