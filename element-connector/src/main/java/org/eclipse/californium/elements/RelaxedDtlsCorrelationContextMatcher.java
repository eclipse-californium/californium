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
 * Relaxed correlation context matcher. Matches DTLS without epoch.
 */
public class RelaxedDtlsCorrelationContextMatcher extends KeySetCorrelationContextMatcher {

	private static final String KEYS[] = { DtlsCorrelationContext.KEY_SESSION_ID, DtlsCorrelationContext.KEY_CIPHER };

	public RelaxedDtlsCorrelationContextMatcher() {
		super("relaxed correlation", KEYS);
	}

}
