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

/**
 * Strict correlation context matcher. Uses strictly matching for DTLS including
 * the security epoch.
 */
public class StrictDtlsCorrelationContextMatcher extends KeySetCorrelationContextMatcher {

	private static final String KEYS[] = { DtlsCorrelationContext.KEY_SESSION_ID, DtlsCorrelationContext.KEY_EPOCH,
			DtlsCorrelationContext.KEY_CIPHER };

	public StrictDtlsCorrelationContextMatcher() {
		super("strict correlation", KEYS);
	}
}
