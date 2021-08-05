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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * TLS endpoint context matcher.
 */
public class TlsEndpointContextMatcher extends DefinitionsEndpointContextMatcher {

	private static final Definitions<Definition<?>> DEFINITIONS = new Definitions<>("tls context")
			.add(TcpEndpointContext.KEY_CONNECTION_ID).add(TlsEndpointContext.KEY_SESSION_ID)
			.add(TlsEndpointContext.KEY_CIPHER);

	public TlsEndpointContextMatcher() {
		super(DEFINITIONS);
	}
}
