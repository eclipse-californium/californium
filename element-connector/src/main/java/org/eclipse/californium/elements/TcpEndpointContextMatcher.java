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
 * TCP endpoint context matcher.
 */
public class TcpEndpointContextMatcher extends KeySetEndpointContextMatcher {

	private static final String KEYS[] = { TcpEndpointContext.KEY_CONNECTION_ID };

	public TcpEndpointContextMatcher() {
		super("tcp context", KEYS);
	}
}
