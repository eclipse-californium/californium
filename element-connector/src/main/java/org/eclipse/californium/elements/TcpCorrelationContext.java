/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages using TCP.
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * A correlation context that explicitly supports TCP specific properties.
 */
public class TcpCorrelationContext extends MapBasedCorrelationContext {

	/**
	 * Key for TCP connection ID.
	 * 
	 */
	public static final String KEY_CONNECTION_ID = "CONNECTION_ID";

	/**
	 * Creates a new correlation context from TCP connection ID.
	 * 
	 * @param connectionId the connectionn's ID.
	 * @throws NullPointerException if connectionId is <code>null</code>.
	 */
	public TcpCorrelationContext(String connectionId) {
		if (connectionId == null) {
			throw new NullPointerException("Connection ID must not be null");
		} else {
			put(KEY_CONNECTION_ID, connectionId);
		}
	}

	public String getConnectionId() {
		return get(KEY_CONNECTION_ID);
	}

	@Override
	public String toString() {
		return String.format("TCP(%s)", getConnectionId());
	}

}
