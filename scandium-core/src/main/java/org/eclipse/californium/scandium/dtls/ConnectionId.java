/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Implementation of DTLS connection id.
 * 
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id">draft-ietf-tls-dtls-connection-id</a>
 */
public class ConnectionId extends Bytes {

	public static final ConnectionId EMPTY = new ConnectionId(Bytes.EMPTY);

	/**
	 * Create connection id from bytes.
	 * 
	 * @param connectionId connectionId bytes
	 * @throws NullPointerException if connectionId is {@code null}
	 * @throws IllegalArgumentException if connectionId length is larger than 255
	 */
	public ConnectionId(byte[] connectionId) {
		super(connectionId);
	}

	@Override
	public String toString() {
		return new StringBuilder("CID=").append(getAsString()).toString();
	}
}
