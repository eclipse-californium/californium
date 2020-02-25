/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * Raised when an handshake flight timed-out.
 * 
 * @since 2.1
 */
public class DtlsHandshakeTimeoutException extends DtlsException {

	private static final long serialVersionUID = 1L;

	private final int flightNumber;

	public DtlsHandshakeTimeoutException(String message, InetSocketAddress peer, int flightNumber) {
		super(message, peer);
		this.flightNumber = flightNumber;
	}

	/**
	 * For more details on flight numbers, see <a href="https://tools.ietf.org/html/rfc6347#section-4.2.4">RFC 6347 §4.2.4.  Timeout and Retransmission</a>.
	 * 
	 * @return Number of the flight which timed-out.
	 */
	public int getFlightNumber() {
		return flightNumber;
	}
}
