/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * <code>DtlsException</code> is the superclass of those exceptions that can be thrown
 * in the context of a DTLS connection with a peer.
 */
public class DtlsException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	private final InetSocketAddress peer;

	/**
	 * Constructs a new DTLS exception with the specified detail message and peer address.
	 * 
	 * @param message the detail message (which is saved for later retrieval by the <code>Throwable.getMessage()</code> method).
	 * @param peer the IP address and port of the DTLS connection peer
	 */
	public DtlsException(String message, InetSocketAddress peer) {
		super(message);
		this.peer = peer;
	}

	/**
	 * Constructs a new DTLS exception with the specified detail message, peer address and cause.
	 * <p>
	 * Note that the detail message associated with <code>cause</code> is not automatically incorporated
	 * in this DTLS exception's detail message.
	 * </p>
	 * 
	 * @param message the detail message (which is saved for later retrieval by the <code>Throwable.getMessage()</code> method).
	 * @param peer the IP address and port of the DTLS connection peer
	 * @param cause the cause (which is saved for later retrieval by the <code>Throwable.getCause()</code> method).
	 *          (A <code>null</code> value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	public DtlsException(String message, InetSocketAddress peer, Throwable cause) {
		super(message, cause);
		this.peer = peer;
	}

	/**
	 * The IP and port of the peer of the DTLS connection.
	 * <p>
	 * This exception has occurred in the context of a connection with
	 * the peer identified by the returned address.
	 * </p>
	 * 
	 * @return the address
	 */	
	public final InetSocketAddress getPeer() {
		return peer;
	}
}
