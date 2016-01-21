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

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

public class DtlsHandshakeException extends DtlsException {

	private static final long serialVersionUID = 1L;

	private final AlertLevel level;
	private final AlertDescription description;

	/**
	 * Constructs a new DTLS exception with the specified detail message, description, level and peer address.
	 * 
	 * @param message the detail message (which is saved for later retrieval by the <code>Throwable.getMessage()</code> method).
	 * @param description the TLS <em>alert description</em> used to characterize the exception.
	 * @param level the TLS <em>alert level</em> indicating the severity of the exception.
	 * @param peer the IP address and port of the DTLS connection peer (which is saved for later retrieval by the
	 *          <code>DtlsException.getPeer()</code> method).
	 */
	public DtlsHandshakeException(String message, AlertDescription description, AlertLevel level, InetSocketAddress peer) {
		super(message, peer);
		if (description == null) {
			throw new NullPointerException("Description must not be null");
		} else if (level == null) {
			throw new NullPointerException("Level must not be null");
		} else {
			this.description = description;
			this.level = level;
		}
	}

	/**
	 * Constructs a new DTLS exception with the specified detail message, description, level, peer address and cause.
	 * <p>
	 * Note that the detail message associated with <code>cause</code> is not automatically incorporated
	 * in this handshake exception's detail message.
	 * </p>
	 * 
	 * @param message the detail message (which is saved for later retrieval by the <code>Throwable.getMessage()</code> method).
	 * @param description the TLS <em>alert description</em> used to characterize the exception.
	 * @param level the TLS <em>alert level</em> indicating the severity of the exception.
	 * @param peer the IP address and port of the DTLS connection peer (which is saved for later retrieval by the
	 *          <code>DtlsException.getPeer()</code> method).
	 * @param cause the cause for this handshake exception (which is saved for later retrieval by the
	 *          <code>Throwable.getCause()</code> method). (A <code>null</code> value is permitted, and indicates
	 *          that the cause is nonexistent or unknown.)
	 */
	public DtlsHandshakeException(String message, AlertDescription description, AlertLevel level, InetSocketAddress peer, Throwable cause) {
		super(message, peer, cause);
		if (description == null) {
			throw new NullPointerException("Description must not be null");
		} else if (level == null) {
			throw new NullPointerException("Level must not be null");
		} else {
			this.description = description;
			this.level = level;
		}
	}

	/**
	 * Gets the TLS <em>alert description</em> used to characterize this handshake exception.
	 * <p>
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.2">TLS 1.2, section 7.2</a> for details
	 * regarding possible values.
	 * </p>
	 * 
	 * @return the alert description
	 */
	public final AlertDescription getDescription() {
		return description;
	}

	public final AlertLevel getLevel() {
		return level;
	}
}
