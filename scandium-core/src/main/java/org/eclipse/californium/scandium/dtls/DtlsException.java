/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * {@code DtlsException} is the superclass of those exceptions that can be thrown
 * in the context of DTLS.
 */
public class DtlsException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a new DTLS exception with the specified detail message.
	 * 
	 * @param message the detail message (which is saved for later retrieval by the {@code Throwable.getMessage()} method).
	 */
	public DtlsException(String message) {
		super(message);
	}

	/**
	 * Constructs a new DTLS exception with the specified detail message and cause.
	 * <p>
	 * Note that the detail message associated with {@code cause} is not automatically incorporated
	 * in this DTLS exception's detail message.
	 * </p>
	 * 
	 * @param message the detail message (which is saved for later retrieval by the {@code Throwable.getMessage()} method).
	 * @param cause the cause (which is saved for later retrieval by the {@code Throwable.getCause()} method).
	 *          (A {@code null} value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	public DtlsException(String message, Throwable cause) {
		super(message, cause);
	}
}
