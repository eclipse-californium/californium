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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;

/**
 * This exception is thrown when a MAC validation fails.
 * 
 */
public class InvalidMacException extends GeneralSecurityException {

	private static final long serialVersionUID = 1L;

	private byte[] expected;
	private byte[] actual;
	
	/**
	 * Sets the expected and actual MAC values.
	 * 
	 * @param expected the expected MAC value
	 * @param actual the actual MAC value
	 */
	public InvalidMacException(byte[] expected, byte[] actual) {
		super("MAC validation failed");
		this.expected = expected;
		this.actual = actual;
	}

	public final byte[] getExpected() {
		return expected;
	}

	public final byte[] getActual() {
		return actual;
	}

}
