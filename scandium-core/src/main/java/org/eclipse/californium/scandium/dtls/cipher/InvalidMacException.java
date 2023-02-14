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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.eclipse.californium.elements.util.Bytes;

/**
 * This exception is thrown when a MAC validation fails.
 * 
 */
public class InvalidMacException extends GeneralSecurityException {

	private static final long serialVersionUID = 1L;
	private static final String DEFAULT_MESSAGE = "MAC validation failed!";

	private final byte[] expected;
	private final byte[] actual;

	/**
	 * Create generic invalid MAC exception without actual MAC values.
	 */
	public InvalidMacException() {
		this(DEFAULT_MESSAGE);
	}

	/**
	 * Create invalid MAC exception without actual MAC values.
	 * 
	 * @param msg message
	 */
	public InvalidMacException(String msg) {
		super(msg);
		this.expected = Bytes.EMPTY;
		this.actual = Bytes.EMPTY;
	}

	/**
	 * Sets the expected and actual MAC values.
	 * 
	 * @param expected the expected MAC value
	 * @param actual the actual MAC value
	 */
	public InvalidMacException(final byte[] expected, final byte[] actual) {
		super(DEFAULT_MESSAGE);
		this.expected = Arrays.copyOf(expected, expected.length);
		this.actual = Arrays.copyOf(actual, actual.length);
	}

	public final byte[] getExpected() {
		return expected;
	}

	public final byte[] getActual() {
		return actual;
	}
}
