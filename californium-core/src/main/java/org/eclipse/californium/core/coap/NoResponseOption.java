/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.CodeClass;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.util.Bytes;

/**
 * NoResponseOption.
 * 
 * This option is used to suppress responses by their code class. If errors are
 * not suppressed, this overrides the multicast behavior to not respond with
 * errors, as defined by the RFC 7967, page 6.
 * 
 * <pre>
 * The server MUST send back responses of the classes for which the
 * client has not expressed any disinterest. There may be instances
 * where a server, on its own, decides to suppress responses. An
 * example is suppression of responses by multicast servers as described
 * in Section 2.7 of [RFC7390]. If such a server receives a request
 * with a No-Response option showing ’interest’ in specific response
 * classes (i.e., not expressing disinterest for these options), then
 * any default behavior of suppressing responses, if present, MUST be
 * overridden to deliver those responses that are of interest to the
 * client.
 * </pre>
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7967" target="_blank"> RFC7967 - No Server Response</a>
 * @since 3.0
 */
public final class NoResponseOption {

	/**
	 * Bit to suppress success responses.
	 * 
	 * @see CodeClass#SUCCESS_RESPONSE
	 */
	public static final int SUPPRESS_SUCCESS = 0b00000010;
	/**
	 * Bit to suppress client error responses.
	 * 
	 * @see CodeClass#ERROR_RESPONSE
	 */
	public static final int SUPPRESS_CLIENT_ERROR = 0b00001000;
	/**
	 * Bit to suppress server error responses.
	 * 
	 * @see CodeClass#SERVER_ERROR_RESPONSE
	 */
	public static final int SUPPRESS_SERVER_ERROR = 0b00010000;
	/**
	 * Suppress all responses.
	 */
	public static final int SUPPRESS_ALL = SUPPRESS_SUCCESS | SUPPRESS_CLIENT_ERROR | SUPPRESS_SERVER_ERROR;

	/**
	 * Bit mask with suppressed code classes.
	 */
	private final int mask;

	/**
	 * Create no-response option.
	 * 
	 * If used and errors are not suppressed, this overrides the multicast
	 * behavior to not respond with errors.
	 * 
	 * @param mask bit mask. Use a bitwise or combinations of
	 *            {@link #SUPPRESS_SUCCESS}, {@link #SUPPRESS_CLIENT_ERROR}, or
	 *            {@link #SUPPRESS_SERVER_ERROR}. {@code 0} does not suppress
	 *            any response.
	 */
	public NoResponseOption(int mask) {
		if (mask < 0 || mask > 255) {
			throw new IllegalArgumentException("No-Response option " + mask + " must be between 0 and 255 inclusive");
		}
		this.mask = mask;
	}

	/**
	 * Get encoded option value.
	 * 
	 * @return byte array with encoded option value
	 */
	public byte[] getValue() {
		if (mask == 0) {
			return Bytes.EMPTY;
		} else {
			return new byte[] { (byte) mask };
		}
	}

	/**
	 * Gets the bit mask of suppress response code classes.
	 *
	 * @return the mask
	 * @see #SUPPRESS_SUCCESS
	 * @see #SUPPRESS_CLIENT_ERROR
	 * @see #SUPPRESS_SERVER_ERROR
	 */
	public int getMask() {
		return mask;
	}

	/**
	 * Check, if response with the code must be suppressed.
	 * 
	 * If errors are not suppressed, this overrides the multicast behavior to
	 * not respond with errors.
	 * 
	 * @param code raw response code.
	 * @return {@code true}, if response must be suppressed, {@code false},
	 *         otherwise.
	 */
	public boolean suppress(int code) {
		int bit = 1 << (CoAP.getCodeClass(code) - 1);
		return (mask & bit) != 0;
	}

	/**
	 * Check, if response with the code must be suppressed.
	 * 
	 * If errors are not suppressed, this overrides the multicast behavior to
	 * not respond with errors.
	 * 
	 * @param code response code.
	 * @return {@code true}, if response must be suppressed, {@code false},
	 *         otherwise.
	 */
	public boolean suppress(CoAP.ResponseCode code) {
		int bit = 1 << (code.codeClass - 1);
		return (mask & bit) != 0;
	}

	/**
	 * Convert to generic {@link Option}.
	 * 
	 * @return generic option.
	 */
	public Option toOption() {
		return StandardOptionRegistry.NO_RESPONSE.create(getValue());
	}

	@Override
	public String toString() {
		if ((mask & SUPPRESS_ALL) != 0) {
			StringBuilder text = new StringBuilder("NO ");
			if ((mask & SUPPRESS_SUCCESS) != 0) {
				text.append("SUCCESS,");
			}
			if ((mask & SUPPRESS_CLIENT_ERROR) != 0) {
				text.append("CLIENT_ERROR,");
			}
			if ((mask & SUPPRESS_SERVER_ERROR) != 0) {
				text.append("SERVER_ERROR,");
			}
			text.setLength(text.length() - 1);
			return text.toString();
		} else {
			return "ALL";
		}
	}

	@Override
	public boolean equals(final Object o) {
		if (!(o instanceof NoResponseOption)) {
			return false;
		}
		NoResponseOption option = (NoResponseOption) o;
		return mask == option.mask;
	}

	@Override
	public int hashCode() {
		return mask;
	}
}
