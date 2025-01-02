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
package org.eclipse.californium.core.coap.option;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.CodeClass;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.Names;
import org.eclipse.californium.elements.util.DatagramReader;

/**
 * NoResponseOption.
 * <p>
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
 * @see <a href="https://tools.ietf.org/html/rfc7967" target="_blank"> RFC7967 -
 *      No Server Response</a>
 * @since 4.0 (moved from package org.eclipse.californium.core.coap)
 */
public final class NoResponseOption extends IntegerOption {

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
	 * Creates no-response option.
	 * <p>
	 * If used and errors are not suppressed, this overrides the multicast
	 * behavior to not respond with errors.
	 * 
	 * @param mask bit mask. Use a bitwise or combinations of
	 *            {@link #SUPPRESS_SUCCESS}, {@link #SUPPRESS_CLIENT_ERROR}, or
	 *            {@link #SUPPRESS_SERVER_ERROR}. {@code 0} does not suppress
	 *            any response.
	 * @throws IllegalArgumentException if mask doesn't match the definition.
	 */
	public NoResponseOption(int mask) {
		super(StandardOptionRegistry.NO_RESPONSE, mask);
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
		return getIntegerValue();
	}

	/**
	 * Checks, if response with the code must be suppressed.
	 * <p>
	 * If errors are not suppressed, this overrides the multicast behavior to
	 * not respond with errors.
	 * 
	 * @param code raw response code.
	 * @return {@code true}, if response must be suppressed, {@code false},
	 *         otherwise.
	 */
	public boolean suppress(int code) {
		int bit = 1 << (CoAP.getCodeClass(code) - 1);
		return (getIntegerValue() & bit) != 0;
	}

	/**
	 * Checks, if response with the code must be suppressed.
	 * <p>
	 * If errors are not suppressed, this overrides the multicast behavior to
	 * not respond with errors.
	 * 
	 * @param code response code.
	 * @return {@code true}, if response must be suppressed, {@code false},
	 *         otherwise.
	 */
	public boolean suppress(ResponseCode code) {
		int bit = 1 << (code.codeClass - 1);
		return (getIntegerValue() & bit) != 0;
	}

	@Override
	public String toValueString() {
		int mask = getIntegerValue();
		if ((mask & SUPPRESS_ALL) != 0) {
			StringBuilder text = new StringBuilder("\"NO ");
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
			text.append('"');
			return text.toString();
		} else {
			return "\"ALL\"";
		}
	}

	/**
	 * Definition for no response option.
	 * 
	 * @since 4.0
	 */
	public static class Definition extends IntegerOption.Definition {

		/**
		 * Creates option definition for a no response option.
		 */
		public Definition() {
			super(OptionNumberRegistry.NO_RESPONSE, Names.No_Response, true, 0, 1);
		}

		@Override
		public NoResponseOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			if (length != 0 && length != 1) {
				throw new IllegalArgumentException("Option " + getName() + " value must be empty or 1 byte.");
			}
			int mask = 0;
			if (length == 1) {
				mask = reader.readNextByte() & 0xFF;
			}
			return new NoResponseOption(mask);
		}

		/**
		 * Creates no response option from mask.
		 * 
		 * @param mask bit mask. Use a bitwise or combinations of
		 *            {@link NoResponseOption#SUPPRESS_SUCCESS},
		 *            {@link NoResponseOption#SUPPRESS_CLIENT_ERROR}, or
		 *            {@link NoResponseOption#SUPPRESS_SERVER_ERROR}. {@code 0}
		 *            does not suppress any response.
		 * @return the created no response option.
		 * @throws IllegalArgumentException if mask doesn't match the
		 *             definition.
		 */
		public NoResponseOption create(int mask) {
			return new NoResponseOption(mask);
		}

	}

}
