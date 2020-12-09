/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - add toHexText 
 *                                                    (for message tracing)
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace '\n' with 
 *                                                    System.lineSeparator() 
 *    Achim Kraus (Bosch Software Innovations GmbH) - add rtt
 ******************************************************************************/
package org.eclipse.californium.core;

import java.security.Principal;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Auxiliary helper methods for Californium.
 */
public final class Utils {

	/*
	 * Prevent initialization
	 */
	private Utils() {
		// nothing to do
	}

	/**
	 * Converts the specified byte array to a hexadecimal string.
	 *
	 * @param bytes the byte array
	 * @return the hexadecimal code string
	 */
	public static String toHexString(byte[] bytes) {
		if (bytes == null) {
			return "null";
		} else {
			return "[" + StringUtil.byteArray2Hex(bytes) + "]";
		}
	}

	/**
	 * Converts the specified byte array up to the specified length into a hexadecimal text.
	 * Separate bytes by spaces and group them in lines. Append length of array, if specified 
	 * length is smaller then the length of the array.
	 * 
	 * @param bytes the array of bytes. If null, the text "null" is returned.
	 * @param length length up to the bytes should be converted into hexadecimal text. 
	 *               If larger then the array length, reduce it to the array length.
	 * @return byte array as hexadecimal text
	 */
	public static String toHexText(byte[] bytes, int length) {
		if (bytes == null) return "null";
		if (length > bytes.length) length = bytes.length;
		StringBuilder sb = new StringBuilder();
		if (16 < length) sb.append(StringUtil.lineSeparator());
		for(int index = 0; index < length; ++index) {
			sb.append(String.format("%02x", bytes[index] & 0xFF));
			if (31 == (31 & index)) {
				sb.append(StringUtil.lineSeparator());
			} else {
				sb.append(' ');
			}
		}
		if (length < bytes.length) {
			sb.append(" .. ").append(bytes.length).append(" bytes");
		}
		return sb.toString();
	}

	/**
	 * Formats a {@link Request} into a readable String representation. 
	 * 
	 * @param r the Request
	 * @return the pretty print
	 */
	public static String prettyPrint(Request r) {

		String nl = StringUtil.lineSeparator();
		StringBuilder sb = new StringBuilder();

		sb.append("==[ CoAP Request ]=============================================").append(nl);
		sb.append(String.format("MID    : %d%n", r.getMID()));
		sb.append(String.format("Token  : %s%n", r.getTokenString()));
		sb.append(String.format("Type   : %s%n", r.getType()));
		Code code = r.getCode();
		if (code == null) {
			sb.append("Method : 0.00 - PING").append(nl);
		} else {
			sb.append(String.format("Method : %s - %s%n", code.text, code.name()));
		}
		if (r.getOffloadMode() != null) {
			sb.append("(offloaded)").append(nl);
		} else {
			sb.append(String.format("Options: %s%n", r.getOptions()));
			sb.append(String.format("Payload: %d Bytes%n", r.getPayloadSize()));
			if (r.getPayloadSize() > 0 && MediaTypeRegistry.isPrintable(r.getOptions().getContentFormat())) {
				sb.append("---------------------------------------------------------------").append(nl);
				sb.append(r.getPayloadString());
				sb.append(nl);
			}
		}
		sb.append("===============================================================");

		return sb.toString();
	}

	/**
	 * Formats a {@link CoapResponse} into a readable String representation. 
	 * 
	 * @param r the CoapResponse
	 * @return the pretty print
	 */
	public static String prettyPrint(CoapResponse r) {
		return prettyPrint(r.advanced());
	}

	/**
	 * Formats a {@link Response} into a readable String representation. 
	 * 
	 * @param r the Response
	 * @return the pretty print
	 */
	public static String prettyPrint(Response r) {
		String nl = StringUtil.lineSeparator();
		StringBuilder sb = new StringBuilder();

		sb.append("==[ CoAP Response ]============================================").append(nl);
		sb.append(String.format("MID    : %d%n", r.getMID()));
		sb.append(String.format("Token  : %s%n", r.getTokenString()));
		sb.append(String.format("Type   : %s%n", r.getType()));
		ResponseCode code = r.getCode();
		sb.append(String.format("Status : %s - %s%n", code, code.name()));
		if (r.getOffloadMode() != null) {
			if (r.getRTT() != null) {
				sb.append(String.format("RTT    : %d ms%n", r.getRTT()));
				sb.append("(offloaded)").append(nl);
			}
		} else {
			sb.append(String.format("Options: %s%n", r.getOptions()));
			if (r.getRTT() != null) {
				sb.append(String.format("RTT    : %d ms%n", r.getRTT()));
			}
			sb.append(String.format("Payload: %d Bytes%n", r.getPayloadSize()));
			if (r.getPayloadSize() > 0 && MediaTypeRegistry.isPrintable(r.getOptions().getContentFormat())) {
				sb.append("---------------------------------------------------------------").append(nl);
				sb.append(r.getPayloadString());
				sb.append(nl);
			}
		}
		sb.append("===============================================================");

		return sb.toString();
	}

	/**
	 * Formats a {@link EndpointContext} into a readable String representation. 
	 * 
	 * @param endpointContext the EndpointContext
	 * @return the pretty print
	 * @since 2.3
	 */
	public static String prettyPrint(EndpointContext endpointContext) {
		String nl = StringUtil.lineSeparator();
		StringBuilder sb = new StringBuilder();

		sb.append(">>> ").append(endpointContext);
		String cipher = endpointContext.getString(DtlsEndpointContext.KEY_CIPHER);
		if (cipher == null) {
			cipher = endpointContext.getString(TlsEndpointContext.KEY_CIPHER);
		}
		if (cipher != null) {
			sb.append(nl).append(">>> ").append(cipher);
		}
		Principal principal = endpointContext.getPeerIdentity();
		if (principal != null) {
			sb.append(nl).append(">>> ").append(principal);
		}
		return sb.toString();
	}
}
