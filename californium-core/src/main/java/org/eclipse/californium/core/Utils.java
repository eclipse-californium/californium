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
import java.util.concurrent.TimeUnit;

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
	 * Formats a {@link Request} into a readable String representation. 
	 * 
	 * @param request the Request
	 * @return the pretty print
	 */
	public static String prettyPrint(Request request) {

		String nl = StringUtil.lineSeparator();
		StringBuilder sb = new StringBuilder();

		sb.append("==[ CoAP Request ]=============================================").append(nl);
		sb.append(String.format("MID    : %d%n", request.getMID()));
		sb.append(String.format("Token  : %s%n", request.getTokenString()));
		sb.append(String.format("Type   : %s%n", request.getType()));
		Code code = request.getCode();
		if (code == null) {
			sb.append("Method : 0.00 - PING").append(nl);
		} else {
			sb.append(String.format("Method : %s - %s%n", code.text, code.name()));
		}
		if (request.getOffloadMode() != null) {
			sb.append("(offloaded)").append(nl);
		} else {
			sb.append(String.format("Options: %s%n", request.getOptions()));
			sb.append(String.format("Payload: %d Bytes%n", request.getPayloadSize()));
			if (request.getPayloadSize() > 0 && MediaTypeRegistry.isPrintable(request.getOptions().getContentFormat())) {
				sb.append("---------------------------------------------------------------").append(nl);
				sb.append(request.getPayloadString());
				sb.append(nl);
			}
		}
		sb.append("===============================================================");

		return sb.toString();
	}

	/**
	 * Formats a {@link CoapResponse} into a readable String representation. 
	 * 
	 * @param response the CoapResponse
	 * @return the pretty print
	 */
	public static String prettyPrint(CoapResponse response) {
		return prettyPrint(response.advanced());
	}

	/**
	 * Formats a {@link Response} into a readable String representation. 
	 * 
	 * @param response the Response
	 * @return the pretty print
	 */
	public static String prettyPrint(Response response) {
		String nl = StringUtil.lineSeparator();
		StringBuilder sb = new StringBuilder();

		sb.append("==[ CoAP Response ]============================================").append(nl);
		sb.append(String.format("MID    : %d%n", response.getMID()));
		sb.append(String.format("Token  : %s%n", response.getTokenString()));
		sb.append(String.format("Type   : %s%n", response.getType()));
		ResponseCode code = response.getCode();
		sb.append(String.format("Status : %s - %s%n", code, code.name()));
		Long rtt = response.getApplicationRttNanos();
		if (response.getOffloadMode() != null) {
			if (rtt != null) {
				sb.append(String.format("RTT    : %d ms%n", TimeUnit.NANOSECONDS.toMillis(rtt)));
			}
			sb.append("(offloaded)").append(nl);
		} else {
			sb.append(String.format("Options: %s%n", response.getOptions()));
			if (rtt != null) {
				sb.append(String.format("RTT    : %d ms%n", TimeUnit.NANOSECONDS.toMillis(rtt)));
			}
			sb.append(String.format("Payload: %d Bytes%n", response.getPayloadSize()));
			if (response.getPayloadSize() > 0 && MediaTypeRegistry.isPrintable(response.getOptions().getContentFormat())) {
				sb.append("---------------------------------------------------------------").append(nl);
				sb.append(response.getPayloadString());
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
		String cid = endpointContext.getString(DtlsEndpointContext.KEY_READ_CONNECTION_ID);
		if (cid != null) {
			sb.append(nl).append(">>> read-cid : ").append(cid);
		}
		cid = endpointContext.getString(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		if (cid != null) {
			sb.append(nl).append(">>> write-cid: ").append(cid);
		}
		return sb.toString();
	}
}
