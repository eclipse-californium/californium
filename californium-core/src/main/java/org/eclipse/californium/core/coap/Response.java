/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - move payload string conversion
 *    												  from toString() to
 *                                                    Message.getPayloadTracingString(). 
 *                                                    (for message tracing)
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.stack.ReliabilityLayer;

/**
 * Response represents a CoAP response to a CoAP request.
 * <p>
 * A response is either a <em>piggy-backed</em> response of type {@code ACK} or
 * a <em>separate</em> response of type {@code CON} or {@code NON}.
 * Each response carries a ({@link CoAP.ResponseCode}) indicating the outcome
 * of the request it is the response for.
 * 
 * @see Request
 */
public class Response extends Message {

	/** The response code. */
	private final CoAP.ResponseCode code;

	private long rtt;

	private boolean last = true;

	/**
	 * Creates a response to the specified request with the specified response
	 * code. The destination address of the response is the source address of
	 * the request.
	 * Type and MID are usually set automatically by the {@link ReliabilityLayer}.
	 * The token is set automatically by the {@link Matcher}.
	 *
	 * @param request
	 *            the request
	 * @param code
	 *            the code
	 * @return the response
	 */
	public static Response createResponse(Request request, ResponseCode code) {
		Response response = new Response(code);
		response.setDestination(request.getSource());
		response.setDestinationPort(request.getSourcePort());
		return response;
	}

	/**
	 * Instantiates a new response with the specified response code.
	 *
	 * @param code the response code
	 */
	public Response(ResponseCode code) {
		this.code = code;
	}

	/**
	 * Gets the response code.
	 *
	 * @return the code
	 */
	public CoAP.ResponseCode getCode() {
		return code;
	}

	@Override
	public int getRawCode() {
		return code.value;
	}

	@Override
	public String toString() {
		String payload = getPayloadTracingString();
		return String.format("%s-%-6s MID=%5d, Token=%s, OptionSet=%s, %s", getType(), getCode(), getMID(), getTokenString(), getOptions(), payload);
	}

	/**
	 * Checks whether this is the last response expected for the exchange it is part of.
	 * 
	 * @return {@code true} if this is the last expected response.
	 */
	public boolean isLast() {
		return last;
	}

	/**
	 * Defines whether this response is the last response of an exchange.
	 * <p>
	 * If this is only a block or a notification, the response might not be the
	 * last one.
	 * 
	 * @param last if this is the last response of an exchange
	 */
	public void setLast(boolean last) {
		this.last = last;
	}

	public long getRTT() {
		return rtt;
	}

	public void setRTT(long rtt) {
		this.rtt = rtt;
	}

	/**
	 * Checks whether this response is a notification for
	 * an observed resource.
	 * 
	 * @return {@code true} if this response has the observe option set.
	 */
	public boolean isNotification() {
		return getOptions().hasObserve();
	}

	/**
	 * Checks whether this response has either a <em>block1</em> or
	 * <em>block2</em> option.
	 * 
	 * @return {@code true} if this response has a block option.
	 */
	public boolean hasBlockOption() {
		return getOptions().hasBlock1() || getOptions().hasBlock2();
	}

	/**
	 * Checks whether this response's code indicates an error.
	 * 
	 * @return {@code true} if <em>code</em> indicates an error.
	 */
	public final boolean isError() {
		return isClientError() || isServerError();
	}

	/**
	 * Checks whether this response's code indicates a client error.
	 * 
	 * @return {@code true} if <em>code</em> indicates a client error.
	 */
	public final boolean isClientError() {
		return ResponseCode.isClientError(code);
	}

	/**
	 * Checks whether this response's code indicates a server error.
	 * 
	 * @return {@code true} if <em>code</em> indicates a server error.
	 */
	public final boolean isServerError() {
		return ResponseCode.isServerError(code);
	}
}
