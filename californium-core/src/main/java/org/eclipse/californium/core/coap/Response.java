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
 *    Achim Kraus (Bosch Software Innovations GmbH) - move payload string conversion
 *                                                    from toString() to
 *                                                    Message.getPayloadTracingString(). 
 *                                                    (for message tracing)
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce source and destination
 *                                                    EndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - change type for rtt to Long
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove "is last", not longer meaningful
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

	/**
	 * RTT (round trip time) in milliseconds.
	 */
	private volatile Long rtt;

	/**
	 * Creates a response to the provided received request with the specified
	 * response code. The destination endpoint context of the response will be
	 * the source endpoint context of the request. Type and MID are usually set
	 * automatically by the {@link ReliabilityLayer}. The token is set
	 * automatically by the {@link Matcher}.
	 *
	 * @param receivedRequest the request
	 * @param code the code
	 * @return the response
	 * @throws IllegalArgumentException if request has no source endpoint
	 *             context.
	 * @throws NullPointerException if receivedRequest or code is {@code null}
	 *             (since 2.3, before that this was thrown delayed, when
	 *             accessing the code)
	 */
	public static Response createResponse(Request receivedRequest, ResponseCode code) {
		if (receivedRequest == null) {
			throw new NullPointerException("received request must not be null!");
		}
		if (receivedRequest.getSourceContext() == null) {
			throw new IllegalArgumentException("received request must contain a source context.");
		}
		Response response = new Response(code);
		response.setDestinationContext(receivedRequest.getSourceContext());
		return response;
	}

	/**
	 * Instantiates a new response with the specified response code.
	 *
	 * @param code the response code
	 * @throws NullPointerException if code is {@code null} (since 2.3, before
	 *             that this was thrown delayed, when accessing the code)
	 */
	public Response(ResponseCode code) {
		if (code == null) {
			throw new NullPointerException("ResponseCode must not be null!");
		}
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
	public void assertPayloadMatchsBlocksize() {
		BlockOption block2 = getOptions().getBlock2();
		if (block2 != null) {
			block2.assertPayloadSize(getPayloadSize());
		}
	}

	@Override
	public String toString() {
		return toTracingString(code.toString());
	}

	/**
	 * Return RTT (round trip time).
	 * 
	 * @return RTT in milliseconds, or {@code null}, if not set.
	 */
	public Long getRTT() {
		return rtt;
	}

	/**
	 * Set RTT (round trip time) .
	 * 
	 * @param rtt round trip time of response in milliseconds
	 */
	public void setRTT(long rtt) {
		this.rtt = rtt;
	}

	/**
	 * Ensure, that the response uses the provided token.
	 * 
	 * @param token token to ensure to be used by the response.
	 * @throws IllegalArgumentException if token differs
	 */
	public void ensureToken(Token token) {
		Token current = getToken();
		if (current == null) {
			setToken(token);
		} else if (!current.equals(token)) {
			throw new IllegalArgumentException("token mismatch! (" + current + "!=" + token + ")");
		}
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

	@Override
	public boolean hasBlock(final BlockOption block) {
		return hasBlock(block, getOptions().getBlock2());
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
