/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - make all methods static
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;

/**
 * The serializer serializes requests, responses and empty messages to bytes,
 * i.e. {@link RawData}.
 */
public class Serializer {

	private Serializer() {
	}

	/**
	 * Serializes the specified request. Message identifier, message code,
	 * token, options and payload are converted into a byte array and wrapped in
	 * a {@link RawData} object. The request's destination address and port are
	 * stored as address and port in the RawData object.
	 * 
	 * @param request the request
	 * @return the request as raw data
	 */
	public static RawData serialize(Request request) {
		byte[] bytes = request.getBytes();
		if (bytes == null) {
			bytes = DataSerializer.serializeRequest(request);
		}
		request.setBytes(bytes);
		return new RawData(bytes, request.getDestination(), request.getDestinationPort());
	}

	/**
	 * Serializes a given CoAP request.
	 * <p>
	 * Message identifier, message code, token, options and payload are
	 * converted into a byte array and wrapped in a {@link RawData} object. The
	 * request's destination address and port are stored as address and port in
	 * the RawData object.
	 * </p>
	 * 
	 * @param request the request
	 * @param callback the callback the transport layer should invoke to signal
	 *            establishment of message context information. This information
	 *            may be used for matching a response to a request.
	 * @return the request as raw data
	 */
	public static RawData serialize(Request request, MessageCallback callback) {
		byte[] bytes = request.getBytes();
		if (bytes == null) {
			bytes = DataSerializer.serializeRequest(request);
		}
		request.setBytes(bytes);
		return RawData.outbound(bytes, new InetSocketAddress(request.getDestination(), request.getDestinationPort()),
				callback, false);
	}

	/**
	 * Serializes the specified response. Message identifier, message code,
	 * token, options and payload are converted into a byte array and wrapped in
	 * a {@link RawData} object. The response's destination address and port are
	 * stored as address and port in the RawData object.
	 *
	 * @param response the response
	 * @return the response as raw data
	 */
	public static RawData serialize(Response response) {
		byte[] bytes = response.getBytes();
		if (bytes == null) {
			bytes = DataSerializer.serializeResponse(response);
		}
		response.setBytes(bytes);
		return new RawData(bytes, response.getDestination(), response.getDestinationPort());
	}

	/**
	 * Serializes the specified empty message. Message identifier and code are
	 * converted into a byte array and wrapped in a {@link RawData} object. The
	 * message's destination address and port are stored as address and port in
	 * the RawData object.
	 * 
	 * @param message the message
	 * @return the empty message as raw data
	 */
	public static RawData serialize(EmptyMessage message) {
		byte[] bytes = message.getBytes();
		if (bytes == null) {
			bytes = DataSerializer.serializeEmptyMessage(message);
		}
		message.setBytes(bytes);
		return new RawData(bytes, message.getDestination(), message.getDestinationPort());
	}
}
