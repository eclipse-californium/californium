/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove etag
 *                                                    issue #529
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * A key based on a CoAP message's target URI that is scoped to an endpoint address.
 * <p>
 * This class is used by the blockwise layer to correlate blockwise transfer exchanges.
 */
public final class KeyUri {

	private static final int MAX_PORT_NO = (1 << 16) - 1;
	private final String uri;
	private final byte[] address;
	private final int port;
	private final int hash;

	/**
	 * Creates a new key for a URI scoped to an endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param address the endpoint's address.
	 * @param port the endpoint's port.
	 * @throws NullPointerException if uri or address is {@code null}
	 * @throws IllegalArgumentException if port &lt; 0 or port &gt; 65535.
	 */
	public KeyUri(final String requestUri, final byte[] address, final int port) {
		if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else if (address == null) {
			throw new NullPointerException("address must not be null");
		} else if (port < 0 || port > MAX_PORT_NO) {
			throw new IllegalArgumentException("port must be an unsigned 16 bit int");
		} else {
			this.uri = requestUri;
			this.address = address;
			this.port = port;
			this.hash = (port * 31 + requestUri.hashCode()) * 31 + Arrays.hashCode(address);
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		KeyUri other = (KeyUri) obj;
		if (!Arrays.equals(address, other.address)) {
			return false;
		}
		if (port != other.port) {
			return false;
		}
		if (uri == null) {
			if (other.uri != null) {
				return false;
			}
		} else if (!uri.equals(other.uri)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public String toString() {
		StringBuilder b = new StringBuilder("KeyUri[");
		b.append(uri);
		b.append(", ").append(Utils.toHexString(address)).append(":").append(port).append("]");
		return b.toString();
	}

	/**
	 * Get URI from request.
	 * 
	 * Contains URI path and URI query.
	 * 
	 * @param request request containing the URI.
	 * @return URI string of request
	 * @throws NullPointerException if request is {@code null}.
	 */
	private static String getUri(final Request request) {
		if (request == null) {
			throw new NullPointerException("request must not be null");
		}
		return request.getScheme() + ":" + request.getOptions().getUriString();
	}

	/**
	 * Creates a new key for an incoming response scoped to the response's source endpoint address.
	 * 
	 * @param request The request with the URI of the requested resource.
	 * @param response The response.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public static KeyUri fromInboundResponse(final Request request, final Response response) {
		if (response == null) {
			throw new NullPointerException("response must not be null");
		} else {
			InetSocketAddress address = response.getSourceContext().getPeerAddress();
			return new KeyUri(getUri(request), address.getAddress().getAddress(), address.getPort());
		}
	}

	/**
	 * Creates a new key for an outgoing response scoped to the response's destination endpoint address.
	 * 
	 * @param request The request with the URI of the requested resource.
	 * @param response The response.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public static KeyUri fromOutboundResponse(final Request request, final Response response) {
		if (response == null) {
			throw new NullPointerException("response must not be null");
		} else {
			InetSocketAddress address = response.getDestinationContext().getPeerAddress();
			return new KeyUri(getUri(request), address.getAddress().getAddress(), address.getPort());
		}
	}

	/**
	 * Creates a new key for an incoming request scoped to the request's source endpoint address.
	 * 
	 * @param request The request.
	 * @return The key.
	 * @throws NullPointerException if the request is {@code null}.
	 */
	public static KeyUri fromInboundRequest(final Request request) {
		String uri = getUri(request);
		InetSocketAddress address = request.getSourceContext().getPeerAddress();
		return new KeyUri(uri, address.getAddress().getAddress(), address.getPort());
	}

	/**
	 * Creates a new key for an outgoing request scoped to the request's destination endpoint address.
	 * 
	 * @param request The request.
	 * @return The key.
	 * @throws NullPointerException if the request is {@code null}.
	 */
	public static KeyUri fromOutboundRequest(final Request request) {
		String uri = getUri(request);
		InetSocketAddress address = request.getDestinationContext().getPeerAddress();
		return new KeyUri(uri, address.getAddress().getAddress(), address.getPort());
	}
}
