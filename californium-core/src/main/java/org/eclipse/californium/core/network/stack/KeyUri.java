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

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A key based on a CoAP message's target URI that is scoped to an endpoint
 * address.
 * <p>
 * This class is used by the blockwise layer to correlate blockwise transfer
 * exchanges.
 */
public final class KeyUri {

	private final String uri;
	private final InetSocketAddress address;
	private final int hash;

	/**
	 * Creates a new key for a URI scoped to an endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param address the endpoint's address.
	 * @throws NullPointerException if uri or address is {@code null}
	 * @since 3.0
	 */
	public KeyUri(final String requestUri, final InetSocketAddress address) {
		if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else if (address == null) {
			throw new NullPointerException("address must not be null");
		} else {
			this.uri = requestUri;
			this.address = address;
			this.hash = requestUri.hashCode() * 31 + address.hashCode();
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
		if (!address.equals(other.address)) {
			return false;
		}
		if (!uri.equals(other.uri)) {
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
		b.append(", ").append(StringUtil.toDisplayString(address)).append("]");
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
	 * Creates a new key for a request scoped to the other peer's address.
	 * 
	 * @param exchange The exchange.
	 * @param request The request with the URI of the resource.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @since 3.0
	 */
	public static KeyUri getKey(Exchange exchange, Request request) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		}
		String uri = getUri(request);
		EndpointContext peer;
		if (exchange.isOfLocalOrigin()) {
			peer = request.getDestinationContext();
		} else {
			peer = request.getSourceContext();
		}
		return new KeyUri(uri, peer.getPeerAddress());
	}

	/**
	 * Creates a new key for a response scoped to the other peer's address.
	 * 
	 * @param exchange The exchange with the URI of the requested resource.
	 * @param response The response.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @since 3.0
	 */
	public static KeyUri getKey(final Exchange exchange, final Response response) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		}
		String uri = getUri(exchange.getRequest());
		EndpointContext peer;
		if (exchange.isOfLocalOrigin()) {
			peer = response.getSourceContext();
		} else {
			peer = response.getDestinationContext();
		}
		return new KeyUri(uri, peer.getPeerAddress());
	}

}
