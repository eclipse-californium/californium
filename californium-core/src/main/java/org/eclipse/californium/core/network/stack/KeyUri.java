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

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A key based on a CoAP message's target URI that is scoped to an endpoint
 * address.
 * <p>
 * This class is used by the blockwise layer to correlate blockwise transfer
 * exchanges. 
 * <p>
 * Note: since 3.9, the message code is also used part of the key.
 */
public final class KeyUri {

	private final Code code;
	private final String uri;
	private final Object peersIdentity;
	private final int hash;

	/**
	 * Creates a new key for a URI scoped to an endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param peersIdentity peer's identity. Usually that's the peer's
	 *            {@link InetSocketAddress}.
	 * @throws NullPointerException if uri or address is {@code null}
	 * @since 3.0
	 * @deprecated use KeyUri(String, Object, Code) instead
	 */
	@Deprecated
	public KeyUri(String requestUri, Object peersIdentity) {
		this(requestUri, peersIdentity, null);
	}

	/**
	 * Creates a new key for a URI scoped to an endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param peersIdentity peer's identity. Usually that's the peer's
	 *            {@link InetSocketAddress}.
	 * @param code message code. {@code null} for ping request.
	 * @throws NullPointerException if uri or address is {@code null}
	 * @since 3.9
	 */
	public KeyUri(String requestUri, Object peersIdentity, Code code) {
		if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else if (peersIdentity == null) {
			throw new NullPointerException("peer's identity must not be null");
		} else {
			this.code = code;
			this.uri = requestUri;
			this.peersIdentity = peersIdentity;
			int hash = requestUri.hashCode() * 31 + peersIdentity.hashCode();
			if (code != null) {
				hash = hash * 31 + code.hashCode();
			}
			this.hash = hash;
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
		if (!peersIdentity.equals(other.peersIdentity)) {
			return false;
		}
		if (!uri.equals(other.uri)) {
			return false;
		}
		if (code != other.code && !code.equals(other.code)) {
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
		b.append(code).append(", ").append(uri);
		Object peer = this.peersIdentity;
		if (peer instanceof InetSocketAddress) {
			peer = StringUtil.toDisplayString((InetSocketAddress) peer);
		}
		b.append(", ").append(peer).append("]");
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
	 * Creates a new key scoped to the other peer's identity.
	 * 
	 * @param exchange The exchange with the URI of the requested resource and
	 *            the identity.
	 * @return The key.
	 * @throws NullPointerException if exchange is {@code null}.
	 * @since 3.0
	 */
	public static KeyUri getKey(Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		}
		Request request = exchange.getRequest();
		String uri = getUri(request);
		Code code = request.getCode();
			return new KeyUri(uri, exchange.getPeersIdentity(), code);
	}

}
