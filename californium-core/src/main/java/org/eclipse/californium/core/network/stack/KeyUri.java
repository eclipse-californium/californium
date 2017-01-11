/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Arrays;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.OptionSet;
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
	private byte[] eTag;

	/**
	 * Creates a new key for a URI scoped to an endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param options The options contained in the message.
	 * @param address the endpoint's address.
	 * @param port the endpoint's port.
	 * @throws NullPointerException if uri or address is {@code null}
	 * @throws IllegalArgumentException if port &lt; 0 or port &gt; 65535.
	 */
	public KeyUri(final String requestUri, final OptionSet options, final byte[] address, final int port) {
		if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else if (options == null) {
			throw new NullPointerException("OptionSet must not be null");
		} else if (address == null) {
			throw new NullPointerException("address must not be null");
		} else if (port < 0 || port > MAX_PORT_NO) {
			throw new IllegalArgumentException("port must be an unsigned 16 bit int");
		} else {
			this.uri = requestUri;
			this.address = address;
			this.port = port;
			int hashCode = (port * 31 + requestUri.hashCode()) * 31 + Arrays.hashCode(address);
			if (options.getETagCount() > 0) {
				this.eTag = options.getETags().get(0);
				hashCode = hashCode * 31 + Arrays.hashCode(eTag);
			}
			this.hash = hashCode;
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
		if (!Arrays.equals(eTag, other.eTag)) {
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
		if (eTag != null) {
			b.append("[").append(Utils.toHexString(eTag)).append("]");
		}
		b.append(", ").append(Utils.toHexString(address)).append(":").append(port).append("]");
		return b.toString();
	}

	/**
	 * Creates a new key for an incoming response scoped to the response's source endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param response The response.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public static KeyUri fromInboundResponse(final String requestUri, final Response response) {
		if (response == null) {
			throw new NullPointerException("response must not be null");
		} else if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else {
			return new KeyUri(requestUri, response.getOptions(), response.getSource().getAddress(), response.getSourcePort());
		}
	}

	/**
	 * Creates a new key for an outgoing response scoped to the response's destination endpoint address.
	 * 
	 * @param requestUri The URI of the requested resource.
	 * @param response The response.
	 * @return The key.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public static KeyUri fromOutboundResponse(final String requestUri, final Response response) {
		if (response == null) {
			throw new NullPointerException("response must not be null");
		} else if (requestUri == null) {
			throw new NullPointerException("URI must not be null");
		} else {
			return new KeyUri(requestUri, response.getOptions(), response.getDestination().getAddress(), response.getDestinationPort());
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
		if (request == null) {
			throw new NullPointerException("request must not be null");
		} else {
			return new KeyUri(request.getURI(), request.getOptions(), request.getSource().getAddress(), request.getSourcePort());
		}
	}

	/**
	 * Creates a new key for an outgoing request scoped to the request's destination endpoint address.
	 * 
	 * @param request The request.
	 * @return The key.
	 * @throws NullPointerException if the request is {@code null}.
	 */
	public static KeyUri fromOutboundRequest(final Request request) {
		if (request == null) {
			throw new NullPointerException("request must not be null");
		} else {
			return new KeyUri(request.getURI(), request.getOptions(), request.getDestination().getAddress(), request.getDestinationPort());
		}
	}
}