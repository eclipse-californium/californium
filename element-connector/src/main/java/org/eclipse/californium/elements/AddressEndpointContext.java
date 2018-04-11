/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A endpoint context providing the inet socket address and a optional
 * principal.
 */
public class AddressEndpointContext implements EndpointContext {

	protected static final int ID_TRUNC_LENGTH = 6;

	private final InetSocketAddress peerAddress;

	private final Principal peerIdentity;

	/**
	 * Create endpoint context without principal.
	 * 
	 * @param peerAddress socket address of peer's service
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public AddressEndpointContext(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("missing peer socket address!");
		}
		this.peerAddress = peerAddress;
		this.peerIdentity = null;
	}

	/**
	 * Create endpoint context without principal.
	 * 
	 * @param address inet address of peer
	 * @param port port of peer
	 * @throws NullPointerException if provided address is {@code null}.
	 */
	public AddressEndpointContext(InetAddress address, int port) {
		if (address == null) {
			throw new NullPointerException("missing peer inet address!");
		}
		this.peerAddress = new InetSocketAddress(address, port);
		this.peerIdentity = null;
	}

	/**
	 * Create endpoint context with principal.
	 * 
	 * @param peerAddress socket address of peer's service
	 * @param peerIdentity peer's principal
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public AddressEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity) {
		if (peerAddress == null) {
			throw new NullPointerException("missing peer socket address, must not be null!");
		}
		this.peerAddress = peerAddress;
		this.peerIdentity = peerIdentity;
	}

	@Override
	public String get(String key) {
		return null;
	}

	@Override
	public Map<String, String> entries() {
		return Collections.emptyMap();
	}

	@Override
	public boolean inhibitNewConnection() {
		return false;
	}

	@Override
	public Principal getPeerIdentity() {
		return peerIdentity;
	}

	@Override
	public InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	@Override
	public int hashCode() {
		int result = peerAddress.hashCode();
		if (peerIdentity != null) {
			result = peerIdentity.hashCode();
		}
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof AddressEndpointContext)) {
			return false;
		}
		AddressEndpointContext other = (AddressEndpointContext) obj;
		if (!peerAddress.equals(other.getPeerAddress())) {
			return false;
		}
		if (peerIdentity != null) {
			if (!peerIdentity.equals(other.getPeerIdentity())) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		return String.format("IP(%s)", getPeerAddressAsString());
	}

	protected String getPeerAddressAsString() {
		return StringUtil.toString(peerAddress);
	}
}
