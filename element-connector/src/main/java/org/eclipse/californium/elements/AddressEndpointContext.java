/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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

	protected static final int ID_TRUNC_LENGTH = 10;

	private final InetSocketAddress peerAddress;

	private final Principal peerIdentity;

	private final String virtualHost;

	/**
	 * Creates a context for an IP address and port.
	 * 
	 * @param address IP address of peer
	 * @param port port of peer
	 * @throws NullPointerException if provided address is {@code null}.
	 */
	public AddressEndpointContext(InetAddress address, int port) {
		if (address == null) {
			throw new NullPointerException("missing peer inet address!");
		}
		this.peerAddress = new InetSocketAddress(address, port);
		this.peerIdentity = null;
		this.virtualHost = null;
	}

	/**
	 * Creates a context for a socket address.
	 * 
	 * @param peerAddress socket address of peer's service
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public AddressEndpointContext(InetSocketAddress peerAddress) {
		this(peerAddress, null, null);
	}

	/**
	 * Creates a context for a socket address and an authenticated identity.
	 * 
	 * @param peerAddress socket address of peer's service
	 * @param peerIdentity peer's principal
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public AddressEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity) {
		this(peerAddress, null, peerIdentity);
	}

	/**
	 * Create endpoint context with principal.
	 * 
	 * @param peerAddress socket address of peer's service
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer's principal
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public AddressEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity) {
		if (peerAddress == null) {
			throw new NullPointerException("missing peer socket address, must not be null!");
		}
		this.peerAddress = peerAddress;
		this.virtualHost = virtualHost == null ? null : virtualHost.toLowerCase();
		this.peerIdentity = peerIdentity;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return {@code null}
	 */
	@Override
	public String get(String key) {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return an empty map
	 */
	@Override
	public Map<String, String> entries() {
		return Collections.emptyMap();
	}

	@Override
	public boolean hasCriticalEntries() {
		return false;
	}

	@Override
	public final Principal getPeerIdentity() {
		return peerIdentity;
	}

	@Override
	public final InetSocketAddress getPeerAddress() {
		return peerAddress;
	}

	@Override
	public final String getVirtualHost() {
		return virtualHost;
	}

	@Override
	public String toString() {
		return String.format("IP(%s)", getPeerAddressAsString());
	}

	protected final String getPeerAddressAsString() {
		return StringUtil.toString(peerAddress);
	}
}
