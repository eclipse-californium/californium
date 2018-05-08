/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 *    Achim Kraus (Bosch Software Innovations GmbH) - make entries map unmodifiable
 *    Achim Kraus (Bosch Software Innovations GmbH) - add constructor with attributes map
 *                                                    to support cloning
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A map based endpoint context.
 */
public class MapBasedEndpointContext extends AddressEndpointContext {

	private final Map<String, String> entries;

	/**
	 * Creates a context for a socket address, authenticated identity and arbitrary
	 * key/value pairs.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)
	 * @throws NullPointerException if provided peer address is {@code null}, or
	 *             one of the attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd
	 *             size or contains a duplicate key.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String... attributes) {

		this(peerAddress, null, peerIdentity, attributes);
	}

	/**
	 * Creates a context for a socket address, authenticated identity and arbitrary
	 * key/value pairs.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)
	 * @throws NullPointerException if provided peer address is {@code null}, or
	 *             one of the attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd
	 *             size or contains a duplicate key.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			String... attributes) {

		super(peerAddress, virtualHost, peerIdentity);

		if ((attributes.length & 1) == 0) {
			Map<String, String> newEntries = new HashMap<>();
			for (int index = 0; index < attributes.length; ++index) {
				String key = attributes[index];
				String value = attributes[++index];
				if (null == key) {
					throw new NullPointerException((index / 2) + ". key is null");
				}
				if (null == value) {
					throw new NullPointerException((index / 2) + ". value is null");
				}
				String old = newEntries.put(key, value);
				if (null != old) {
					throw new IllegalArgumentException((index / 2) + ". key '" + key + "' is provided twice");
				}
			}
			this.entries = Collections.unmodifiableMap(newEntries);
		} else {
			throw new IllegalArgumentException("number of attributes must be even, not " + attributes.length + "!");
		}
	}

	/**
	 * Creates a new endpoint context with correlation context support.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes map of attributes
	 * @throws NullPointerException if provided peer address, or attributes map
	 *             is {@code null}.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity,
			Map<String, String> attributes) {

		this(peerAddress, null, peerIdentity, attributes);
	}

	/**
	 * Creates a new endpoint context with correlation context support.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes map of attributes
	 * @throws NullPointerException if provided peer address, or attributes map
	 *             is {@code null}.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			Map<String, String> attributes) {

		super(peerAddress, virtualHost, peerIdentity);

		if (attributes == null) {
			throw new NullPointerException("missing attributes map, must not be null!");
		}
		this.entries = Collections.unmodifiableMap(new HashMap<>(attributes));
	}

	@Override
	public String get(String key) {
		return entries.get(key);
	}

	@Override
	public Map<String, String> entries() {
		return entries;
	}

	@Override
	public boolean inhibitNewConnection() {
		return !entries.isEmpty();
	}

	@Override
	public String toString() {
		return String.format("MAP(%s)", getPeerAddressAsString());
	}

}
