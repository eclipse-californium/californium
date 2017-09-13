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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * A map based endpoint context.
 */
public class MapBasedEndpointContext extends AddressEndpointContext {

	private final Map<String, String> entries = new HashMap<>();

	/**
	 * Creates a new endpoint context with correlation context support.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @throws NullPointerException if provided peer address is {@code null}.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity) {
		super(peerAddress, peerIdentity);
	}

	/**
	 * Puts a value to the context.
	 * 
	 * @param key the key to put the value under.
	 * @param value the value to put to the context.
	 * @return the previous value for the given key or <code>null</code> if the
	 *         context did not contain any value for the key yet.
	 */
	public final Object put(String key, String value) {
		return entries.put(key, value);
	}

	@Override
	public String get(String key) {
		return entries.get(key);
	}

	@Override
	public Set<Map.Entry<String, String>> entrySet() {
		return entries.entrySet();
	}

	@Override
	public boolean inhibitNewConnection() {
		return !entries.isEmpty();
	}

	/**
	 * Creates a hash code based on the entries stored in this context.
	 * <p>
	 * The hash code for two instances will be the same if they contain the same
	 * keys and values.
	 * </p>
	 * 
	 * @return the hash code.
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((entries == null) ? 0 : entries.hashCode());
		return result;
	}

	/**
	 * Checks if this endpoint context has the same entries as another instance.
	 * 
	 * @param obj the object to compare this context to.
	 * @return <code>true</code> if the other object also is a
	 *         <code>MapBasedEndpointContext</code> and has the same entries as
	 *         this context.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof MapBasedEndpointContext)) {
			return false;
		}
		if (!super.equals(obj)) {
			return false;
		}
		MapBasedEndpointContext other = (MapBasedEndpointContext) obj;
		if (entries == null) {
			if (other.entries != null) {
				return false;
			}
		} else if (!entries.equals(other.entries)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return String.format("MAP(%s:%d)", getPeerAddress().getHostString(), getPeerAddress().getPort());
	}

}
