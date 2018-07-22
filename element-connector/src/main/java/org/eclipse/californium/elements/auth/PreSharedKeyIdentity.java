/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import java.security.Principal;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A principal representing an authenticated peer's identity as used in a
 * <em>pre-shared key</em> handshake.
 */
public final class PreSharedKeyIdentity implements Principal {

	private final String virtualHost;
	private final String identity;
	private final String name;

	/**
	 * Creates a new instance for an identity.
	 * 
	 * @param identity the identity
	 * @throws NullPointerException if the identity is <code>null</code>
	 */
	public PreSharedKeyIdentity(String identity) {
		this(null, identity);
	}

	/**
	 * Creates a new instance for an identity scoped to a virtual host.
	 * 
	 * @param virtualHost The virtual host name that the identity is scoped to.
	 *                    The host name will be converted to lower case.
	 * @param identity the identity.
	 * @throws NullPointerException if the identity is <code>null</code>
	 * @throws IllegalArgumentException if virtual host is not a valid host name
	 *             as per <a href="http://tools.ietf.org/html/rfc1123">RFC 1123</a>.
	 */
	public PreSharedKeyIdentity(String virtualHost, String identity) {
		if (identity == null) {
			throw new NullPointerException("Identity must not be null");
		} else {
			StringBuilder b = new StringBuilder();
			if (virtualHost == null) {
				this.virtualHost = null;
			} else if (StringUtil.isValidHostName(virtualHost)) {
				this.virtualHost = virtualHost.toLowerCase();
				b.append(this.virtualHost);
			} else {
				throw new IllegalArgumentException("virtual host is not a valid hostname");
			}
			this.identity = identity;

			b.append(":").append(identity);
			this.name = b.toString();
		}
	}

	/**
	 * Gets the virtual host name that the identity is scoped to.
	 * 
	 * @return The name or {@code null} if not set.
	 */
	public String getVirtualHost() {
		return virtualHost;
	}

	/**
	 * Gets the identity.
	 * 
	 * @return The identity.
	 */
	public String getIdentity() {
		return identity;
	}

	/**
	 * Gets the name of this principal.
	 * <p>
	 * The name consists of the server name and the identity,
	 * separated by a colon character. If not server name has been
	 * provided, then the name only consists of the identity.
	 * 
	 * @return the name
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Gets a string representation of this principal.
	 * 
	 * Clients should not assume any particular format of the returned string
	 * since it may change over time.
	 *  
	 * @return the string representation
	 */
	@Override
	public String toString() {
		return new StringBuilder("PreSharedKey Identity [")
				.append("virtual host: ").append(virtualHost)
				.append(", identity: ").append(identity)
				.append("]").toString();
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	/**
	 * Compares another object to this identity.
	 * 
	 * @return {@code true} if the other object is a {@code PreSharedKeyIdentity} and
	 *         its name property has the same value as this instance.
	 */
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
		PreSharedKeyIdentity other = (PreSharedKeyIdentity) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}
}
