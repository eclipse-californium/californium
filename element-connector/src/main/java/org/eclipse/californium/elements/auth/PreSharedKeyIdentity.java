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

/**
 * A principal representing an authenticated peer's identity as used in a
 * <em>pre-shared key</em> handshake.
 */
public final class PreSharedKeyIdentity implements Principal {

	private final String virtualHost;
	private final String identity;
	private final int hash;
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
	 * @param virtualHost the virtual host name that the identity is scoped to.
	 * @param identity the identity.
	 * @throws NullPointerException if the identity is <code>null</code>
	 */
	public PreSharedKeyIdentity(String virtualHost, String identity) {
		if (identity == null) {
			throw new NullPointerException("Identity must not be null");
		} else {
			this.identity = identity;
			this.virtualHost = virtualHost;

			final int prime = 31;
			int result = 1;
			result = prime * result + ((identity == null) ? 0 : identity.hashCode());
			result = prime * result + ((virtualHost == null) ? 0 : virtualHost.hashCode());
			this.hash = result;

			StringBuilder b = new StringBuilder();
			if (virtualHost != null) {
				b.append(virtualHost).append(":");
			}
			b.append(identity);
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
		return hash;
	}

	/**
	 * Compares another object to this identity.
	 * 
	 * @return {@code true} if the other object is a RawPublicKey identity and
	 *         contains the same identity and virtual host name.
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
		if (identity == null) {
			if (other.identity != null) {
				return false;
			}
		} else if (!identity.equals(other.identity)) {
			return false;
		}
		if (virtualHost == null) {
			if (other.virtualHost != null) {
				return false;
			}
		} else if (!virtualHost.equals(other.virtualHost)) {
			return false;
		}
		return true;
	}
}
