/*******************************************************************************
 * Copyright (c) 2015, 2019 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add scoped identity indicator
 *                                                    issue #649
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A principal representing an authenticated peer's identity as used in a
 * <em>pre-shared key</em> handshake.
 */
public final class PreSharedKeyIdentity extends AbstractExtensiblePrincipal<PreSharedKeyIdentity> {

	private final boolean scopedIdentity;
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
		this(false, null, identity, null);
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
		this(true, virtualHost, identity, null);
	}

	/**
	 * Creates a new instance for an identity optional scoped to a virtual host.
	 * 
	 * @param sni enable scope to a virtual host
	 * @param virtualHost The virtual host name that the identity is scoped to.
	 *            The host name will be converted to lower case.
	 * @param identity the identity.
	 * @param additionalInformation Additional information for this principal.
	 * @throws NullPointerException if the identity is <code>null</code>
	 * @throws IllegalArgumentException if virtual host is not a valid host name
	 *             as per <a href="http://tools.ietf.org/html/rfc1123">RFC
	 *             1123</a>.
	 */
	private PreSharedKeyIdentity(boolean sni, String virtualHost, String identity, AdditionalInfo additionalInformation) {
		super(additionalInformation);
		if (identity == null) {
			throw new NullPointerException("Identity must not be null");
		} else {
			scopedIdentity = sni;
			if (sni) {
				StringBuilder b = new StringBuilder();
				if (virtualHost == null) {
					this.virtualHost = null;
				} else if (StringUtil.isValidHostName(virtualHost)) {
					this.virtualHost = virtualHost.toLowerCase();
					b.append(this.virtualHost);
				} else {
					throw new IllegalArgumentException("virtual host is not a valid hostname");
				}
				b.append(":");
				b.append(identity);
				this.name = b.toString();
			} else {
				if (virtualHost != null) {
					throw new IllegalArgumentException("virtual host is not supported, if sni is disabled");
				}
				this.virtualHost = null;
				this.name = identity;
			}
			this.identity = identity;
		}
	}

	private PreSharedKeyIdentity(boolean scopedIdentity, String virtualHost, String identity, String name, AdditionalInfo additionalInfo) {
		super(additionalInfo);
		this.scopedIdentity = scopedIdentity;
		this.virtualHost = virtualHost;
		this.identity = identity;
		this.name = name;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PreSharedKeyIdentity amend(AdditionalInfo additionInfo) {
		return new PreSharedKeyIdentity(scopedIdentity, virtualHost, identity, name, additionInfo);
	}

	/**
	 * Checks, if the identity is scoped by the virtual host name.
	 * 
	 * @return {@code true}, if the identity is scoped by the virtual host name.
	 */
	public boolean isScopedIdentity() {
		return scopedIdentity;
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
	 * If the identity is not scoped by the server name, the
	 * {@link #getIdentity()} is returned. If the identity is scoped by the
	 * server name, the name consists of that server name and the identity,
	 * separated by a colon character. If no server name has been provided, then
	 * the name consists of a colon character followed by the identity.
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
		if (scopedIdentity) {
			return new StringBuilder("PreSharedKey Identity [").append("virtual host: ").append(virtualHost)
					.append(", identity: ").append(identity).append("]").toString();
		} else {
			return new StringBuilder("PreSharedKey Identity [").append("identity: ").append(identity).append("]")
					.toString();
		}
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
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
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
