/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
package org.eclipse.californium.scandium.auth;

import java.security.Principal;

/**
 * A principal representing an authenticated peer's identity as used in a
 * <em>pre-shared key</em> handshake.
 */
public class PreSharedKeyIdentity implements Principal {

	private final String identity;

	/**
	 * Creates a new instance for a given identity.
	 * 
	 * @param identity the identity
	 * @throws NullPointerException if the identity is <code>null</code>
	 */
	public PreSharedKeyIdentity(String identity) {
		if (identity == null) {
			throw new NullPointerException("Identity must not be null");
		} else {
			this.identity = identity;
		}
	}

	/**
	 * Gets the identity.
	 * 
	 * @return the identity
	 */
	@Override
	public String getName() {
		return identity;
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
		return new StringBuilder("PreSharedKey Identity [").append(identity).append("]").toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((identity == null) ? 0 : identity.hashCode());
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
		if (!(obj instanceof PreSharedKeyIdentity)) {
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
		return true;
	}
}
