/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Implementation of client-local and not client-local tokens.
 */
public class KeyToken {

	/**
	 * Precalculated hash.
	 */
	private final int hash;
	/**
	 * Token.
	 */
	private final Token token;
	/**
	 * Peer's identity. Usually that's the peer's {@link InetSocketAddress}.
	 */
	private final Object peer;

	/**
	 * Create key token.
	 * 
	 * @param token token
	 * @param peer peer's identity. May be {@code null}, if key token is not
	 *            client-local. Usually that's the peer's
	 *            {@link InetSocketAddress}.
	 */
	public KeyToken(Token token, Object peer) {
		this.token = token;
		this.peer = peer;
		int hash = token.hashCode();
		if (peer != null) {
			hash += peer.hashCode() * 31;
		}
		this.hash = hash;
	}

	/**
	 * Get token.
	 * 
	 * @return token
	 */
	public Token getToken() {
		return token;
	}

	/**
	 * Get peer's identity.
	 * 
	 * @return peer's identity. Usually that's the peer's
	 *         {@link InetSocketAddress}.
	 */
	public Object getPeer() {
		return peer;
	}

	@Override
	public final int hashCode() {
		return hash;
	}

	@Override
	public final boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		}
		KeyToken other = (KeyToken) obj;
		if (hash != other.hash) {
			return false;
		} else if (!token.equals(other.token)) {
			return false;
		}
		if (peer == other.peer) {
			return true;
		} else if (peer == null) {
			return false;
		}
		return peer.equals(other.peer);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("KeyToken[");
		if (peer != null) {
			Object peer = this.peer;
			if (peer instanceof InetSocketAddress) {
				peer = StringUtil.toDisplayString((InetSocketAddress) peer);
			}
			builder.append(peer).append('-');
		}
		builder.append(token.getAsString()).append(']');
		return builder.toString();
	}
}
