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

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A CoAP message ID scoped to a remote endpoint.
 * <p>
 * This class is used by the matcher to correlate messages by MID and
 * endpoint address.
 */
public final class KeyMID {

	private final int mid;
	private final Object peer;
	private final int hash;

	/**
	 * Creates a key based on a message ID and a remote endpoint address.
	 * 
	 * @param mid the message ID.
	 * @param peer peer's identity. Usually that's the peer's
	 *            {@link InetSocketAddress}.
	 * @throws NullPointerException if address or origin is {@code null}
	 * @throws IllegalArgumentException if mid is &lt; 0 or &gt; 65535.
	 * 
	 */
	public KeyMID(int mid, Object peer) {
		if (mid < 0 || mid > Message.MAX_MID) {
			throw new IllegalArgumentException("MID must be a 16 bit unsigned int: " + mid);
		} else if (peer == null) {
			throw new NullPointerException("peer must not be null");
		} else {
			this.mid = mid;
			this.peer = peer;
			this.hash = 31 * mid + peer.hashCode();
		}
	}

	public int getMID() {
		return mid;
	}

	public Object getPeer() {
		return peer;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		KeyMID other = (KeyMID) obj;
		if (mid != other.mid)
			return false;
		return peer.equals(other.peer);
	}

	@Override
	public String toString() {
		Object peer = this.peer;
		if (peer instanceof InetSocketAddress) {
			peer = StringUtil.toDisplayString((InetSocketAddress) peer);
		}
		return new StringBuilder("KeyMID[").append(peer).append('-').append(mid).append(']').toString();
	}
}