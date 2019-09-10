/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.Message;

/**
 * A CoAP message ID scoped to a remote endpoint.
 * <p>
 * This class is used by the matcher to correlate messages by MID and
 * endpoint address.
 */
public final class KeyMID {

	private final int MID;
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
	private KeyMID(int mid,  Object peer) {
		if (mid < 0 || mid > Message.MAX_MID) {
			throw new IllegalArgumentException("MID must be a 16 bit unsigned int: " + mid);
		} else if (peer == null) {
			throw new NullPointerException("peer must not be null");
		} else {
			this.MID = mid;
			this.peer = peer;
			this.hash = 31 * mid + peer.hashCode();
		}
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
		if (MID != other.MID)
			return false;
		return peer.equals(other.peer);
	}

	@Override
	public String toString() {
		return new StringBuilder("KeyMID[").append(MID).append(", ").append(peer).append("]").toString();
	}

	/**
	 * Creates a key from an inbound CoAP message.
	 * 
	 * @param message the message.
	 * @return the key derived from the message. The key's <em>mid</em> is
	 *         scoped to the message's source address and port.
	 */
	public static KeyMID fromInboundMessage(Message message) {
		InetSocketAddress address = message.getSourceContext().getPeerAddress();
		return new KeyMID(message.getMID(), address);
	}

	/**
	 * Creates a key from an outbound CoAP message.
	 * 
	 * @param message the message.
	 * @return the key derived from the message. The key's <em>mid</em> is
	 *         scoped to the message's destination address and port.
	 */
	public static KeyMID fromOutboundMessage(Message message) {
		InetSocketAddress address = message.getDestinationContext().getPeerAddress();
		return new KeyMID(message.getMID(), address);
	}
}