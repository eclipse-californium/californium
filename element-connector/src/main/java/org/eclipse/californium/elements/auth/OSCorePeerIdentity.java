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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add scoped identity indicator
 *                                                    issue #649
 *    Rikard Höglund (RISE SICS)                    - principal for OSCORE
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import java.security.Principal;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * A principal representing an OSCORE peer's identity with
 * information from its associated OSCORE Context.
 */
public final class OSCorePeerIdentity implements Principal {

	private final String host;
	private final byte[] contextId;
	private final byte[] senderId;
	private final byte[] recipientId;
	private final String name;

	/**
	 * Creates a new instance for an OSCORE identity.
	 * 
	 * It is defined by a set of fields from its corresponding OSCORE Context.
	 * 
	 * @param host the host this context is associated with if any
	 * @param contextId the Context ID
	 * @param senderId the Sender ID
	 * @param recipientId the Recipient ID
	 */
	public OSCorePeerIdentity(String host, byte[] contextId, byte[] senderId, byte[] recipientId) {
		if (host != null && host.isEmpty()) {
			throw new IllegalArgumentException("Host must have a non-zero length");
		} else if (host != null && !StringUtil.isValidHostName(host)) {
			throw new IllegalArgumentException("Host is not a valid hostname");
		}

		if(senderId == null) {
			throw new IllegalArgumentException("Sender ID must be set");
		}

		if(recipientId == null) {
			throw new IllegalArgumentException("Recipient ID must be set");
		}

		this.host = host;
		this.senderId = senderId.clone();
		this.recipientId = recipientId.clone();

		if(contextId != null) {
			this.contextId = contextId.clone();
		} else {
			this.contextId = null;
		}

		name = generateName();
	}

	/**
	 * Gets the name of this principal.
	 * 
	 * @return the name
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Generates a name for this principal based on its properties.
	 * 
	 * @return name of this Principal
	 */
	private String generateName() {
		StringBuilder b = new StringBuilder();

		b.append(OSCorePeerIdentity.class.getSimpleName()).append(" [");
		b.append("Host: ").append(host).append(", ");

		b.append("Context ID: ");
		if(contextId != null) {
			b.append("0x").append(DatatypeConverter.printHexBinary(contextId));
		} else {
			b.append("null");
		}
		b.append(", ");

		b.append("Sender ID: 0x").append(DatatypeConverter.printHexBinary(senderId)).append(", ");
		b.append("Recipient ID: 0x").append(DatatypeConverter.printHexBinary(recipientId));
		b.append("]");

		return b.toString();
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
			return name;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	/**
	 * Compares another object to this identity.
	 * 
	 * @return {@code true} if the other object is a {@code OSCorePeerIdentity} and
	 *         its properties have the same value as this instance.
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

		OSCorePeerIdentity other = (OSCorePeerIdentity) obj;

		if (host == null) {
			if (other.host != null) {
				return false;
			}
		} else if (!host.equals(other.host)) {
			return false;
		}

		if (contextId == null) {
			if (other.contextId != null) {
				return false;
			}
		} else if (!contextId.equals(other.contextId)) {
			return false;
		}

		if (senderId == null) {
			if (other.senderId != null) {
				return false;
			}
		} else if (!senderId.equals(other.senderId)) {
			return false;
		}

		if (recipientId == null) {
			if (other.recipientId != null) {
				return false;
			}
		} else if (!recipientId.equals(other.recipientId)) {
			return false;
		}

		return true;
	}

	/**
	 * @return the host this context is associated with
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @return the contextID
	 */
	public byte[] getContextId() {
		if(contextId != null) {
			return contextId.clone();
		} else {
			return null;
		}
	}

	/**
	 * @return the senderID
	 */
	public byte[] getSenderId() {
		return senderId.clone();
	}

	/**
	 * @return the recipientID
	 */
	public byte[] getRecipientId() {
		return recipientId.clone();
	}
}
