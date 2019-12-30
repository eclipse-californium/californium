/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use source and destination
 *                                                    EndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.elements.EndpointContext;

/**
 * EmptyMessage represents an empty CoAP message. An empty message has either
 * the message {@link Type} ACK or RST.
 */
public class EmptyMessage extends Message {

	/**
	 * Instantiates a new empty message.
	 *
	 * @param type the message type (ACK or RST)
	 */
	public EmptyMessage(Type type) {
		super(type);
	}

	/**
	 * Set destination endpoint context.
	 * 
	 * Multicast addresses are not supported.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param peerContext destination endpoint context
	 * @return this EmptyMessage
	 * @throws IllegalArgumentException if destination address is multicast
	 *             address
	 */
	public Message setDestinationContext(EndpointContext peerContext) {
		if (peerContext != null && peerContext.getPeerAddress().getAddress().isMulticastAddress()) {
			throw new IllegalArgumentException("Multicast destination is not supported for empty messages!");
		}
		setInternalDestinationContext(peerContext);
		return this;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String appendix = "";
		// crude way to check nothing extra is set in an empty message
		if (!hasEmptyToken() || getOptions().asSortedList().size() > 0 || getPayloadSize() > 0) {
			String payload = getPayloadString();
			if (payload == null) {
				payload = "no payload";
			} else {
				int len = payload.length();
				if (payload.indexOf("\n") != -1) {
					payload = payload.substring(0, payload.indexOf("\n"));
				}
				if (payload.length() > 24) {
					payload = payload.substring(0, 20);
				}
				payload = "\"" + payload + "\"";
				if (payload.length() != len + 2) {
					payload += ".. " + payload.length() + " bytes";
				}
			}
			appendix = " NON-EMPTY: Token=" + getTokenString() + ", " + getOptions() + ", " + payload;
		}
		return String.format("%s        MID=%5d%s", getType(), getMID(), appendix);
	}

	@Override
	public int getRawCode() {
		return 0;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * EMPTY messages are never intended to have payload!
	 */
	@Override
	public boolean isIntendedPayload() {
		return false;
	}

	/**
	 * Create a new acknowledgment for the specified message.
	 *
	 * @param message the message to acknowledge
	 * @return the acknowledgment
	 */
	public static EmptyMessage newACK(Message message) {
		EmptyMessage ack = new EmptyMessage(Type.ACK);
		ack.setDestinationContext(message.getSourceContext());
		ack.setMID(message.getMID());
		return ack;
	}

	/**
	 * Create a new reset message for the specified message.
	 *
	 * @param message the message to reject
	 * @return the reset
	 */
	public static EmptyMessage newRST(Message message) {
		EmptyMessage rst = new EmptyMessage(Type.RST);
		rst.setDestinationContext(message.getSourceContext());
		rst.setMID(message.getMID());
		return rst;
	}

}
