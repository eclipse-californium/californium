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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Handshake state. Used for handshake validation.
 * 
 * Contains expected {@link ContentType} and {@link HandshakeType} with an flag
 * to mark the state as optional.
 */
public class HandshakeState {

	/**
	 * Expected record content type.
	 */
	private final ContentType contentType;
	/**
	 * Expected handshake message type. Maybe {@code null}, if
	 * {@link #contentType} is not {@link ContentType#HANDSHAKE}.
	 */
	private final HandshakeType handshakeType;
	/**
	 * Mark state as optional. If not matching, try next state.
	 */
	private final boolean optional;

	/**
	 * Create state for none handshake messages.
	 * 
	 * @param contentType record content type,
	 *            {@link ContentType#CHANGE_CIPHER_SPEC}.
	 */
	public HandshakeState(ContentType contentType) {
		this(contentType, null, false);
	}

	/**
	 * Create state for specific handshake messages.
	 * 
	 * @param handshakeType specific handshake message type
	 */
	public HandshakeState(HandshakeType handshakeType) {
		this(ContentType.HANDSHAKE, handshakeType, false);
	}

	/**
	 * Create optional state for specific handshake messages.
	 * 
	 * @param handshakeType specific handshake message type
	 * @param optional marker for optional states. {@code true}, if state is
	 *            {@link #isOptional()}.
	 */
	public HandshakeState(HandshakeType handshakeType, boolean optional) {
		this(ContentType.HANDSHAKE, handshakeType, optional);
	}

	/**
	 * Create state.
	 * 
	 * @param contentType record content type,
	 * @param handshakeType specific handshake message type, or {@code null}, for
	 *            none handshake messages
	 * @param optional marker for optional states. {@code true}, if state is
	 *            {@link #isOptional()}.
	 */
	private HandshakeState(ContentType contentType, HandshakeType handshakeType, boolean optional) {
		this.contentType = contentType;
		this.handshakeType = handshakeType;
		this.optional = optional;
	}

	/**
	 * Get record content type of state.
	 * 
	 * @return expected content type
	 */
	public ContentType getContentType() {
		return contentType;
	}

	/**
	 * Get handshake message type.
	 * 
	 * @return expected handshake message type, or {@code null}, for none
	 *         handshake messages
	 */
	public HandshakeType getHandshakeType() {
		return handshakeType;
	}

	/**
	 * Check, if state is optional.
	 * 
	 * If a optional state doesn't match, try the next state.
	 * 
	 * @return {@code true}, if optional, {@code false}, otherwise.
	 */
	public boolean isOptional() {
		return optional;
	}

	/**
	 * Check, if message is expected.
	 * 
	 * @param message message to check
	 * @return {@code true}, if message is expected, {@code false}, if not.
	 */
	public boolean expect(DTLSMessage message) {
		if (message.getContentType() != contentType) {
			return false;
		}
		if (message instanceof HandshakeMessage) {
			HandshakeMessage handshake = (HandshakeMessage) message;
			if (handshake.getMessageType() != handshakeType) {
				return false;
			}
		}
		return true;
	}

	public String toString() {
		return toString(contentType, handshakeType);
	}

	/**
	 * Create a message description related to a handshake state.
	 * 
	 * @param message message
	 * @return message description
	 */
	public static String toString(DTLSMessage message) {
		if (message instanceof HandshakeMessage) {
			HandshakeMessage handshake = (HandshakeMessage) message;
			return toString(message.getContentType(), handshake.getMessageType());
		} else {
			return toString(message.getContentType(), null);
		}
	}

	/**
	 * Concatenate the content type name and the handshake type name, if available.
	 * 
	 * @param contentType record content type
	 * @param handshakeType handshake message type, or {@code null}, for none
	 *            handshake messages
	 * @return Concatenated type names
	 */
	private static String toString(ContentType contentType, HandshakeType handshakeType) {
		if (handshakeType != null) {
			return contentType.name() + "/" + handshakeType.name();
		} else {
			return contentType.name();
		}
	}
}
