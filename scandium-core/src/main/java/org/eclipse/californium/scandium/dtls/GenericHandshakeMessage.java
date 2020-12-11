/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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

import java.util.Arrays;

import org.eclipse.californium.elements.util.NoPublicAPI;

/**
 * Generic handshake message.
 * 
 * Use to partially process handshake messages, if they are received out of
 * order an the full processing requires the {@link HandshakeParameter}. Offers
 * later creation of specific handshake messages, if the handshake parameters
 * are available.
 */
@NoPublicAPI
public class GenericHandshakeMessage extends HandshakeMessage {

	/**
	 * Handshake type of message
	 */
	private final HandshakeType type;

	/**
	 * Create generic handshake message.
	 * 
	 * @param type handshake type
	 */
	protected GenericHandshakeMessage(HandshakeType type) {
		this.type = type;
	}

	@Override
	public HandshakeType getMessageType() {
		return type;
	}

	@Override
	public int getMessageLength() {
		return getRawMessage().length - MESSAGE_HEADER_LENGTH_BYTES;
	}

	@Override
	public byte[] fragmentToByteArray() {
		byte[] rawMessage = getRawMessage();
		return Arrays.copyOfRange(rawMessage, MESSAGE_HEADER_LENGTH_BYTES, rawMessage.length);
	}

	/**
	 * Read generic generic handshake message from bytes.
	 * 
	 * @param type handshake type
	 * @return generic handshake message
	 */
	public static GenericHandshakeMessage fromByteArray(HandshakeType type) {
		return new GenericHandshakeMessage(type);
	}
}
