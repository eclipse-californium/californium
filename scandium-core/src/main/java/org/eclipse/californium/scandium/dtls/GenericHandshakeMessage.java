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

import java.net.InetSocketAddress;

/**
 * Generic handshake message.
 * 
 * Use to partially process handshake messages, if they are received out of
 * order an the full processing requires the {@link HandshakeParameter}. Offers
 * later creation of specific handshake messages, if the handshake parameters
 * are available.
 */
public class GenericHandshakeMessage extends HandshakeMessage {

	/**
	 * Handshake type of message
	 */
	private final HandshakeType type;

	/**
	 * Create generic handshake message.
	 * 
	 * @param type handshake type
	 * @param peerAddress address of peer
	 */
	private GenericHandshakeMessage(HandshakeType type, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.type = type;
	}

	@Override
	public HandshakeType getMessageType() {
		return type;
	}

	@Override
	public int getMessageLength() {
		return getRawMessage().length;
	}

	@Override
	public byte[] fragmentToByteArray() {
		return getRawMessage();
	}

	/**
	 * Get specific handshake message.
	 * 
	 * @param parameter handshake parameter
	 * @return specific handshake message
	 * @throws NullPointerException if handshake parameter is {@code null}
	 * @throws HandshakeException if specific handshake message could not be
	 *             created
	 */
	public HandshakeMessage getSpecificHandshakeMessage(HandshakeParameter parameter) throws HandshakeException {
		if (parameter == null) {
			throw new NullPointerException("HandshakeParameter must not be null!");
		}
		return HandshakeMessage.fromByteArray(getRawMessage(), parameter, getPeer());
	}

	/**
	 * Read generic generic handshake message from bytes.
	 * 
	 * @param type handshake type
	 * @param peerAddress address of peer
	 * @return generic handshake message
	 */
	public static GenericHandshakeMessage fromByteArray(HandshakeType type, InetSocketAddress peerAddress) {
		return new GenericHandshakeMessage(type, peerAddress);
	}

}
