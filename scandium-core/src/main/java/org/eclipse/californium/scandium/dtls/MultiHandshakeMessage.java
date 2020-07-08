/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;

/**
 * Multi handshake messages.
 * 
 * Accumulate multi handshake messages to be sent as one dtls record.
 * 
 * @since 2.4
 */
@NoPublicAPI
public class MultiHandshakeMessage extends HandshakeMessage {

	/**
	 * Number of added handshake messages.
	 */
	private int count;
	/**
	 * Length of added handshake messages.
	 */
	private int length;
	/**
	 * Last added handshake message.
	 */
	private HandshakeMessage tail = this;

	/**
	 * Create multi handshake message.
	 * 
	 * @param peerAddress address of peer
	 */
	protected MultiHandshakeMessage(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	/**
	 * Get number of added handshake messages.
	 * 
	 * @return number of added handshake messages
	 */
	public int getNumberOfHandshakeMessages() {
		return count;
	}

	/**
	 * Add handshake message.
	 * 
	 * @param message additional handshake message
	 */
	public void add(HandshakeMessage message) {
		tail.setNextHandshakeMessage(message);
		tail = message;
		length += message.size();
		++count;
	}

	@Override
	public HandshakeType getMessageType() {
		HandshakeMessage message = getNextHandshakeMessage();
		return message == null ? null : message.getMessageType();
	}

	@Override
	public int getMessageLength() {
		return length - MESSAGE_HEADER_LENGTH_BYTES;
	}

	@Override
	public byte[] fragmentToByteArray() {
		throw new RuntimeException("not supported!");
	}

	@Override
	public byte[] toByteArray() {
		DatagramWriter writer = new DatagramWriter(RecordLayer.DEFAULT_ETH_MTU);
		HandshakeMessage message = getNextHandshakeMessage();
		while (message != null) {
			message.writeTo(writer);
			message = message.getNextHandshakeMessage();
		}
		return writer.toByteArray();
	}

}
