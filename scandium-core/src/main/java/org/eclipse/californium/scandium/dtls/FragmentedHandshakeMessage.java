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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * This class represents a fragmented handshake message. It treats the
 * underlying handshake body as transparent data and just helps keeping track of
 * the fragment_offset and fragment_length.
 */
public final class FragmentedHandshakeMessage extends HandshakeMessage {

	// Members ////////////////////////////////////////////////////////

	/** The fragmented handshake body. */
	private final byte[] fragmentedBytes;

	/** The handshake message's type. */
	private final HandshakeType type;

	/** The handshake message's unfragmented length. */
	private final int messageLength;

	/**
	 * The number of bytes contained in previous fragments.
	 */
	private final int fragmentOffset;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Called when reassembling a handshake message or received a fragment
	 * during the handshake.
	 * 
	 * @param type
	 *            the message's type.
	 * @param messageLength
	 *            the message's total length.
	 * @param messageSeq
	 *            the message's message_seq.
	 * @param fragmentOffset
	 *            the message's fragment_offset.
	 * @param fragmentedBytes
	 *            the fragment's byte representation.
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public FragmentedHandshakeMessage(HandshakeType type, int messageLength, int messageSeq, int fragmentOffset,
			byte[] fragmentedBytes, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.type = type;
		this.messageLength = messageLength;
		this.fragmentedBytes = Arrays.copyOf(fragmentedBytes, fragmentedBytes.length);
		this.fragmentOffset = fragmentOffset;
		setMessageSeq(messageSeq);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return type;
	}

	@Override
	public int getMessageLength() {
		return messageLength;
	}

	@Override
	public int getFragmentOffset() {
		return fragmentOffset;
	}

	@Override
	public int getFragmentLength() {
		return fragmentedBytes.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tFragmented Handshake Protocol");
		sb.append(StringUtil.lineSeparator()).append("\tType: ").append(getMessageType());
		sb.append(StringUtil.lineSeparator()).append("\tPeer: ").append(getPeer());
		sb.append(StringUtil.lineSeparator()).append("\tMessage Sequence No: ").append(getMessageSeq());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Offset: ").append(getFragmentOffset());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Length: ").append(getFragmentLength());
		sb.append(StringUtil.lineSeparator()).append("\tLength: ").append(getMessageLength());
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		return fragmentedBytes;
	}

}
