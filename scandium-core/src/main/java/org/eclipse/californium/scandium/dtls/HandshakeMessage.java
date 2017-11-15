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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;


/**
 * Represents a general handshake message and defines the common header. The
 * subclasses are responsible for the rest of the message body. See <a
 * href="http://tools.ietf.org/html/rfc6347#section-4.2.2">RFC 6347</a> for the
 * message format.
 */
public abstract class HandshakeMessage extends AbstractMessage {

	// message header specific constants ////////////////////////////////////////

	public static final int MESSAGE_TYPE_BITS = 8;

	public static final int MESSAGE_LENGTH_BITS = 24;

	public static final int MESSAGE_SEQ_BITS = 16;

	public static final int FRAGMENT_OFFSET_BITS = 24;

	public static final int FRAGMENT_LENGTH_BITS = 24;

	public static final int MESSAGE_HEADER_LENGTH_BYTES = (MESSAGE_TYPE_BITS + MESSAGE_LENGTH_BITS
			+ MESSAGE_SEQ_BITS + FRAGMENT_OFFSET_BITS + FRAGMENT_LENGTH_BITS) / 8; // 12 bytes

	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(HandshakeMessage.class.getCanonicalName());

	// Members ////////////////////////////////////////////////////////

	/**
	 * Whenever each new message is generated, the message_seq value is
	 * incremented by one.
	 */
	private int messageSeq = -1;

	/**
	 * The number of bytes contained in previous fragments.
	 */
	private int fragmentOffset = -1;

	/**
	 * The length of this fragment. A non-fragmented message is a degenerate case
	 * with fragment_offset=0 and fragment_length=length.
	 */
	private int fragmentLength = -1;

	/**
	 * Used to store the message this instance has been created from. Only set
	 * if this message has been received from a client, i.e. we're the server in
	 * the handshake. The rawMessage is used to calculate the hash/message
	 * digest value sent in the <em>Finished</em> message.
	 */
	private byte[] rawMessage;

	/**
	 * Creates a new handshake message for a given peer.
	 * 
	 * @param peerAddress
	 *            the IP address and port of the peer this message has been
	 *            received from or should be sent to
	 */
	protected HandshakeMessage(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	// Abstract methods ///////////////////////////////////////////////

	/**
	 * Returns the type of the handshake message. See {@link HandshakeType}.
	 * 
	 * @return the {@link HandshakeType}.
	 */
	public abstract HandshakeType getMessageType();

	/**
	 * Must be implemented by each subclass. The length is given in bytes and
	 * only includes the length of the subclass' specific fields (not the
	 * handshake message header).
	 * 
	 * @return the length of the message <strong>in bytes</strong>.
	 */
	public abstract int getMessageLength();
	
	/**
	 * The serialization of the handshake body (without the handshake header).
	 * Must be implemented by each subclass.
	 * 
	 * @return the raw byte representation of the handshake body.
	 */
	public abstract byte[] fragmentToByteArray();

	// Methods ////////////////////////////////////////////////////////

	@Override
	public final ContentType getContentType() {
		return ContentType.HANDSHAKE;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tHandshake Protocol");
		sb.append(System.lineSeparator()).append("\tType: ").append(getMessageType());
		sb.append(System.lineSeparator()).append("\tPeer: ").append(getPeer());
		sb.append(System.lineSeparator()).append("\tMessage Sequence No: ").append(messageSeq);
		sb.append(System.lineSeparator()).append("\tFragment Offset: ").append(fragmentOffset);
		sb.append(System.lineSeparator()).append("\tFragment Length: ").append(fragmentLength);
		sb.append(System.lineSeparator()).append("\tLength: ").append(getMessageLength()).append(System.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	/**
	 * Returns the raw binary representation of the handshake header. The
	 * subclasses are responsible for the specific rest of the fragment.
	 * 
	 * @return the byte representation of the handshake message.
	 */
	public byte[] toByteArray() {
		// create datagram writer to encode message data
		DatagramWriter writer = new DatagramWriter();

		// write fixed-size handshake message header
		writer.write(getMessageType().getCode(), MESSAGE_TYPE_BITS);
		writer.write(getMessageLength(), MESSAGE_LENGTH_BITS);

		writer.write(messageSeq, MESSAGE_SEQ_BITS);
		
		if (fragmentOffset < 0) {
			// message not fragmented
			fragmentOffset = 0;
		}
		writer.write(fragmentOffset, FRAGMENT_OFFSET_BITS);
		
		if (fragmentLength < 0) {
			// non-fragmented message is a degenerate case with fragment_offset=0
			// and fragment_length=length
			fragmentLength = getMessageLength();
		}
		writer.write(fragmentLength, FRAGMENT_LENGTH_BITS);
		
		writer.writeBytes(fragmentToByteArray());

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, KeyExchangeAlgorithm keyExchange,
			boolean useRawPublicKey, InetSocketAddress peerAddress) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		HandshakeType type = HandshakeType.getTypeByCode(reader.read(MESSAGE_TYPE_BITS));
		LOGGER.log(Level.FINEST, "Parsing HANDSHAKE message of type [{0}]", type);

		int length = reader.read(MESSAGE_LENGTH_BITS);

		int messageSeq = reader.read(MESSAGE_SEQ_BITS);

		int fragmentOffset = reader.read(FRAGMENT_OFFSET_BITS);
		int fragmentLength = reader.read(FRAGMENT_LENGTH_BITS);

		byte[] bytesLeft = reader.readBytes(fragmentLength);

		if (length != fragmentLength) {
			// fragmented message received
			return new FragmentedHandshakeMessage(type, length, messageSeq, fragmentOffset, bytesLeft, peerAddress);
		}

		HandshakeMessage body;
		switch (type) {
		case HELLO_REQUEST:
			body = new HelloRequest(peerAddress);
			break;

		case CLIENT_HELLO:
			body = ClientHello.fromByteArray(bytesLeft, peerAddress);
			break;

		case SERVER_HELLO:
			body = ServerHello.fromByteArray(bytesLeft, peerAddress);
			break;

		case HELLO_VERIFY_REQUEST:
			body = HelloVerifyRequest.fromByteArray(bytesLeft, peerAddress);
			break;

		case CERTIFICATE:
			body = CertificateMessage.fromByteArray(bytesLeft, useRawPublicKey, peerAddress);
			break;

		case SERVER_KEY_EXCHANGE:
			body = readServerKeyExchange(bytesLeft, keyExchange, peerAddress);
			break;

		case CERTIFICATE_REQUEST:
			body = CertificateRequest.fromByteArray(bytesLeft, peerAddress);
			break;

		case SERVER_HELLO_DONE:
			body = new ServerHelloDone(peerAddress);
			break;

		case CERTIFICATE_VERIFY:
			body = CertificateVerify.fromByteArray(bytesLeft, peerAddress);
			break;

		case CLIENT_KEY_EXCHANGE:
			body = readClientKeyExchange(bytesLeft, keyExchange, peerAddress);
			break;

		case FINISHED:
			body = Finished.fromByteArray(bytesLeft, peerAddress);
			break;

		default:
			throw new HandshakeException(
					String.format("Cannot parse unsupported message type %s", type),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
		// keep the raw bytes for computation of handshake hash
		body.rawMessage = Arrays.copyOf(byteArray, byteArray.length);
		body.setFragmentLength(fragmentLength);
		body.setFragmentOffset(fragmentOffset);
		body.setMessageSeq(messageSeq);

		return body;
	}

	private static HandshakeMessage readServerKeyExchange(byte[] bytesLeft, KeyExchangeAlgorithm keyExchange, InetSocketAddress peerAddress)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return ECDHServerKeyExchange.fromByteArray(bytesLeft, peerAddress);
		case PSK:
			return PSKServerKeyExchange.fromByteArray(bytesLeft, peerAddress);
		default:
			throw new HandshakeException(
					"Unsupported key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}

	}

	private static HandshakeMessage readClientKeyExchange(byte[] bytesLeft, KeyExchangeAlgorithm keyExchange, InetSocketAddress peerAddress)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return ECDHClientKeyExchange.fromByteArray(bytesLeft, peerAddress);
		case PSK:
			return PSKClientKeyExchange.fromByteArray(bytesLeft, peerAddress);
		case NULL:
			return NULLClientKeyExchange.fromByteArray(bytesLeft, peerAddress);
		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	public int getMessageSeq() {
		return messageSeq;
	}

	public void incrementMessageSeq() {
		messageSeq++;
	}

	public int getFragmentOffset() {
		return fragmentOffset;
	}

	public int getFragmentLength() {
		return fragmentLength;
	}

	public void setFragmentLength(int length) {
		this.fragmentLength = length;
	}

	public void setMessageSeq(int messageSeq) {
		this.messageSeq = messageSeq;
	}

	public void setFragmentOffset(int fragmentOffset) {
		this.fragmentOffset = fragmentOffset;
	}

	/**
	 * Gets the raw bytes of the message received from a client that this instance
	 * has been created from.
	 * The raw message is used for calculating the handshake hash sent in the
	 * <em>FINISHED</em> message.
	 * 
	 * @return the message or <code>null</code> if this instance has not been
	 *            created from a message received from a client.
	 */
	protected final byte[] getRawMessage() {
		return rawMessage;
	}

}
