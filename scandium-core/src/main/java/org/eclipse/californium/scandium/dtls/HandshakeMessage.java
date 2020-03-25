/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Vikram (University of Rostock) - added ECDHE_PSK mode
 *    Achim Kraus (Bosch Software Innovations GmbH) - use handshake parameter and
 *                                                    generic handshake messages to
 *                                                    process reordered handshake messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign fragmentation support
 *                                                    move fragment field into 
 *                                                    FragmentedHandshakeMessage
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static final Logger LOGGER = LoggerFactory.getLogger(HandshakeMessage.class);

	// Members ////////////////////////////////////////////////////////

	/**
	 * Whenever each message is assigned to a flight, the message_seq is set 
	 * with an incremented value from the {@link Handshaker}.
	 */
	private int messageSeq;

	/**
	 * Used to store the raw incoming message this instance has been created from. Only set
	 * if this message has been received from an other peer. The rawMessage is used
	 * to calculate the hash/message digest value sent in the <em>Finished</em> message.
	 */
	private byte[] rawMessage;

	/**
	 * Used to store the raw message of this instance. Set either by the
	 * received raw message on incoming messages, or by the generated message
	 * for outgoing messages. If the payload (fragment) of an outgoing messages
	 * is changed, it's required to reset this field by calling
	 * {@link #fragmentChanged()}.
	 * 
	 * @see #toByteArray()
	 */
	private byte[] byteArray;

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
	 * Must be implemented by each subclass. Except the {@link ClientHello}, the
	 * fragments are considered to be not modified. If a modification is required,
	 * call {@link #fragmentChanged()}.
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
		sb.append(StringUtil.lineSeparator()).append("\tType: ").append(getMessageType());
		sb.append(StringUtil.lineSeparator()).append("\tPeer: ").append(getPeer());
		sb.append(StringUtil.lineSeparator()).append("\tMessage Sequence No: ").append(messageSeq);
		sb.append(StringUtil.lineSeparator()).append("\tLength: ").append(getMessageLength()).append(StringUtil.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	/**
	 * Returns the raw binary representation of the handshake message. for
	 * incoming messages this it the same as {@link #getRawMessage()}. For
	 * outgoing messages the header is generated by this method and the
	 * subclasses are responsible for the specific rest of the payload /
	 * fragment. The result is only created once at the first call. Following
	 * calls will get the same bytes until {@link #fragmentChanged()} gets
	 * called.
	 * 
	 * @return the byte representation of the handshake message.
	 * 
	 * @see #byteArray
	 * @see #fragmentToByteArray()
	 * @see #fragmentChanged()
	 */
	public byte[] toByteArray() {
		if (rawMessage != null) {
			return rawMessage;
		}
		if (byteArray == null) {
			// create datagram writer to encode message data
			int fragmentLength = getFragmentLength();
			DatagramWriter writer = new DatagramWriter(fragmentLength + MESSAGE_HEADER_LENGTH_BYTES);

			// write fixed-size handshake message header
			writer.write(getMessageType().getCode(), MESSAGE_TYPE_BITS);
			writer.write(getMessageLength(), MESSAGE_LENGTH_BITS);
			writer.write(messageSeq, MESSAGE_SEQ_BITS);
			writer.write(getFragmentOffset(), FRAGMENT_OFFSET_BITS);
			writer.write(fragmentLength, FRAGMENT_LENGTH_BITS);
			writer.writeBytes(fragmentToByteArray());

			byteArray = writer.toByteArray();
		}
		return byteArray;
	}

	/**
	 * Reset the {@link #byteArray} in order to generate an outgoing raw message
	 * with the changed payload / fragment. Only used by
	 * {@link ClientHello#setCookie(byte[]).
	 */
	protected void fragmentChanged() {
		byteArray = null;
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, HandshakeParameter parameter, InetSocketAddress peerAddress) throws HandshakeException {
		try {
			DatagramReader reader = new DatagramReader(byteArray, false);
			HandshakeType type = HandshakeType.getTypeByCode(reader.read(MESSAGE_TYPE_BITS));
			LOGGER.trace("Parsing HANDSHAKE message of type [{}]", type);
			int left = byteArray.length - MESSAGE_HEADER_LENGTH_BYTES;
			int length = reader.read(MESSAGE_LENGTH_BITS);

			int messageSeq = reader.read(MESSAGE_SEQ_BITS);

			int fragmentOffset = reader.read(FRAGMENT_OFFSET_BITS);
			int fragmentLength = reader.read(FRAGMENT_LENGTH_BITS);

			if (fragmentLength != left) {
				throw new HandshakeException(
						String.format("Message %s fragment length %d doesn't match data %d", type, fragmentLength, left),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
			} else if (length != fragmentLength) {
				if (fragmentOffset + fragmentLength > length) {
					throw new HandshakeException(
							String.format("Message %s fragment overflow %d > %d", type, fragmentOffset + fragmentLength,
									length),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
				}
				// fragmented message received
				return new FragmentedHandshakeMessage(type, length, messageSeq, fragmentOffset, reader.readBytesLeft(), peerAddress);
			} else if (fragmentOffset != 0) {
				throw new HandshakeException(String.format("Message %s unexpected fragment offset", type),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
			}

			HandshakeMessage body;
			switch (type) {
			case HELLO_REQUEST:
				body = new HelloRequest(peerAddress);
				break;

			case CLIENT_HELLO:
				body = ClientHello.fromReader(reader, peerAddress);
				break;

			case SERVER_HELLO:
				body = ServerHello.fromReader(reader, peerAddress);
				break;

			case HELLO_VERIFY_REQUEST:
				body = HelloVerifyRequest.fromReader(reader, peerAddress);
				break;

			case CERTIFICATE:
				if (parameter == null) {
					reader.close();
					body = GenericHandshakeMessage.fromByteArray(type, peerAddress);
				} else {
					body = CertificateMessage.fromReader(reader, parameter.getCertificateType(), peerAddress);
				}
				break;

			case SERVER_KEY_EXCHANGE:
				if (parameter == null) {
					reader.close();
					body = GenericHandshakeMessage.fromByteArray(type, peerAddress);
				} else {
					body = readServerKeyExchange(reader, parameter.getKeyExchangeAlgorithm(), peerAddress);
				}
				break;

			case CERTIFICATE_REQUEST:
				body = CertificateRequest.fromReader(reader, peerAddress);
				break;

			case SERVER_HELLO_DONE:
				body = new ServerHelloDone(peerAddress);
				break;

			case CERTIFICATE_VERIFY:
				body = CertificateVerify.fromReader(reader, peerAddress);
				break;

			case CLIENT_KEY_EXCHANGE:
				if (parameter == null) {
					// handshake parameter are available after flight 4, so in flight 5 it's an error
					throw new HandshakeException(
							"Unexpected client key exchange message",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, peerAddress));
				} else {
					body = readClientKeyExchange(reader, parameter.getKeyExchangeAlgorithm(), peerAddress);
				}
				break;

			case FINISHED:
				body = Finished.fromReader(reader, peerAddress);
				break;

			default:
				throw new HandshakeException(
						String.format("Cannot parse unsupported message type %s", type),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, peerAddress));
			}

			if (reader.bytesAvailable()) {
				byte[] bytesLeft = reader.readBytesLeft();
				throw new HandshakeException(
						String.format("Too many bytes, %d left, message not completely parsed! message type %s", bytesLeft.length, type),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
			}
			// keep the raw bytes for computation of handshake hash
			body.rawMessage = Arrays.copyOf(byteArray, byteArray.length);
			body.setMessageSeq(messageSeq);

			return body;
		} catch (IllegalArgumentException ex) {
			LOGGER.debug("Handshake message from peer [{}] malformed", peerAddress, ex);
			throw new HandshakeException("Handshake message malformed, " + ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR, peerAddress));
		}
	}

	private static HandshakeMessage readServerKeyExchange(DatagramReader reader, KeyExchangeAlgorithm keyExchange, InetSocketAddress peerAddress)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return EcdhEcdsaServerKeyExchange.fromReader(reader, peerAddress);
		case PSK:
			return PSKServerKeyExchange.fromReader(reader, peerAddress);
		case ECDHE_PSK:
			return EcdhPskServerKeyExchange.fromReader(reader, peerAddress);
		default:
			throw new HandshakeException(
					"Unsupported key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}

	}

	private static HandshakeMessage readClientKeyExchange(DatagramReader reader, KeyExchangeAlgorithm keyExchange, InetSocketAddress peerAddress)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return ECDHClientKeyExchange.fromReader(reader, peerAddress);
		case PSK:
			return PSKClientKeyExchange.fromReader(reader, peerAddress);
		case ECDHE_PSK:
			return EcdhPskClientKeyExchange.fromReader(reader, peerAddress);
		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	public int getFragmentOffset() {
		return 0;
	}

	public int getFragmentLength() {
		return getMessageLength();
	}

	public int getMessageSeq() {
		return messageSeq;
	}

	/**
	 * Set the handshake message sequence number.
	 * 
	 * @param messageSeq handshake message sequence number
	 * @throws IllegalStateException if {@link #toByteArray()} was already
	 *             called without calling {@link #fragmentChanged()}.
	 */
	public void setMessageSeq(int messageSeq) {
		if (byteArray != null) {
			throw new IllegalStateException("message is already serialized!");
		}
		this.messageSeq = messageSeq;
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
