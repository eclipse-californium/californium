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

import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
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
@NoPublicAPI
public abstract class HandshakeMessage implements DTLSMessage {

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
	 * Next handshake message received with the dtls record. {@code null}, if no
	 * additional handshake message is received.
	 * 
	 * @since 2.4
	 */
	private HandshakeMessage nextHandshakeMessage;

	/**
	 * Creates a new handshake message.
	 */
	protected HandshakeMessage() {
	}

	// Abstract methods ///////////////////////////////////////////////

	@Override
	public int size() {
		return getFragmentLength() + MESSAGE_HEADER_LENGTH_BYTES;
	}

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
			writeTo(writer);
			byteArray = writer.toByteArray();
		}
		return byteArray;
	}

	/**
	 * Write handshake message to writer.
	 * 
	 * @param writer writer to write handshake message.
	 * @since 2.4
	 */
	protected void writeTo(DatagramWriter writer) {
		// write fixed-size handshake message header
		writer.write(getMessageType().getCode(), MESSAGE_TYPE_BITS);
		writer.write(getMessageLength(), MESSAGE_LENGTH_BITS);
		writer.write(messageSeq, MESSAGE_SEQ_BITS);
		writer.write(getFragmentOffset(), FRAGMENT_OFFSET_BITS);
		writer.write(getFragmentLength(), FRAGMENT_LENGTH_BITS);
		writer.writeBytes(fragmentToByteArray());
	}

	/**
	 * Reset the {@link #byteArray} in order to generate an outgoing raw message
	 * with the changed payload / fragment.
	 * 
	 * Only used by {@link ClientHello#setCookie(byte[])}.
	 */
	protected void fragmentChanged() {
		byteArray = null;
	}

	/**
	 * Read handshake message from (received) byte array.
	 * 
	 * Most handshake messages will be returned as specific subclass. Only a few
	 * will be returned as {@link GenericHandshakeMessage} or
	 * {@link FragmentedHandshakeMessage}. If multiple handshake messages are
	 * contained, the returned handshake messages are chained by
	 * {@link #getNextHandshakeMessage()}.
	 * 
	 * @param byteArray byte array containing the handshake message
	 * @return created handshake message
	 * @throws HandshakeException if handshake message could not be read.
	 */
	public static HandshakeMessage fromByteArray(byte[] byteArray)
			throws HandshakeException {
		try {
			int offset = 0;
			HandshakeMessage first = null;
			HandshakeMessage last = null;
			DatagramReader reader = new DatagramReader(byteArray, false);
			do {
				int code = reader.read(MESSAGE_TYPE_BITS);
				HandshakeType type = HandshakeType.getTypeByCode(code);
				if (type == null) {
					throw new HandshakeException(String.format("Cannot parse unsupported message type %d", code),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
				}
				LOGGER.trace("Parsing HANDSHAKE message of type [{}]", type);
				int length = reader.read(MESSAGE_LENGTH_BITS);
				int messageSeq = reader.read(MESSAGE_SEQ_BITS);
				int fragmentOffset = reader.read(FRAGMENT_OFFSET_BITS);
				int fragmentLength = reader.read(FRAGMENT_LENGTH_BITS);

				int left = reader.bitsLeft() / Byte.SIZE;
				if (fragmentLength > left) {
					throw new HandshakeException(
							String.format("Message %s fragment length %d exceeds available data %d", type, fragmentLength,
									left),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
				}

				DatagramReader fragmentReader = reader.createRangeReader(fragmentLength);
				int start = offset;
				offset = byteArray.length - (reader.bitsLeft() / Byte.SIZE);
				HandshakeMessage body;
				if (length != fragmentLength) {
					if (fragmentOffset + fragmentLength > length) {
						throw new HandshakeException(
								String.format("Message %s fragment %d exceeds overall length %d", type,
										fragmentOffset + fragmentLength, length),
								new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
					}
					// fragmented message received
					body = new FragmentedHandshakeMessage(type, length, messageSeq, fragmentOffset,
							fragmentReader.readBytesLeft());
				} else if (fragmentOffset != 0) {
					throw new HandshakeException(String.format("Message %s unexpected fragment offset", type),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
				} else {
					try {
						body = fromReader(type, fragmentReader, null);
					} catch (MissingHandshakeParameterException ex) {
						body = GenericHandshakeMessage.fromByteArray(type);
					}
					// keep the raw bytes for computation of handshake hash
					body.rawMessage = Arrays.copyOfRange(byteArray, start, offset);
					body.setMessageSeq(messageSeq);
				}
				if (first == null) {
					first = body;
				} else {
					last.setNextHandshakeMessage(body);
				}
				last = body;
			} while (reader.bytesAvailable());

			return first;
		} catch (IllegalArgumentException ex) {
			LOGGER.debug("Handshake message malformed", ex);
			throw new HandshakeException("Handshake message malformed, " + ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}
	}

	/**
	 * Create specific handshake from generic handshake message using the now
	 * available handshake parameter.
	 * 
	 * @param message generic handshake message
	 * @param parameter handshake parameter
	 * @return specific handshake message.
	 * @throws HandshakeException if specific handshake message could not be
	 *             created.
	 * @since 2.4
	 */
	public static HandshakeMessage fromGenericHandshakeMessage(GenericHandshakeMessage message,
			HandshakeParameter parameter) throws HandshakeException {
		try {
			HandshakeType type = message.getMessageType();
			LOGGER.trace("Parsing HANDSHAKE message of type [{}]", type);
			byte[] byteArray = message.toByteArray();
			DatagramReader reader = new DatagramReader(message.fragmentToByteArray(), false);

			HandshakeMessage body = fromReader(type, reader, parameter);

			// keep the raw bytes for computation of handshake hash
			body.rawMessage = byteArray;
			body.setMessageSeq(message.getMessageSeq());
			body.setNextHandshakeMessage(message.getNextHandshakeMessage());

			return body;
		} catch (IllegalArgumentException ex) {
			LOGGER.debug("Handshake message malformed", ex);
			throw new HandshakeException("Handshake message malformed, " + ex.getMessage(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}
	}

	/**
	 * Create handshake message from reader.
	 * 
	 * If the handshake parameter are available, a specific handshake message is
	 * returned. If not, a {@link GenericHandshakeMessage} or
	 * {@link FragmentedHandshakeMessage} may be returned.
	 * 
	 * @param type type of handshake message
	 * @param reader reader to read message
	 * @param parameter handshake parameter
	 * @return handshake message
	 * @throws HandshakeException if handshake message could not be created.
	 * @since 2.4
	 */
	private static HandshakeMessage fromReader(HandshakeType type, DatagramReader reader, HandshakeParameter parameter) throws HandshakeException {

		HandshakeMessage body;
		switch (type) {
		case HELLO_REQUEST:
			body = new HelloRequest();
			break;

		case CLIENT_HELLO:
			body = ClientHello.fromReader(reader);
			break;

		case SERVER_HELLO:
			body = ServerHello.fromReader(reader);
			break;

		case HELLO_VERIFY_REQUEST:
			body = HelloVerifyRequest.fromReader(reader);
			break;

		case CERTIFICATE:
			if (parameter == null) {
				throw new MissingHandshakeParameterException("HandshakeParameter must not be null!");
			}
			body = CertificateMessage.fromReader(reader, parameter.getCertificateType());
			break;

		case SERVER_KEY_EXCHANGE:
			if (parameter == null) {
				throw new MissingHandshakeParameterException("HandshakeParameter must not be null!");
			}
			body = readServerKeyExchange(reader, parameter.getKeyExchangeAlgorithm());
			break;

		case CERTIFICATE_REQUEST:
			body = CertificateRequest.fromReader(reader);
			break;

		case SERVER_HELLO_DONE:
			body = new ServerHelloDone();
			break;

		case CERTIFICATE_VERIFY:
			body = CertificateVerify.fromReader(reader);
			break;

		case CLIENT_KEY_EXCHANGE:
			if (parameter == null) {
				throw new MissingHandshakeParameterException("HandshakeParameter must not be null!");
			}
			body = readClientKeyExchange(reader, parameter.getKeyExchangeAlgorithm());
			break;

		case FINISHED:
			body = Finished.fromReader(reader);
			break;

		default:
			throw new HandshakeException(
					String.format("Cannot parse unsupported message type %s", type),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
		}

		if (reader.bytesAvailable()) {
			int bytesLeft = reader.bitsLeft() / Byte.SIZE;
			throw new HandshakeException(
					String.format("Too many bytes, %d left, message not completely parsed! message type %s", bytesLeft, type),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}

		return body;
	}

	/**
	 * Read server key exchange message.
	 * 
	 * @param reader reader with data
	 * @param keyExchange key exchange algorithm
	 * @return key exchange handshake message
	 * @throws HandshakeException if handshake message could not be created.
	 * @since 2.4
	 */
	private static HandshakeMessage readServerKeyExchange(DatagramReader reader, KeyExchangeAlgorithm keyExchange)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return EcdhEcdsaServerKeyExchange.fromReader(reader);
		case PSK:
			return PSKServerKeyExchange.fromReader(reader);
		case ECDHE_PSK:
			return EcdhPskServerKeyExchange.fromReader(reader);
		default:
			throw new HandshakeException(
					"Unsupported key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}

	}

	/**
	 * Read client key exchange message.
	 * 
	 * @param reader reader with data
	 * @param keyExchange key exchange algorithm
	 * @return key exchange handshake message
	 * @throws HandshakeException if handshake message could not be created.
	 * @since 2.4
	 */
	private static HandshakeMessage readClientKeyExchange(DatagramReader reader, KeyExchangeAlgorithm keyExchange)
			throws HandshakeException {
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			return ECDHClientKeyExchange.fromReader(reader);
		case PSK:
			return PSKClientKeyExchange.fromReader(reader);
		case ECDHE_PSK:
			return EcdhPskClientKeyExchange.fromReader(reader);
		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	/**
	 * Get fragment offset.
	 * 
	 * @return fragment offset.
	 */
	public int getFragmentOffset() {
		return 0;
	}

	/**
	 * Get fragment length.
	 * 
	 * @return fragment length
	 */
	public int getFragmentLength() {
		return getMessageLength();
	}

	/**
	 * Get handshake message sequence number.
	 * 
	 * @return handshake message sequence number
	 */
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
	 * Set next handshake message.
	 * 
	 * @param message next handshake message.
	 */
	public void setNextHandshakeMessage(HandshakeMessage message) {
		nextHandshakeMessage = message;
	}

	/**
	 * Get next handshake message.
	 * 
	 * @return next handshake message. {@code null}, if no next handshake
	 *         message is available.
	 */
	public HandshakeMessage getNextHandshakeMessage() {
		return nextHandshakeMessage;
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

	/**
	 * Exception on missing {@link HandshakeParameter}.
	 * 
	 * @since 2.4
	 */
	private static class MissingHandshakeParameterException extends IllegalArgumentException {

		private MissingHandshakeParameterException(String message) {
			super(message);
		}

		private static final long serialVersionUID = -5365688530126068164L;
	}
}
