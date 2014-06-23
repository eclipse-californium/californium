/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * Represents a general handshake message and defines the common header. The
 * subclasses are responsible for the rest of the message body. See <a
 * href="http://tools.ietf.org/html/rfc6347#section-4.2.2">RFC 6347</a> for the
 * message format.
 */
public abstract class HandshakeMessage implements DTLSMessage {

	// Logging ////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(HandshakeMessage.class.getCanonicalName());

	// CoAP-specific constants ////////////////////////////////////////

	private static final int MESSAGE_TYPE_BITS = 8;

	private static final int MESSAGE_LENGTH_BITS = 24;

	private static final int MESSAGE_SEQ_BITS = 16;

	private static final int FRAGMENT_OFFSET_BITS = 24;

	private static final int FRAGMENT_LENGTH_BITS = 24;

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
	 * The length of this fragment. An unfragmented message is a degenerate case
	 * with fragment_offset=0 and fragment_length=length.
	 */
	private int fragmentLength = -1;

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
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tHandshake Protocol\n");
		sb.append("\tType: " + getMessageType().toString() + "\n");
		sb.append("\tMessage Sequence: " + messageSeq + " \n");
		sb.append("\tFragment Offset: " + fragmentOffset + "\n");
		sb.append("\tFragment Length: " + fragmentLength + "\n");
		sb.append("\tLength: " + getMessageLength() + "\n");

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
			// unfragmented message is a degenerate case with fragment_offset=0
			// and fragment_length=length
			fragmentLength = getMessageLength();
		}
		writer.write(fragmentLength, FRAGMENT_LENGTH_BITS);
		
		writer.writeBytes(fragmentToByteArray());

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, KeyExchangeAlgorithm keyExchange, boolean useRawPublicKey) throws HandshakeException {
		DatagramReader reader = new DatagramReader(byteArray);
		HandshakeType type = HandshakeType.getTypeByCode(reader.read(MESSAGE_TYPE_BITS));

		int length = reader.read(MESSAGE_LENGTH_BITS);

		int messageSeq = reader.read(MESSAGE_SEQ_BITS);

		int fragmentOffset = reader.read(FRAGMENT_OFFSET_BITS);
		int fragmentLength = reader.read(FRAGMENT_LENGTH_BITS);

		byte[] bytesLeft = reader.readBytes(fragmentLength);
		
		if (length != fragmentLength) {
			// fragmented message received
			return new FragmentedHandshakeMessage(type, length, messageSeq, fragmentOffset, bytesLeft);
		}
		
		HandshakeMessage body = null;
		switch (type) {
		case HELLO_REQUEST:
			body = new HelloRequest();
			break;

		case CLIENT_HELLO:
			body = ClientHello.fromByteArray(bytesLeft);
			break;

		case SERVER_HELLO:
			body = ServerHello.fromByteArray(bytesLeft);
			break;

		case HELLO_VERIFY_REQUEST:
			body = HelloVerifyRequest.fromByteArray(bytesLeft);
			break;

		case CERTIFICATE:
			body = CertificateMessage.fromByteArray(bytesLeft, useRawPublicKey);
			break;

		case SERVER_KEY_EXCHANGE:
			switch (keyExchange) {
			case EC_DIFFIE_HELLMAN:
				body = ECDHServerKeyExchange.fromByteArray(bytesLeft);
				break;
			case PSK:
				body = PSKServerKeyExchange.fromByteArray(bytesLeft);
				break;
			case NULL:
				LOGGER.severe("Received unexpected ServerKeyExchange message in NULL key exchange mode.");
				break;
			default:
				LOGGER.severe("Unknown key exchange algorithm: " + keyExchange);
				break;
			}
			
			break;

		case CERTIFICATE_REQUEST:
			body = CertificateRequest.fromByteArray(bytesLeft);
			break;

		case SERVER_HELLO_DONE:
			body = new ServerHelloDone();
			break;

		case CERTIFICATE_VERIFY:
			body = CertificateVerify.fromByteArray(bytesLeft);
			break;

		case CLIENT_KEY_EXCHANGE:
			switch (keyExchange) {
			case EC_DIFFIE_HELLMAN:
				body = ECDHClientKeyExchange.fromByteArray(bytesLeft);
				break;
			case PSK:
				body = PSKClientKeyExchange.fromByteArray(bytesLeft);
				break;
			case NULL:
				body = NULLClientKeyExchange.fromByteArray(bytesLeft);
				break;

			default:
				LOGGER.severe("Unknown key exchange algorithm: " + keyExchange);
				break;
			}
			
			break;

		case FINISHED:
			body = Finished.fromByteArray(bytesLeft);
			break;

		default:
			LOGGER.severe("Unknown handshake type: " + type);
			break;
		}

		body.setFragmentLength(fragmentLength);
		body.setFragmentOffset(fragmentOffset);
		body.setMessageSeq(messageSeq);

		return body;
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

}
