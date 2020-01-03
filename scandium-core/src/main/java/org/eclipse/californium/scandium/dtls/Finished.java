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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - log failure to verify FINISHED message
 *    Bosch Software Innovations GmbH - remove dependency on Handshaker class
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Finished message is always sent immediately after a
 * {@link ChangeCipherSpecMessage} to verify that the key exchange and
 * authentication processes were successful. It is essential that a
 * {@link ChangeCipherSpecMessage} be received between the other handshake
 * messages and the Finished message. The Finished message is the first one
 * protected with the just negotiated algorithms, keys, and secrets. The value
 * handshake_messages includes all handshake messages starting at
 * {@link ClientHello} up to, but not including, this {@link Finished} message.
 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.9">RFC 5246</a>.
 */
public final class Finished extends HandshakeMessage {

	private static final Logger LOG = LoggerFactory.getLogger(Finished.class);

	// Members ////////////////////////////////////////////////////////

	private final byte[] verifyData;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Generates the verify data according to <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.9">RFC 5246</a>:<br>
	 * <code>PRF(master_secret, finished_label, Hash(handshake_messages))</code>.
	 * 
	 * @param hmac
	 *            the mac. e.g. HmacSHA256
	 * @param masterSecret
	 *            the master_secret
	 * @param isClient
	 *            to determine the finished_label
	 * @param handshakeHash
	 *            the hash
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public Finished(Mac hmac, SecretKey masterSecret, boolean isClient, byte[] handshakeHash, InetSocketAddress peerAddress) {
		super(peerAddress);
		verifyData = generateVerifyData(hmac, masterSecret, isClient, handshakeHash);
	}

	/**
	 * Called when reconstructing byteArray.
	 * 
	 * @param verifyData the raw verify data
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	private Finished(DatagramReader reader, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.verifyData = reader.readBytesLeft();
	}

	// Methods ////////////////////////////////////////////////////////
	
	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.9">RFC
	 * 5246</a>: All of the data from all messages in this handshake (not
	 * including any HelloRequest messages) up to, but not including, this
	 * message. This is only data visible at the handshake layer and does not
	 * include record layer headers.
	 * 
	 * @param hmac
	 *            the mac. e.g. HmacSHA256
	 * @param masterSecret
	 *            the master secret.
	 * @param isClient
	 *            whether the verify data comes from the client or the server.
	 * @param handshakeHash
	 *            the handshake hash.
	 * @throws HandshakeException if the data can not be verified.
	 */
	public void verifyData(Mac hmac, SecretKey masterSecret, boolean isClient, byte[] handshakeHash) throws HandshakeException {

		byte[] myVerifyData = generateVerifyData(hmac, masterSecret, isClient, handshakeHash);

		if (!MessageDigest.isEqual(myVerifyData, verifyData)) {
			StringBuilder msg = new StringBuilder("Verification of peer's [").append(getPeer())
					.append("] FINISHED message failed");
			if (LOG.isTraceEnabled()) {
				msg.append(StringUtil.lineSeparator()).append("Expected: ").append(StringUtil.byteArray2HexString(myVerifyData));
				msg.append(StringUtil.lineSeparator()).append("Received: ").append(StringUtil.byteArray2HexString(verifyData));
			}
			LOG.debug(msg.toString());
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeer());
			throw new HandshakeException("Verification of FINISHED message failed", alert);
		}
	}

	private byte[] generateVerifyData(Mac hmac, SecretKey masterSecret, boolean isClient, byte[] handshakeHash) {

		// See http://tools.ietf.org/html/rfc5246#section-7.4.9:
		// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages)) [0..verify_data_length-1]
		if (isClient) {
			return PseudoRandomFunction.doPRF(hmac, masterSecret, Label.CLIENT_FINISHED_LABEL, handshakeHash);
		} else {
			return PseudoRandomFunction.doPRF(hmac, masterSecret, Label.SERVER_FINISHED_LABEL, handshakeHash);
		}
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.FINISHED;
	}

	@Override
	public int getMessageLength() {
		return verifyData.length;
	}

	@Override
	public String toString() {
		return new StringBuilder(super.toString())
				.append("\t\tVerify Data: ").append(StringUtil.byteArray2HexString(verifyData)).append(StringUtil.lineSeparator())
				.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		return verifyData;
	}

	public static HandshakeMessage fromReader(DatagramReader reader, InetSocketAddress peerAddress) {
		return new Finished(reader, peerAddress);
	}
}
