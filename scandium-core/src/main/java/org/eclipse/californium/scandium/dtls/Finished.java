/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - log failure to verify FINISHED message
 *    Bosch Software Innovations GmbH - remove dependency on Handshaker class
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
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

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

	private static final Logger LOG = Logger.getLogger(Finished.class.getName());

	// Members ////////////////////////////////////////////////////////

	private final byte[] verifyData;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Generates the verify data according to <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.9">RFC 5246</a>:<br>
	 * <code>PRF(master_secret,
	 * finished_label, Hash(handshake_messages))</code>.
	 * 
	 * @param masterSecret
	 *            the master_secret
	 * @param isClient
	 *            to determine the finished_label
	 * @param handshakeHash
	 *            the hash
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public Finished(byte[] masterSecret, boolean isClient, byte[] handshakeHash, InetSocketAddress peerAddress) {
		super(peerAddress);
		verifyData = getVerifyData(masterSecret, isClient, handshakeHash);
	}

	/**
	 * Called when reconstructing byteArray.
	 * 
	 * @param verifyData the raw verify data
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	private Finished(byte[] verifyData, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.verifyData = Arrays.copyOf(verifyData, verifyData.length);
	}

	// Methods ////////////////////////////////////////////////////////
	
	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.9">RFC
	 * 5246</a>: All of the data from all messages in this handshake (not
	 * including any HelloRequest messages) up to, but not including, this
	 * message. This is only data visible at the handshake layer and does not
	 * include record layer headers.
	 * 
	 * @param masterSecret
	 *            the master secret.
	 * @param isClient
	 *            whether the verify data comes from the client or the server.
	 * @param handshakeHash
	 *            the handshake hash.
	 * @throws HandshakeException if the data can not be verified.
	 */
	public void verifyData(byte[] masterSecret, boolean isClient, byte[] handshakeHash) throws HandshakeException {

		byte[] myVerifyData = getVerifyData(masterSecret, isClient, handshakeHash);

		if (!Arrays.equals(myVerifyData, verifyData)) {
			StringBuilder msg = new StringBuilder("Verification of peer's [").append(getPeer())
					.append("] FINISHED message failed");
			if (LOG.isLoggable(Level.FINEST)) {
				msg.append(System.lineSeparator()).append("Expected: ").append(ByteArrayUtils.toHexString(myVerifyData));
				msg.append(System.lineSeparator()).append("Received: ").append(ByteArrayUtils.toHexString(verifyData));
			}
			LOG.log(Level.FINE, msg.toString());
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeer());
			throw new HandshakeException("Verification of FINISHED message failed", alert);
		}
	}

	private byte[] getVerifyData(byte[] masterSecret, boolean isClient, byte[] handshakeHash) {

		// See http://tools.ietf.org/html/rfc5246#section-7.4.9:
		// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages)) [0..verify_data_length-1]
		if (isClient) {
			return PseudoRandomFunction.doPRF(masterSecret, Label.CLIENT_FINISHED_LABEL, handshakeHash);
		} else {
			return PseudoRandomFunction.doPRF(masterSecret, Label.SERVER_FINISHED_LABEL, handshakeHash);
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
				.append("\t\tVerify Data: ").append(ByteArrayUtils.toHexString(verifyData)).append(System.lineSeparator())
				.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		writer.writeBytes(verifyData);
		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		DatagramReader reader = new DatagramReader(byteArray);
		byte[] verifyData = reader.readBytesLeft();
		return new Finished(verifyData, peerAddress);
	}
}
