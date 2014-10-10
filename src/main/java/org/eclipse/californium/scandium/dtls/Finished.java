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

import java.util.Arrays;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


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
public class Finished extends HandshakeMessage {

	// Members ////////////////////////////////////////////////////////

	private byte[] verifyData;

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
	 */
	public Finished(byte[] masterSecret, boolean isClient, byte[] handshakeHash) {
		verifyData = getVerifyData(masterSecret, isClient, handshakeHash);
	}

	/**
	 * Called when reconstructing byteArray.
	 * 
	 * @param verifyData
	 */
	public Finished(byte[] verifyData) {
		this.verifyData = verifyData;
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
		
		boolean verified = Arrays.equals(myVerifyData, verifyData);
		if (!verified) {
			String message = "Could not verify the finished message:\nExpected: " + ByteArrayUtils.toHexString(myVerifyData) + "\nReceived: " + ByteArrayUtils.toHexString(verifyData);
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException(message, alert);
		}
	}

	private byte[] getVerifyData(byte[] masterSecret, boolean isClient, byte[] handshakeHash) {
		byte[] data = null;

		int labelId = (isClient) ? Handshaker.CLIENT_FINISHED_LABEL : Handshaker.SERVER_FINISHED_LABEL;
		
		/*
		 * See http://tools.ietf.org/html/rfc5246#section-7.4.9: verify_data =
		 * PRF(master_secret, finished_label, Hash(handshake_messages))
		 * [0..verify_data_length-1];
		 */
		data = Handshaker.doPRF(masterSecret, labelId, handshakeHash);

		return data;
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
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\tVerify Data: " + ByteArrayUtils.toHexString(verifyData) + "\n");

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();
		
		writer.writeBytes(verifyData);

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);

		byte[] verifyData = reader.readBytesLeft();

		return new Finished(verifyData);
	}

}
