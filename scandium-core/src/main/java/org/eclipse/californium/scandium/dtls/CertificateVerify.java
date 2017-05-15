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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;


/**
 * This message is used to provide explicit verification of a client
 * certificate. This message is only sent following a client certificate that
 * has signing capability (i.e., all certificates except those containing fixed
 * Diffie-Hellman parameters). When sent, it MUST immediately follow the
 * {@link ClientKeyExchange} message. For further details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.8">RFC 5246</a>.
 */
public final class CertificateVerify extends HandshakeMessage {
	
	// Logging ///////////////////////////////////////////////////////////

	private static final Logger LOGGER = Logger.getLogger(CertificateVerify.class.getCanonicalName());

	// DTLS-specific constants ////////////////////////////////////////

	private static final int HASH_ALGORITHM_BITS = 8;
	
	private static final int SIGNATURE_ALGORITHM_BITS = 8;

	private static final int SIGNATURE_LENGTH_BITS = 16;
	
	// Members ////////////////////////////////////////////////////////

	/** The digitally signed handshake messages. */
	private byte[] signatureBytes;
	
	/** The signature and hash algorithm which must be included into the digitally-signed struct. */
	private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	// Constructor ////////////////////////////////////////////////////
	
	/**
	 * Called by client to create its CertificateVerify message.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the signature and hash algorithm used to create the signature.
	 * @param clientPrivateKey
	 *            the client's private key to sign the signature.
	 * @param handshakeMessages
	 *            the handshake messages which are signed.
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public CertificateVerify(SignatureAndHashAlgorithm signatureAndHashAlgorithm, PrivateKey clientPrivateKey,
			byte[] handshakeMessages, InetSocketAddress peerAddress) {
		this(signatureAndHashAlgorithm, peerAddress);
		this.signatureBytes = setSignature(clientPrivateKey, handshakeMessages);
	}

	/**
	 * Called by the server when receiving the client's CertificateVerify
	 * message.
	 * 
	 * @param signatureAndHashAlgorithm
	 *            the signature and hash algorithm used to verify the signature.
	 * @param signatureBytes
	 *            the signature.
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	private CertificateVerify(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] signatureBytes, InetSocketAddress peerAddress) {
		this(signatureAndHashAlgorithm, peerAddress);
		this.signatureBytes = Arrays.copyOf(signatureBytes, signatureBytes.length);
	}

	private CertificateVerify(SignatureAndHashAlgorithm signatureAndHashAlgorithm, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE_VERIFY;
	}

	@Override
	public int getMessageLength() {
		/*
		 * fixed: signature and hash algorithm (2 bytes) + signature length field (2 bytes), see
		 * http://tools.ietf.org/html/rfc5246#section-4.7
		 */
		return 4 + signatureBytes.length;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		// according to http://tools.ietf.org/html/rfc5246#section-4.7 the
		// signature algorithm must also be included
		writer.write(signatureAndHashAlgorithm.getHash().getCode(), HASH_ALGORITHM_BITS);
		writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SIGNATURE_ALGORITHM_BITS);

		writer.write(signatureBytes.length, SIGNATURE_LENGTH_BITS);
		writer.writeBytes(signatureBytes);

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		DatagramReader reader = new DatagramReader(byteArray);

		// according to http://tools.ietf.org/html/rfc5246#section-4.7 the
		// signature algorithm must also be included
		int hashAlgorithm = reader.read(HASH_ALGORITHM_BITS);
		int signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS);
		SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);

		int length = reader.read(SIGNATURE_LENGTH_BITS);
		byte[] signature = reader.readBytes(length);

		return new CertificateVerify(signAndHash, signature, peerAddress);
	}
	
	// Methods ////////////////////////////////////////////////////////
	
	/**
	 * Creates the signature and signs it with the client's private key.
	 * 
	 * @param clientPrivateKey
	 *            the client's private key.
	 * @param handshakeMessages
	 *            the handshake messages used up to now in the handshake.
	 * @return the signature.
	 */
	private byte[] setSignature(PrivateKey clientPrivateKey, byte[] handshakeMessages) {
		signatureBytes = new byte[] {};

		try {
			Signature signature = Signature.getInstance(signatureAndHashAlgorithm.jcaName());
			signature.initSign(clientPrivateKey);

			signature.update(handshakeMessages);

			signatureBytes = signature.sign();
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not create signature.",e);
		}

		return signatureBytes;
	}
	
	/**
	 * Tries to verify the client's signature contained in the CertificateVerify
	 * message.
	 * 
	 * @param clientPublicKey
	 *            the client's public key.
	 * @param handshakeMessages
	 *            the handshake messages exchanged so far.
	 * @throws HandshakeException if the signature could not be verified.
	 */
	public void verifySignature(PublicKey clientPublicKey, byte[] handshakeMessages) throws HandshakeException {
		boolean verified = false;
		try {
			Signature signature = Signature.getInstance(signatureAndHashAlgorithm.jcaName());
			signature.initVerify(clientPublicKey);

			signature.update(handshakeMessages);

			verified = signature.verify(signatureBytes);

		} catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE,"Could not verify the client's signature.", e);
		}
		
		if (!verified) {
			String message = "The client's CertificateVerify message could not be verified.";
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeer());
			throw new HandshakeException(message, alert);
		}
	}

}
