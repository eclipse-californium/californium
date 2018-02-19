/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add access to client identity
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 469593 (validation of peer certificate chain)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve handling of empty messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 477074 (erroneous encoding of RPK)
 *    Ludwig Seitz (RISE SICS) - Moved certificate validation to Handshaker
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * The server MUST send a Certificate message whenever the agreed-upon key
 * exchange method uses certificates for authentication. This message will
 * always immediately follow the {@link ServerHello} message. For details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.2">RFC 5246</a>.
 */
public final class CertificateMessage extends HandshakeMessage {

	// Logging ///////////////////////////////////////////////////////////

	private static final String CERTIFICATE_TYPE_X509 = "X.509";

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateMessage.class.getCanonicalName());

	// DTLS-specific constants ///////////////////////////////////////////
	
	/**
	 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.2">RFC 5246</a>:
	 * <code>opaque ASN.1Cert<1..2^24-1>;</code>
	 */
	private static final int CERTIFICATE_LENGTH_BITS = 24;

	/**
	 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.2">RFC 5246</a>:
	 * <code>ASN.1Cert certificate_list<0..2^24-1>;</code>
	 */
	private static final int CERTIFICATE_LIST_LENGTH = 24;

	// Members ///////////////////////////////////////////////////////////

	/**
	 * A chain of certificates asserting the sender's identity.
	 * The sender's identity is reflected by the certificate at index 0.
	 */
	private CertPath certPath;

	/** The encoded chain of certificates */
	private List<byte[]> encodedChain;

	/**
	 * The SubjectPublicKeyInfo part of the X.509 certificate. Used in
	 * constrained environments for smaller message size.
	 */
	private byte[] rawPublicKeyBytes;

	// length is at least 3 bytes containing the message's overall number of bytes
	private int length = 3;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a certificate chain.
	 * 
	 * @param certificateChain
	 *            the certificate chain with the (first certificate must be the
	 *            server's)
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 * @throws NullPointerException if the certificate chain is <code>null</code>
	 *            (use an array of length zero to create an <em>empty</em> message)
	 * @throws IllegalArgumentException if the certificate chain contains any
	 *            non-X.509 certificates or does not form a valid chain of
	 *            certification.
	 * 
	 */
	public CertificateMessage(X509Certificate[] certificateChain, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null");
		} else {
			setCertificateChain(certificateChain);
			calculateLength();
		}
	}

	private CertificateMessage(final CertPath peerCertChain, final InetSocketAddress peerAddress) {
		super(peerAddress);
		this.certPath = peerCertChain;
		calculateLength();
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a raw public key.
	 * 
	 * @param rawPublicKeyBytes
	 *           the raw public key (SubjectPublicKeyInfo)
	 * @param peerAddress the IP address and port of the peer this
	 *           message has been received from or should be sent to
	 * @throws NullPointerException if the raw public key byte array is <code>null</code>
	 *           (use an array of length zero to create an <em>empty</em> message)
	 */
	public CertificateMessage(byte[] rawPublicKeyBytes, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (rawPublicKeyBytes == null) {
			throw new NullPointerException("Raw public key byte array must not be null");
		} else {
			this.rawPublicKeyBytes = Arrays.copyOf(rawPublicKeyBytes, rawPublicKeyBytes.length);
			length += this.rawPublicKeyBytes.length;
		}
	}

	/**
	 * Sets the chain of certificates to be sent to a peer as
	 * part of this message for authentication purposes.
	 * <p>
	 * Only the non-root certificates from the given chain are sent to the
	 * peer because the peer is assumed to have been provisioned with a
	 * set of trusted root certificates already.
	 * <p>
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.2">
	 * TLS 1.2, Section 7.4.2</a> for details.
	 *  
	 * @param chain the certificate chain
	 * @throws IllegalArgumentException if the given array contains non X.509 certificates or
	 *                                  the certificates do not form a chain.
	 */
	private void setCertificateChain(final X509Certificate[] chain) {
		this.certPath = X509CertPath.generateCertPath(chain);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE;
	}

	private void calculateLength() {
		if (certPath != null && encodedChain == null) {
			// the certificate chain length uses 3 bytes
			// each certificate's length in the chain also uses 3 bytes
			encodedChain = new ArrayList<byte[]>(certPath.getCertificates().size());
			try {
				for (Certificate cert : certPath.getCertificates()) {
					byte[] encoded = cert.getEncoded();
					encodedChain.add(encoded);

					// the length of the encoded certificate (3 bytes) plus the
					// encoded bytes
					length += 3 + encoded.length;
				}
			} catch (CertificateEncodingException e) {
				encodedChain = null;
				LOGGER.error("Could not encode certificate chain", e);
			}
		}
	}
			
	@Override
	public int getMessageLength() {
		return length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		if (rawPublicKeyBytes == null && certPath != null) {
			sb.append("\t\tCertificate chain length: ").append(getMessageLength() - 3).append(System.lineSeparator());
			int index = 0;
			for (Certificate cert : certPath.getCertificates()) {
				sb.append("\t\t\tCertificate Length: ").append(encodedChain.get(index).length).append(System.lineSeparator());
				sb.append("\t\t\tCertificate: ").append(cert).append(System.lineSeparator());
				index++;
			}
		} else if (rawPublicKeyBytes != null && certPath == null) {
			sb.append("\t\tRaw Public Key: ");
			sb.append(getPublicKey().toString());
			sb.append(System.lineSeparator());
		}

		return sb.toString();
	}

	/**
	 * Gets the certificate chain provided by the peer.
	 * 
	 * This method only provides a result if the peer uses
	 * <em>X.509</em> certificates. In that case the returned array
	 * contains the peer's public key certificate at position 0.
	 * 
	 * @return the certificate chain or <code>null</code> if
	 *        <em>RawPublicKey</em>s are used
	 */
	public CertPath getCertificateChain() {
		return certPath;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		if (rawPublicKeyBytes == null) {
			writer.write(getMessageLength() - 3, CERTIFICATE_LIST_LENGTH);
			// the size of the certificate chain
			for (byte[] encoded : encodedChain) {
				// the size of the current certificate
				writer.write(encoded.length, CERTIFICATE_LENGTH_BITS);
				// the encoded current certificate
				writer.writeBytes(encoded);
			}
		} else {
			writer.write(rawPublicKeyBytes.length, CERTIFICATE_LENGTH_BITS);
			writer.writeBytes(rawPublicKeyBytes);
		}

		return writer.toByteArray();
	}

	/**
	 * Creates a certificate message from its binary encoding.
	 * 
	 * @param byteArray The binary encoding of the message.
	 * @param useRawPublicKey {@code true} if the certificate message contains a RawPublicKey instead
	 *                        of an X.509 certificate chain.
	 * @param peerAddress The IP address and port of the peer that sent the message.
	 * @return The certificate message.
	 * @throws HandshakeException if the binary encoding could not be parsed.
	 */
	public static CertificateMessage fromByteArray(
			final byte[] byteArray,
			boolean useRawPublicKey,
			InetSocketAddress peerAddress) throws HandshakeException {

		DatagramReader reader = new DatagramReader(byteArray);

		if (useRawPublicKey) {
			LOGGER.debug("Parsing RawPublicKey CERTIFICATE message");
			int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
			byte[] rawPublicKey = reader.readBytes(certificateLength);
			return new CertificateMessage(rawPublicKey, peerAddress);
		} else {
			return readX509CertificateMessage(reader, peerAddress);
		}
	}

	private static CertificateMessage readX509CertificateMessage(final DatagramReader reader, final InetSocketAddress peerAddress) throws HandshakeException {

		LOGGER.debug("Parsing X.509 CERTIFICATE message");
		int certificateChainLength = reader.read(CERTIFICATE_LIST_LENGTH);
		List<Certificate> certs = new ArrayList<>();

		try {
			CertificateFactory factory = CertificateFactory.getInstance(CERTIFICATE_TYPE_X509);

			while (certificateChainLength > 0) {
				int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
				byte[] certificate = reader.readBytes(certificateLength);
	
				// the size of the length and the actual length of the encoded certificate
				certificateChainLength -= (CERTIFICATE_LENGTH_BITS/8) + certificateLength;

				certs.add(factory.generateCertificate(new ByteArrayInputStream(certificate)));
			}

			return new CertificateMessage(factory.generateCertPath(certs), peerAddress);

		} catch (CertificateException e) {
			throw new HandshakeException(
					"Cannot parse X.509 certificate chain provided by peer",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, peerAddress),
					e);
		}
	}

	/**
	 * Gets the public key contained in this message.
	 * 
	 * The key is either extracted from the certificate chain contained
	 * in the message or is instantiated from the <em>RawPublicKey</em>
	 * bytes from the message.
	 * 
	 * @return the peer's public key
	 */
	public PublicKey getPublicKey() {
		PublicKey publicKey = null;

		if (rawPublicKeyBytes == null) {
			if (certPath != null && !certPath.getCertificates().isEmpty()) {
				publicKey = certPath.getCertificates().get(0).getPublicKey();
			}// else : no public key in this certificate message
		} else {
			// get server's public key from Raw Public Key
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rawPublicKeyBytes);
			try {
				// TODO make instance variable
				// TODO dynamically determine algorithm for KeyFactory creation
				publicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
			} catch (GeneralSecurityException e) {
				LOGGER.error("Could not reconstruct the peer's public key", e);
			}
		}
		return publicKey;
	}
}
