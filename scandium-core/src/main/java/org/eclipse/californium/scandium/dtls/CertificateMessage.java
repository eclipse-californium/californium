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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add access to client identity
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 469593 (validation of peer certificate chain)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve handling of empty messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 477074 (erroneous encoding of RPK)
 *    Ludwig Seitz (RISE SICS) - Moved certificate validation to Handshaker
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCertificateFactory;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server MUST send a Certificate message whenever the agreed-upon key
 * exchange method uses certificates for authentication. This message will
 * always immediately follow the {@link ServerHello} message. For details see
 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2" target=
 * "_blank">RFC 5246</a>.
 */
public final class CertificateMessage extends HandshakeMessage {

	private static final String CERTIFICATE_TYPE_X509 = "X.509";

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateMessage.class);

	/**
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2" target="_blank">RFC 5246</a>:
	 * {@code opaque ASN.1Cert<1..2^24-1>;}
	 */
	private static final int CERTIFICATE_LENGTH_BITS = 24;

	/**
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2" target="_blank">RFC 5246</a>:
	 * {@code ASN.1Cert certificate_list<0..2^24-1>;}
	 */
	private static final int CERTIFICATE_LIST_LENGTH_BITS = 24;

	/**
	 * @since 2.4
	 */
	private static final ThreadLocalCertificateFactory CERTIFICATE_FACTORY = new ThreadLocalCertificateFactory(
			CERTIFICATE_TYPE_X509);

	/**
	 * Empty certificate chain. Used for empty client certificate messages, if
	 * no matching certificate is available.
	 * 
	 * @since 3.0
	 */
	private static final List<X509Certificate> EMPTY = Collections.emptyList();

	/**
	 * A chain of certificates asserting the sender's identity.
	 * The sender's identity is reflected by the certificate at index 0.
	 */
	private final CertPath certPath;

	/** The encoded chain of certificates */
	private final List<byte[]> encodedChain;

	/**
	 * The SubjectPublicKeyInfo part of the X.509 certificate. Used in
	 * constrained environments for smaller message size.
	 */
	private final byte[] rawPublicKeyBytes;
	private final PublicKey publicKey;

	// length is at least 3 bytes containing the message's overall number of bytes
	private final int length;

	/**
	 * Creates a empty <em>CERTIFICATE</em> message containing a empty
	 * certificate chain.
	 * 
	 * @since 3.0
	 */
	public CertificateMessage() {
		this(EMPTY, null);
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a certificate chain.
	 * 
	 * @param certificateChain
	 *            the certificate chain with the (first certificate must be the
	 *            server's)
	 * @throws NullPointerException if the certificate chain is {@code null}
	 *            (use an array of length zero to create an <em>empty</em> message)
	 * @throws IllegalArgumentException if the certificate chain contains any
	 *            non-X.509 certificates or does not form a valid chain of
	 *            certification.
	 * 
	 */
	public CertificateMessage(List<X509Certificate> certificateChain) {
		this(certificateChain, null);
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a certificate chain.
	 * 
	 * @param certificateChain the certificate chain with the (first certificate
	 *            must be the server's)
	 * @param certificateAuthorities the certificate authorities to truncate
	 *            chain. Maybe {@code null} or empty.
	 * @throws NullPointerException if the certificate chain is
	 *             {@code null} (use an array of length zero to create an
	 *             <em>empty</em> message)
	 * @throws IllegalArgumentException if the certificate chain contains any
	 *             non-X.509 certificates or does not form a valid chain of
	 *             certification.
	 * @since 2.1
	 */
	public CertificateMessage(List<X509Certificate> certificateChain, List<X500Principal> certificateAuthorities) {
		this(CertPathUtil.generateValidatableCertPath(certificateChain, certificateAuthorities));
		if (LOGGER.isDebugEnabled()) {
			int size = certPath.getCertificates().size();
			if (size < certificateChain.size()) {
				LOGGER.debug("created CERTIFICATE message with truncated certificate chain [length: {}, full-length: {}]",
						size, certificateChain.size());
			} else {
				LOGGER.debug("created CERTIFICATE message with certificate chain [length: {}]", size);
			}
		}
	}

	private CertificateMessage(CertPath peerCertChain) {
		if (peerCertChain == null) {
			throw new NullPointerException("Certificate chain must not be null");
		}
		this.rawPublicKeyBytes = null;
		this.certPath = peerCertChain;

		List<? extends Certificate> certificates = peerCertChain.getCertificates();
		int size = certificates.size();
		List<byte[]> encodedChain = new ArrayList<byte[]>(size);
		int length = 0;
		if (size > 0) {
			try {
				for (Certificate cert : certificates) {
					byte[] encoded = cert.getEncoded();
					encodedChain.add(encoded);

					// the length of the encoded certificate (3 bytes)
					// plus the encoded bytes
					length += (CERTIFICATE_LENGTH_BITS / Byte.SIZE) + encoded.length;
				}
			} catch (CertificateEncodingException e) {
				encodedChain = null;
				length = 0;
				LOGGER.warn("Could not encode certificate chain", e);
			}
		}
		this.publicKey = encodedChain == null || size == 0 ? null : certificates.get(0).getPublicKey();
		this.encodedChain = encodedChain;
		// the certificate chain length uses 3 bytes
		this.length = length + CERTIFICATE_LENGTH_BITS / Byte.SIZE;
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a raw public key.
	 * 
	 * @param publicKey
	 *           the public key
	 * @since 2.4
	 */
	public CertificateMessage(PublicKey publicKey) {
		this.certPath = null;
		this.encodedChain = null;
		this.rawPublicKeyBytes = publicKey == null ? Bytes.EMPTY : publicKey.getEncoded();
		this.length = (CERTIFICATE_LENGTH_BITS / Byte.SIZE) + rawPublicKeyBytes.length;
		this.publicKey = publicKey;
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a raw public key.
	 * 
	 * @param rawPublicKeyBytes
	 *           the raw public key (SubjectPublicKeyInfo)
	 * @throws NullPointerException if the raw public key byte array is {@code null}
	 *           (use an array of length zero to create an <em>empty</em> message)
	 */
	public CertificateMessage(byte[] rawPublicKeyBytes) {
		if (rawPublicKeyBytes == null) {
			throw new NullPointerException("Raw public key byte array must not be null");
		} else {
			this.certPath = null;
			this.encodedChain = null;
			this.rawPublicKeyBytes = Arrays.copyOf(rawPublicKeyBytes, rawPublicKeyBytes.length);
			this.length = (CERTIFICATE_LENGTH_BITS / Byte.SIZE) + rawPublicKeyBytes.length;
			// get server's public key from Raw Public Key
			PublicKey publicKey = null;
			if (rawPublicKeyBytes.length > 0) {
				try {
					String keyAlgorithm = Asn1DerDecoder.readSubjectPublicKeyAlgorithm(rawPublicKeyBytes);
					if (keyAlgorithm != null) {
						ThreadLocalKeyFactory factory = ThreadLocalKeyFactory.KEY_FACTORIES.get(keyAlgorithm);
						if (factory != null && factory.current() != null) {
							publicKey = factory.current().generatePublic(new X509EncodedKeySpec(rawPublicKeyBytes));
						}
					} else {
						LOGGER.info("Could not reconstruct the peer's public key [{}]",
								StringUtil.byteArray2Hex(rawPublicKeyBytes));
					}
				} catch (GeneralSecurityException e) {
					LOGGER.warn("Could not reconstruct the peer's public key", e);
				} catch (IllegalArgumentException e) {
					LOGGER.warn("Could not reconstruct the peer's public key", e);
				}
			}
			this.publicKey = publicKey;
		}
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE;
	}

	@Override
	public int getMessageLength() {
		return length;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		String indentation2 = StringUtil.indentation(indent + 2);
		if (rawPublicKeyBytes == null && certPath != null) {
			List<? extends Certificate> certificates = certPath.getCertificates();
			sb.append(indentation).append("Certificate chain: ").append(certificates.size()).append(" certificates").append(StringUtil.lineSeparator());
			int index = 0;
			for (Certificate cert : certificates) {
				sb.append(indentation2).append("Certificate Length: ").append(encodedChain.get(index).length).append(" bytes").append(StringUtil.lineSeparator());
				String text = StringUtil.toDisplayString(cert);
				sb.append(indentation2).append("Certificate[").append(index).append(".]: ");
				sb.append(text.replaceAll("\n", "\n" + indentation2)).append(StringUtil.lineSeparator());
				index++;
			}
		} else if (rawPublicKeyBytes != null && certPath == null) {
			sb.append(indentation).append("Raw Public Key: ");
			String text = StringUtil.toDisplayString(publicKey); 
			sb.append(text.replaceAll("\n", "\n" + indentation2));
			sb.append(StringUtil.lineSeparator());
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
	 * @return the certificate chain or {@code null}, if
	 *        <em>RawPublicKey</em>s are used
	 */
	public CertPath getCertificateChain() {
		return certPath;
	}

	/**
	 * Is empty certificate message.
	 * 
	 * If a server requests a client certificate, but the client has no proper
	 * certificate, the client respond with an empty certificate message.
	 * 
	 * @return {@code true}, if certificate message contains no certificates,
	 *         {@code false}, otherwise.
	 * @since 2.5
	 */
	public boolean isEmpty() {
		return encodedChain != null && encodedChain.isEmpty();
	}

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter(getMessageLength());

		if (rawPublicKeyBytes == null) {
			writer.write(getMessageLength() - (CERTIFICATE_LENGTH_BITS / Byte.SIZE), CERTIFICATE_LIST_LENGTH_BITS);
			// the size of the certificate chain
			for (byte[] encoded : encodedChain) {
				writer.writeVarBytes(encoded, CERTIFICATE_LENGTH_BITS);
			}
		} else {
			writer.writeVarBytes(rawPublicKeyBytes, CERTIFICATE_LENGTH_BITS);
		}

		return writer.toByteArray();
	}

	/**
	 * Creates a certificate message from its binary encoding.
	 * 
	 * @param reader reader for the binary encoding of the message.
	 * @param certificateType negotiated type of certificate the certificate message contains.
	 * @return The certificate message.
	 * @throws HandshakeException if the binary encoding could not be parsed.
	 * @throws IllegalArgumentException if the certificate type is not supported.
	 */
	public static CertificateMessage fromReader(
			DatagramReader reader,
			CertificateType certificateType) throws HandshakeException {

		if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
			LOGGER.debug("Parsing RawPublicKey CERTIFICATE message");
			byte[] rawPublicKey = reader.readVarBytes(CERTIFICATE_LENGTH_BITS);
			return new CertificateMessage(rawPublicKey);
		} else if (CertificateType.X_509 == certificateType) {
			return readX509CertificateMessage(reader);
		} else {
			throw new IllegalArgumentException("Certificate type " + certificateType + " not supported!");
		}
	}

	private static CertificateMessage readX509CertificateMessage(final DatagramReader reader) throws HandshakeException {

		LOGGER.debug("Parsing X.509 CERTIFICATE message");
		int certificateChainLength = reader.read(CERTIFICATE_LIST_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(certificateChainLength);
		try {
			CertificateFactory factory = CERTIFICATE_FACTORY.currentWithCause();
			List<Certificate> certs = new ArrayList<>();

			while (rangeReader.bytesAvailable()) {
				int certificateLength = rangeReader.read(CERTIFICATE_LENGTH_BITS);
				certs.add(factory.generateCertificate(rangeReader.createRangeInputStream(certificateLength)));
			}

			return new CertificateMessage(factory.generateCertPath(certs));

		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
					"Cannot parse X.509 certificate chain provided by peer",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE),
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
		return publicKey;
	}
}
