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
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
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
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2" target=
	 * "_blank">RFC 5246</a>: {@code opaque ASN.1Cert<1..2^24-1>;}
	 */
	private static final int CERTIFICATE_LENGTH_BITS = 24;

	/**
	 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2" target=
	 * "_blank">RFC 5246</a>: {@code ASN.1Cert certificate_list<0..2^24-1>;}
	 */
	private static final int CERTIFICATE_LIST_LENGTH_BITS = 24;

	/**
	 * X509 certificate factory.
	 * 
	 * @since 2.4
	 */
	private static final ThreadLocalCertificateFactory CERTIFICATE_FACTORY = new ThreadLocalCertificateFactory(
			CERTIFICATE_TYPE_X509);

	/**
	 * Empty certificate chain.
	 * 
	 * Used for empty client certificate messages, if no matching certificate is
	 * available.
	 * 
	 * Note: <a href="https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.6"
	 * target="_blank">RFC 5246, 7.4.6 Client Certificate</a>
	 * 
	 * "If no suitable certificate is available, the client MUST send a
	 * certificate message containing no certificates. That is, the
	 * certificate_list structure has a length of zero."
	 * 
	 * That complies to the definition of:
	 * <a href="https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.2"
	 * target="_blank">RFC 5246, 7.4.2 Server Certificate</a>
	 * 
	 * <pre>
	 * struct {
	 *    ASN.1Cert certificate_list{@code <0..2^24-1>};
	 * } Certificate;
	 * </pre>
	 * 
	 * (0 as minimum value.)
	 * 
	 * <a href="https://www.rfc-editor.org/rfc/rfc7250#section-3" target=
	 * "_blank">RFC 7250, 3 Structure of the Raw Public Key Extension</a>
	 * 
	 * extends that by
	 * 
	 * <pre>
	 * struct {
	 *    select(certificate_type){
	 * 
	 *       // certificate type defined in this document.
	 *       case RawPublicKey:
	 *          opaque ASN.1_subjectPublicKeyInfo{@code <1..2^24-1>};
	 * 
	 *       // X.509 certificate defined in RFC 5246
	 *       case X.509:
	 *          ASN.1Cert certificate_list{@code <0..2^24-1>};
	 * 
	 *       // Additional certificate type based on
	 *       // "TLS Certificate Types" subregistry
	 *    };
	 * } Certificate;
	 * </pre>
	 * 
	 * The culprit of this definition is, that the minimum length for a Raw
	 * Public key certificate is 1. That creates a contradiction to the client
	 * certificate definition in RFC 5246. Californium follows therefore RFC5246
	 * and relaxes that 1 also to 0.
	 * 
	 * @since 3.6
	 */
	private static final CertPath EMPTY_CERT_PATH;

	private static final List<byte[]> EMPTY_ENCODED_CHAIN;

	static {
		CertPath certPath = null;
		try {
			List<Certificate> certs = Collections.emptyList();
			CertificateFactory factory = CERTIFICATE_FACTORY.currentWithCause();
			certPath = factory.generateCertPath(certs);
		} catch (GeneralSecurityException e) {
		}
		EMPTY_CERT_PATH = certPath;
		EMPTY_ENCODED_CHAIN = Collections.emptyList();
	}

	/**
	 * A chain of certificates asserting the sender's identity. The sender's
	 * identity is reflected by the certificate at index 0.
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

	// length is at least 3 bytes containing the message's overall number of
	// bytes
	private final int length;

	/**
	 * Creates a empty <em>CERTIFICATE</em> message containing a empty
	 * certificate chain.
	 * 
	 * @since 3.0
	 */
	public CertificateMessage() {
		this(EMPTY_CERT_PATH);
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a certificate chain.
	 * 
	 * @param certificateChain the certificate chain with the (first certificate
	 *            must be the server's)
	 * @throws NullPointerException if the certificate chain is {@code null}
	 *             (use an array of length zero to create an <em>empty</em>
	 *             message)
	 * @throws IllegalArgumentException if the certificate chain contains any
	 *             non-X.509 certificates or does not form a valid chain of
	 *             certification.
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
	 * @throws NullPointerException if the certificate chain is {@code null}
	 *             (use an array of length zero to create an <em>empty</em>
	 *             message)
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
				LOGGER.debug(
						"created CERTIFICATE message with truncated certificate chain [length: {}, full-length: {}]",
						size, certificateChain.size());
			} else {
				LOGGER.debug("created CERTIFICATE message with certificate chain [length: {}]", size);
			}
		}
	}

	private CertificateMessage(CertPath peerCertChain) {
		if (peerCertChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		this.rawPublicKeyBytes = null;
		this.certPath = peerCertChain;

		List<? extends Certificate> certificates = peerCertChain.getCertificates();
		int size = certificates.size();
		if (size == 0) {
			this.publicKey = null;
			this.encodedChain = EMPTY_ENCODED_CHAIN;
			this.length = CERTIFICATE_LENGTH_BITS / Byte.SIZE;
		} else {
			List<byte[]> encodedChain = new ArrayList<byte[]>(size);
			int length = 0;
			try {
				for (Certificate cert : certificates) {
					byte[] encoded = cert.getEncoded();
					encodedChain.add(encoded);

					// the length of the encoded certificate (3 bytes)
					// plus the encoded bytes
					length += (CERTIFICATE_LENGTH_BITS / Byte.SIZE) + encoded.length;
				}
			} catch (CertificateEncodingException e) {
				encodedChain = EMPTY_ENCODED_CHAIN;
				length = 0;
				LOGGER.warn("Could not encode certificate chain", e);
			}
			this.publicKey = encodedChain.isEmpty() ? null : certificates.get(0).getPublicKey();
			this.encodedChain = encodedChain;
			// the certificate chain length uses 3 bytes
			this.length = length + CERTIFICATE_LENGTH_BITS / Byte.SIZE;
		}
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a raw public key.
	 * 
	 * @param publicKey the public key, {@code null} for an empty
	 *            <em>CERTIFICATE</em> message
	 */
	public CertificateMessage(PublicKey publicKey) {
		this.publicKey = publicKey;
		if (publicKey == null) {
			this.rawPublicKeyBytes = null;
			this.certPath = EMPTY_CERT_PATH;
			this.encodedChain = EMPTY_ENCODED_CHAIN;
			this.length = CERTIFICATE_LENGTH_BITS / Byte.SIZE;
		} else {
			this.certPath = null;
			this.encodedChain = null;
			this.rawPublicKeyBytes = publicKey.getEncoded();
			this.length = (CERTIFICATE_LENGTH_BITS / Byte.SIZE) + rawPublicKeyBytes.length;
		}
	}

	/**
	 * Creates a <em>CERTIFICATE</em> message containing a raw public key.
	 * 
	 * @param rawPublicKeyBytes the raw public key (SubjectPublicKeyInfo).
	 *            {@code null} or empty array for an empty <em>CERTIFICATE</em>
	 *            message
	 */
	public CertificateMessage(byte[] rawPublicKeyBytes) {
		this(generateRawPublicKey(rawPublicKeyBytes));
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
			sb.append(indentation).append("Certificate chain: ").append(certificates.size()).append(" certificates")
					.append(StringUtil.lineSeparator());
			int index = 0;
			for (Certificate cert : certificates) {
				sb.append(indentation2).append("Certificate Length: ").append(encodedChain.get(index).length)
						.append(" bytes").append(StringUtil.lineSeparator());
				String text = StringUtil.toDisplayString(cert);
				sb.append(indentation2).append("Certificate[").append(index).append(".]: ");
				sb.append(text.replaceAll("\n", "\n" + indentation2)).append(StringUtil.lineSeparator());
				index++;
			}
		} else if (rawPublicKeyBytes != null && certPath == null) {
			sb.append(indentation).append("Raw Public Key: ");
			String text;
			if (publicKey != null) {
				text = StringUtil.toDisplayString(publicKey);
				text = text.replaceAll("\n", "\n" + indentation2);
			} else {
				text = "<empty>";
			}
			sb.append(text.replaceAll("\n", "\n" + indentation2));
			sb.append(StringUtil.lineSeparator());
		}

		return sb.toString();
	}

	/**
	 * Gets the public key contained in this message.
	 * 
	 * The key is either extracted from the certificate chain contained in the
	 * message or is instantiated from the <em>RawPublicKey</em> bytes from the
	 * message.
	 * 
	 * @return the peer's public key. {@code null}, for an empty
	 *         <em>CERTIFICATE</em> message.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the certificate chain provided by the peer.
	 * 
	 * This method only provides a result if the peer uses <em>X.509</em>
	 * certificates. In that case the returned array contains the peer's public
	 * key certificate at position 0.
	 * 
	 * Note: if <em>RawPublicKey</em> is used, and the client has no no suitable
	 * public key, this is interpreted as empty list.
	 * 
	 * @return the certificate chain or {@code null}, if <em>RawPublicKey</em>s
	 *         are used. May be an empty certificate path, if the client has no
	 *         suitable certificate or public key.
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
		return publicKey == null;
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
	 * @param certificateType negotiated type of certificate the certificate
	 *            message contains.
	 * @return The certificate message.
	 * @throws HandshakeException if the binary encoding could not be parsed.
	 * @throws IllegalArgumentException if the certificate type is not
	 *             supported.
	 */
	public static CertificateMessage fromReader(DatagramReader reader, CertificateType certificateType)
			throws HandshakeException {

		int certificatesLength = reader.read(CERTIFICATE_LIST_LENGTH_BITS);
		if (certificatesLength == 0) {
			// anonymous peer
			return new CertificateMessage(EMPTY_CERT_PATH);
		} else if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
			LOGGER.debug("Parsing RawPublicKey CERTIFICATE message");
			byte[] rawPublicKey = reader.readBytes(certificatesLength);
			return new CertificateMessage(rawPublicKey);
		} else if (CertificateType.X_509 == certificateType) {
			reader = reader.createRangeReader(certificatesLength);
			LOGGER.debug("Parsing X.509 CERTIFICATE message");
			try {
				CertificateFactory factory = CERTIFICATE_FACTORY.currentWithCause();
				List<Certificate> certs = new ArrayList<>();

				while (reader.bytesAvailable()) {
					int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
					certs.add(factory.generateCertificate(reader.createRangeInputStream(certificateLength)));
				}

				return new CertificateMessage(factory.generateCertPath(certs));

			} catch (GeneralSecurityException e) {
				throw new HandshakeException("Cannot parse X.509 certificate chain provided by peer",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE), e);
			}
		} else {
			throw new IllegalArgumentException("Certificate type " + certificateType + " not supported!");
		}
	}

	/**
	 * Generate <em>RawPublicKey</em> from binary representation.
	 * 
	 * @param rawPublicKeyBytes byte array with binary representation. May be
	 *            {@code null} or empyt.
	 * @return generated public key, or {@code null}, if the byte array doesn't
	 *         contain a public key.
	 * @since 3.6
	 */
	private static PublicKey generateRawPublicKey(byte[] rawPublicKeyBytes) {
		if (rawPublicKeyBytes != null && rawPublicKeyBytes.length > 0) {
			try {
				String keyAlgorithm = Asn1DerDecoder.readSubjectPublicKeyAlgorithm(rawPublicKeyBytes);
				if (keyAlgorithm != null) {
					ThreadLocalKeyFactory factory = ThreadLocalKeyFactory.KEY_FACTORIES.get(keyAlgorithm);
					if (factory != null && factory.current() != null) {
						return factory.current().generatePublic(new X509EncodedKeySpec(rawPublicKeyBytes));
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
		return null;
	}

}
