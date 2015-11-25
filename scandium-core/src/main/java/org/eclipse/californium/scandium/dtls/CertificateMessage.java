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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add access to client identity
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 469593 (validation of peer certificate chain)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - improve handling of empty messages
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 477074 (erroneous encoding of RPK)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

/**
 * The server MUST send a Certificate message whenever the agreed-upon key
 * exchange method uses certificates for authentication. This message will
 * always immediately follow the {@link ServerHello} message. For details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.2">RFC 5246</a>.
 */
public final class CertificateMessage extends HandshakeMessage {

	// Logging ///////////////////////////////////////////////////////////

	private static final String CERTIFICATE_TYPE_X509 = "X.509";

	private static final Logger LOGGER = Logger.getLogger(CertificateMessage.class.getCanonicalName());

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
	private X509Certificate[] certificateChain;

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
	public CertificateMessage(Certificate[] certificateChain, InetSocketAddress peerAddress) {
		super(peerAddress);
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null");
		} else {
			setCertificateChain(certificateChain);
			calculateLength(certificateChain);
		}
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
	 */
	private void setCertificateChain(Certificate[] chain) {
		List<X509Certificate> certificates = new ArrayList<>();
		X500Principal issuer = null;
		X509Certificate cert;
		for (Certificate c : chain) {
			if (!(c instanceof X509Certificate)) {
				throw new IllegalArgumentException(
						"Certificate chain must consist of X.509 certificates only");
			} else {
				cert = (X509Certificate) c;
				LOGGER.log(Level.FINER, "Current Subject DN: {0}", cert.getSubjectX500Principal().getName());
				if (issuer != null && !issuer.equals(cert.getSubjectX500Principal())) {
					LOGGER.log(Level.FINER, "Actual Issuer DN: {0}",
							cert.getSubjectX500Principal().getName());
					throw new IllegalArgumentException("Given certificates do not form a chain");
				}
				if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
					// not a self-signed certificate
					certificates.add(cert);
					issuer = cert.getIssuerX500Principal();
					LOGGER.log(Level.FINER, "Expected Issuer DN: {0}", issuer.getName());
				}
			}
		}
		this.certificateChain = certificates.toArray(new X509Certificate[]{});
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE;
	}

	private void calculateLength(Certificate[] certificateChain) {
		if (certificateChain != null && encodedChain == null) {
			// the certificate chain length uses 3 bytes
			// each certificate's length in the chain also uses 3 bytes
			encodedChain = new ArrayList<byte[]>(certificateChain.length);
			try {
				for (Certificate cert : certificateChain) {
					byte[] encoded = cert.getEncoded();
					encodedChain.add(encoded);

					// the length of the encoded certificate (3 bytes) plus the
					// encoded bytes
					length += 3 + encoded.length;
				}
			} catch (CertificateEncodingException e) {
				encodedChain = null;
				LOGGER.log(Level.SEVERE, "Could not encode certificate chain", e);
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
		if (rawPublicKeyBytes == null && certificateChain != null) {
			sb.append("\t\tCertificate chain length: ").append(getMessageLength() - 3).append("\n");
			int index = 0;
			for (Certificate cert : certificateChain) {
				sb.append("\t\t\tCertificate Length: ").append(encodedChain.get(index).length).append("\n");
				sb.append("\t\t\tCertificate: ").append(cert).append("\n");
				index++;
			}
		} else if (rawPublicKeyBytes != null && certificateChain == null) {
			sb.append("\t\tRaw Public Key: ");
			sb.append(getPublicKey().toString());
			sb.append("\n");
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
	public X509Certificate[] getCertificateChain() {
		if (certificateChain != null) {
			return Arrays.copyOf(certificateChain, certificateChain.length);
		} else {
			return null;
		}
	}
	
	private static Set<TrustAnchor> getTrustAnchors(Certificate[] trustedCertificates) {
		Set<TrustAnchor> result = new HashSet<>();
		if (trustedCertificates != null) {
			for (Certificate cert : trustedCertificates) {
				if (CERTIFICATE_TYPE_X509.equals(cert.getType())) {
					result.add(new TrustAnchor((X509Certificate) cert, null));
				} else {
					LOGGER.log(Level.INFO,
							"List of trusted CA certificates contains non-X.509 certificate of type [{0}]",
							cert.getType());
				}
			}
		}
		return result;
	}

	/**
	 * Validates the X.509 certificate chain provided by the the peer as part of this message.
	 * 
	 * This method checks
	 * <ol>
	 * <li>that each certificate's issuer DN equals the subject DN of the next certiciate in the chain</li>
	 * <li>that each certificate is currently valid according to its validity period</li>
	 * <li>that the chain is rooted at a trusted CA</li>
	 * </ol>
	 * 
	 * @param trustedCertificates the list of trusted root CAs
	 * 
	 * @throws HandshakeException if any of the checks fails
	 */
	public void verifyCertificate(Certificate[] trustedCertificates) throws HandshakeException {
		if (rawPublicKeyBytes == null) {

			Set<TrustAnchor> trustAnchors = getTrustAnchors(trustedCertificates);
			
			try {
				CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE_X509);
				CertPath certPath = certFactory.generateCertPath(Arrays.asList(certificateChain));
				
				PKIXParameters params = new PKIXParameters(trustAnchors);
				// TODO: implement alternative means of revocation checking
				params.setRevocationEnabled(false);
				
				CertPathValidator validator = CertPathValidator.getInstance("PKIX");
				validator.validate(certPath, params);
				
			} catch (GeneralSecurityException e) {
				if (LOGGER.isLoggable(Level.FINEST)) {
					LOGGER.log(Level.FINEST, "Certificate validation failed", e);
				} else if (LOGGER.isLoggable(Level.FINE)) {
					LOGGER.log(Level.FINE, "Certificate validation failed due to {0}", e.getMessage());
				}
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, getPeer());
				throw new HandshakeException("Certificate chain could not be validated", alert);
			}			
		}
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

	public static CertificateMessage fromByteArray(byte[] byteArray, boolean useRawPublicKey, InetSocketAddress peerAddress) 
		throws HandshakeException {

		DatagramReader reader = new DatagramReader(byteArray);

		if (useRawPublicKey) {
			LOGGER.log(Level.FINER, "Parsing RawPublicKey CERTIFICATE message");
			int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
			byte[] rawPublicKey = reader.readBytes(certificateLength);
			return new CertificateMessage(rawPublicKey, peerAddress);
		} else {
			return readX509CertificateMessage(reader, peerAddress);
		}
	}

	private static CertificateMessage readX509CertificateMessage(DatagramReader reader, InetSocketAddress peerAddress) throws HandshakeException {
		LOGGER.log(Level.FINER, "Parsing X.509 CERTIFICATE message");
		int certificateChainLength = reader.read(CERTIFICATE_LIST_LENGTH);
		List<Certificate> certs = new ArrayList<Certificate>();

		CertificateFactory certificateFactory = null;
		while (certificateChainLength > 0) {
			int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
			byte[] certificate = reader.readBytes(certificateLength);

			// the size of the length and the actual length of the encoded certificate
			certificateChainLength -= (CERTIFICATE_LENGTH_BITS/8) + certificateLength;

			try {
				if (certificateFactory == null) {
					certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE_X509);
				}
				certs.add(certificateFactory.generateCertificate(new ByteArrayInputStream(certificate)));
			} catch (CertificateException e) {
				throw new HandshakeException(
						"Cannot parse X.509 certificate chain provided by peer",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, peerAddress),
						e);
			}
		}

		return new CertificateMessage(certs.toArray(new X509Certificate[certs.size()]), peerAddress);
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
			if (certificateChain != null && certificateChain.length > 0) {
				publicKey = certificateChain[0].getPublicKey();
			}// else : no public key in this certificate message
		} else {
			// get server's public key from Raw Public Key
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rawPublicKeyBytes);
			try {
				// TODO make instance variable
				// TODO dynamically determine algorithm for KeyFactory creation
				publicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.SEVERE, "Could not reconstruct the peer's public key", e);
			}
		}
		return publicKey;
	}
}
