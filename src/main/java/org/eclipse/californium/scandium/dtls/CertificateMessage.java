/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
	 * This is a sequence (chain) of certificates. The sender's certificate MUST
	 * come first in the list.
	 */
	private final Certificate[] certificateChain;

	/** The encoded chain of certificates */
	private List<byte[]> encodedChain;

	/**
	 * The SubjectPublicKeyInfo part of the X.509 certificate. Used in
	 * constrained environments for smaller message size.
	 */
	private final byte[] rawPublicKeyBytes;
	
	private int length;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Adds the whole certificate chain to the message and if requested extracts
	 * the raw public key from the server's certificate.
	 * 
	 * @param certificateChain
	 *            the certificate chain (first certificate must be the
	 *            server's)
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public CertificateMessage(Certificate[] certificateChain, InetSocketAddress peerAddress) {
		this(null, certificateChain, peerAddress);
		calculateLength(certificateChain);
	}

	/**
	 * Called when only the raw public key is available (and not the whole
	 * certificate chain).
	 * 
	 * @param rawPublicKeyBytes
	 *           the raw public key (SubjectPublicKeyInfo)
	 * @param peerAddress the IP address and port of the peer this
	 *           message has been received from or should be sent to
	 */
	public CertificateMessage(byte[] rawPublicKeyBytes, InetSocketAddress peerAddress) {
		this(rawPublicKeyBytes, null, peerAddress);
		// fixed: 3 bytes for certificates length field + 3 bytes for
		// certificate length
		length = 6 + rawPublicKeyBytes.length;
		// TODO still unclear whether the payload only consists of the raw public key
		
		// http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.2:
		// "If the negotiated certificate type is RawPublicKey the TLS server
		// MUST place the SubjectPublicKeyInfo structure into the Certificate
		// payload. The public key MUST match the selected key exchange algorithm."
	}
	
	private CertificateMessage(byte[] rawPublicKey, Certificate[] certificateChain, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.rawPublicKeyBytes = rawPublicKey;
		this.certificateChain = certificateChain;
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE;
	}

	private void calculateLength(Certificate[] certificateChain) {
		if (certificateChain != null) {
			// the certificate chain length uses 3 bytes
			// each certificate's length in the chain also uses 3 bytes
			if (encodedChain == null) {
				length = 3;
				encodedChain = new ArrayList<byte[]>(certificateChain.length);
				for (Certificate cert : certificateChain) {
					try {
						byte[] encoded = cert.getEncoded();
						encodedChain.add(encoded);

						// the length of the encoded certificate plus 3 bytes
						// for the length
						length += encoded.length + 3;
					} catch (CertificateEncodingException e) {
						encodedChain = null;
						LOGGER.log(Level.SEVERE, "Could not encode certificate chain", e);
					}
				}
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
		if (rawPublicKeyBytes == null) {
			sb.append("\t\tCertificates Length: " + (getMessageLength() - 3) + "\n");
			int index = 0;
			for (Certificate cert : certificateChain) {
				sb.append("\t\t\tCertificate Length: " + encodedChain.get(index).length + "\n");
				sb.append("\t\t\tCertificate: " + cert.toString() + "\n");

				index++;
			}
		} else {
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
	public Certificate[] getCertificateChain() {
		if (certificateChain != null) {
			return Arrays.copyOf(certificateChain, certificateChain.length);
		} else {
			return null;
		}
	}
	
	private Set<TrustAnchor> getTrustAnchors(Certificate[] trustedCertificates) {
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
				LOGGER.log(Level.FINE, "Certificate validation failed due to {0}", e.getMessage());
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
			// the size of the certificate chain
			writer.write(getMessageLength() - (CERTIFICATE_LIST_LENGTH/8), CERTIFICATE_LIST_LENGTH);
			for (byte[] encoded : encodedChain) {
				// the size of the current certificate
				writer.write(encoded.length, CERTIFICATE_LENGTH_BITS);
				// the encoded current certificate
				writer.writeBytes(encoded);
			}
		} else {
			writer.write(getMessageLength() - 3, CERTIFICATE_LIST_LENGTH);
			writer.write(rawPublicKeyBytes.length, CERTIFICATE_LENGTH_BITS);
			writer.writeBytes(rawPublicKeyBytes);
		}

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray, boolean useRawPublicKey, InetSocketAddress peerAddress) {

		DatagramReader reader = new DatagramReader(byteArray);

		int certificateChainLength = reader.read(CERTIFICATE_LENGTH_BITS);
		
		CertificateMessage message;
		if (useRawPublicKey) {
			LOGGER.log(Level.FINER, "Parsing RawPublicKey CERTIFICATE message");
			int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
			byte[] rawPublicKey = reader.readBytes(certificateLength);
			message = new CertificateMessage(rawPublicKey, peerAddress);
		} else {
			LOGGER.log(Level.FINER, "Parsing X.509 CERTIFICATE message");
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
					LOGGER.log(Level.INFO,
							"Could not create X.509 certificate from byte array, reason [{0}]",
							e.getMessage());
					break;
				}
			}

			message = new CertificateMessage(certs.toArray(new X509Certificate[certs.size()]), peerAddress);
		}
		
		return message;
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
			publicKey = certificateChain[0].getPublicKey();
		} else {
			// get server's public key from Raw Public Key
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rawPublicKeyBytes);
			try {
				// TODO make instance variable
				publicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.SEVERE, "Could not reconstruct the peer's public key.", e);
			}
		}
		return publicKey;

	}

}
