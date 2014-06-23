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

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
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
public class CertificateMessage extends HandshakeMessage {

	// Logging ///////////////////////////////////////////////////////////

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
	private Certificate[] certificateChain;

	/** The encoded chain of certificates */
	private List<byte[]> encodedChain;

	/** The total length of the {@link CertificateMessage}. */
	private int messageLength;
	
	/**
	 * The SubjectPublicKeyInfo part of the X.509 certificate. Used in
	 * constrained environments for smaller message size.
	 */
	private byte[] rawPublicKeyBytes = null;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Adds the whole certificate chain to the message and if requested extracts
	 * the raw public key from the server's certificate.
	 * 
	 * @param certificateChain
	 *            the certificate chain (first certificate must be the
	 *            server's).
	 * @param useRawPublicKey
	 *            whether only the raw public key (SubjectPublicKeyInfo) is
	 *            needed.
	 */
	public CertificateMessage(Certificate[] certificateChain, boolean useRawPublicKey) {
		this.certificateChain = certificateChain;
		if (useRawPublicKey) {
			this.rawPublicKeyBytes = certificateChain[0].getPublicKey().getEncoded();
		}
	}

	/**
	 * Called when only the raw public key is available (and not the whole
	 * certificate chain).
	 * 
	 * @param rawPublicKeyBytes
	 *            the raw public key (SubjectPublicKeyInfo).
	 */
	public CertificateMessage(byte[] rawPublicKeyBytes) {
		this.rawPublicKeyBytes = rawPublicKeyBytes;
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE;
	}

	@Override
	public int getMessageLength() {
		if (rawPublicKeyBytes == null) {
			// the certificate chain length uses 3 bytes
			// each certificate's length in the chain also uses 3 bytes
			if (encodedChain == null) {
				messageLength = 3;
				encodedChain = new ArrayList<byte[]>(certificateChain.length);
				for (Certificate cert : certificateChain) {
					try {
						byte[] encoded = cert.getEncoded();
						encodedChain.add(encoded);

						// the length of the encoded certificate plus 3 bytes
						// for
						// the length
						messageLength += encoded.length + 3;
					} catch (CertificateEncodingException e) {
						encodedChain = null;
						LOGGER.log(Level.SEVERE,"Could not encode the certificate.", e);
					}
				}
			}
		} else {
			// fixed: 3 bytes for certificates length field + 3 bytes for
			// certificate length
			messageLength = 6 + rawPublicKeyBytes.length;
			// TODO still unclear whether the payload only consists of the raw public key
			
			// http://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.2:
			// "If the negotiated certificate type is RawPublicKey the TLS server
			// MUST place the SubjectPublicKeyInfo structure into the Certificate
			// payload. The public key MUST match the selected key exchange algorithm."
		}
		return messageLength;
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
			sb.append("\t\tRaw Public Key:\n");
			sb.append("\t\t\t" + getPublicKey().toString() + "\n");
		}

		return sb.toString();
	}

	public Certificate[] getCertificateChain() {
		return certificateChain;
	}
	
	/**
	 * Tries to verify the peer's certificate. Checks its validity and verifies
	 * that it was signed with the stated private key.
	 * 
	 * @throws HandshakeException
	 *             if the certificate could not be verified.
	 */
	public void verifyCertificate(Certificate[] trustedCertificates) throws HandshakeException {
		if (rawPublicKeyBytes == null) {
			boolean verified = false;

			X509Certificate peerCertificate = (X509Certificate) certificateChain[0];
			try {
				peerCertificate.checkValidity();
			} catch (Exception e) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.CERTIFICATE_EXPIRED);
				throw new HandshakeException("Certificate not valid.", alert);
			}
			
			if (isSelfSigned(peerCertificate)) {
				// TODO allow self-signed certificates?
				LOGGER.info("Peer used self-signed certificate.");
				return;
			}

			try {
				verified = validateKeyChain(peerCertificate, certificateChain, trustedCertificates);

			} catch (Exception e) {
				e.printStackTrace();
			}

			if (!verified) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				throw new HandshakeException("Certificate could not be verified.", alert);
			}
		}
	}
	
	/**
	 * Tries to validate the certificate chain with the given intermediate and
	 * trusted certificates.
	 * 
	 * @param certificate
	 *            the end of the certificate chain which needs to be verified.
	 * @param intermediateCertificates
	 *            the intermediate certificates (not trusted).
	 * @param trustedCertificates
	 *            the trusted certificates.
	 * @return <code>true</code> if the chain could be validated,
	 *         <code>false</code> otherwise.
	 */
	public boolean validateKeyChain(X509Certificate certificate, Certificate[] intermediateCertificates, Certificate[] trustedCertificates) {
		
		// first check all the intermediate certificates, if one of these signed
		// the chain's end certificate
		for (Certificate cert : intermediateCertificates) {
			X509Certificate intermediateCertificate = (X509Certificate) cert;
			
			if (certificate.getIssuerX500Principal().equals(intermediateCertificate.getSubjectX500Principal())) {
				try {
					certificate.verify(intermediateCertificate.getPublicKey());
				} catch (Exception e) {
					continue;
				}

				if (!isSelfSigned(intermediateCertificate) && !certificate.equals(intermediateCertificate)) {
					// intermediate certificates can't be trusted to
					// complete the chain, but they can be middle parts
					return validateKeyChain(intermediateCertificate, intermediateCertificates, trustedCertificates);
				}

			}

		}
		
		// check all trusted certificates, if one of theses is the root of the
		// certificate chain
		for (Certificate cert : trustedCertificates) {
			X509Certificate trustedCertificate = (X509Certificate) cert;

			if (certificate.getIssuerX500Principal().equals(trustedCertificate.getSubjectX500Principal())) {
				try {
					certificate.verify(trustedCertificate.getPublicKey());
				} catch (Exception e) {
					continue;
				}

				if (isSelfSigned(trustedCertificate)) {
					return true;
				} else if (!certificate.equals(trustedCertificate)) {
					// follow next step of the chain
					return validateKeyChain(trustedCertificate, intermediateCertificates, trustedCertificates);
				}

			}

		}
		// no valid chain found
		return false;
	}
	
	/**
	 * Checks whether this certificate was signed with the private key that
	 * corresponds to this certificates public key.
	 * 
	 * @param certificate
	 *            the certificate to be checked for self-signing.
	 * @return <code>true</code> if the certificate was self-signed,
	 *         <code>false</code> otherwise.
	 */
	private boolean isSelfSigned(X509Certificate certificate) {
		try {
            certificate.verify(certificate.getPublicKey());
            
            return true;
        } catch (Exception e) {
        	// the certificate was not signed with this public key
            return false;
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

	public static HandshakeMessage fromByteArray(byte[] byteArray, boolean useRawPublicKey) {

		DatagramReader reader = new DatagramReader(byteArray);

		int certificateChainLength = reader.read(CERTIFICATE_LENGTH_BITS);
		
		CertificateMessage message;
		if (useRawPublicKey) {
			int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
			byte[] rawPublicKey = reader.readBytes(certificateLength);
			message = new CertificateMessage(rawPublicKey);
		} else {
			List<Certificate> certs = new ArrayList<Certificate>();

			CertificateFactory certificateFactory = null;
			while (certificateChainLength > 0) {
				int certificateLength = reader.read(CERTIFICATE_LENGTH_BITS);
				byte[] certificate = reader.readBytes(certificateLength);

				// the size of the length and the actual length of the encoded certificate
				certificateChainLength -= (CERTIFICATE_LENGTH_BITS/8) + certificateLength;

				try {
					if (certificateFactory == null) {
						// doing this in try/catch
						certificateFactory = CertificateFactory.getInstance("X.509");
					}
					Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(certificate));
					certs.add(cert);
				} catch (CertificateException e) {
					LOGGER.log(Level.SEVERE,"Could not generate the certificate.",e);
					break;
				}
			}

			message = new CertificateMessage(certs.toArray(new X509Certificate[certs.size()]), useRawPublicKey);
		}
		
		return message;
	}

	/**
	 * @return the peer's public contained in its certificate.
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
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE,"Could not reconstruct the server's public key.",e);
			}
		}
		return publicKey;

	}

}
