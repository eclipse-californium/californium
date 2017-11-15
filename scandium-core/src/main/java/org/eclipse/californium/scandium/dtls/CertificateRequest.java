/*******************************************************************************
 * Copyright (c) 2015 - 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;


/**
 * A non-anonymous server can optionally request a certificate from the client,
 * if appropriate for the selected cipher suite.
 * <p>
 * This message, if sent, will immediately follow the {@link ServerKeyExchange} message (if it is sent;
 * otherwise, this message follows the server's {@link CertificateMessage} message).
 * 
 * @see <a href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246, 7.4.4. Certificate Request</a>
 */
public final class CertificateRequest extends HandshakeMessage {

	private static final Logger LOGGER = Logger.getLogger(CertificateRequest.class.getName());

	// DTLS-specific constants ////////////////////////////////////////

	/* See http://tools.ietf.org/html/rfc5246#section-7.4.4 for message format. */

	private static final String THREE_TABS = "\t\t\t";

	private static final int CERTIFICATE_TYPES_LENGTH_BITS = 8;

	private static final int CERTIFICATE_TYPE_BITS = 8;

	private static final int SUPPORTED_SIGNATURE_LENGTH_BITS = 16;

	private static final int CERTIFICATE_AUTHORITIES_LENGTH_BITS = 16;

	private static final int CERTIFICATE_AUTHORITY_LENGTH_BITS = 16;

	private static final int SUPPORTED_SIGNATURE_BITS = 8;

	private static final int MAX_LENGTH_CERTIFICATE_AUTHORITIES = (1 << 16) - 1;

	// Members ////////////////////////////////////////////////////////

	private final List<ClientCertificateType> certificateTypes = new ArrayList<>();
	private final List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new ArrayList<>();
	private final List<X500Principal> certificateAuthorities = new ArrayList<>();
	private int certificateAuthoritiesEncodedLength = 0;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Initializes an empty certificate request.
	 * 
	 * @param peerAddress the IP address and port of the peer this
	 *           message has been received from or should be sent to
	 */
	public CertificateRequest(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	/**
	 * 
	 * @param certificateTypes
	 *            the list of allowed client certificate types.
	 * @param supportedSignatureAlgorithms
	 *            the list of supported signature and hash algorithms.
	 * @param certificateAuthorities
	 *            the list of allowed certificate authorities.
	 * @param peerAddress the IP address and port of the peer this
	 *            message has been received from or should be sent to
	 */
	public CertificateRequest(
			List<ClientCertificateType> certificateTypes,
			List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms,
			List<X500Principal> certificateAuthorities,
			InetSocketAddress peerAddress) {
		super(peerAddress);
		if (certificateTypes != null) {
			this.certificateTypes.addAll(certificateTypes);
		}
		if (supportedSignatureAlgorithms != null) {
			this.supportedSignatureAlgorithms.addAll(supportedSignatureAlgorithms);
		}
		if (certificateAuthorities != null) {
			addCerticiateAuthorities(certificateAuthorities);
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE_REQUEST;
	}

	@Override
	public int getMessageLength() {
		// fixed: certificate type length field (1 byte) + supported signature
		// algorithms length field (2 bytes) + certificate authorities length
		// field (2 bytes) = 5 bytes

		return 1 + // certificate type length field
			certificateTypes.size() + // each type is represented by 1 byte
			2 + // supported signature algorithms length field
			(supportedSignatureAlgorithms.size() * 2) + // each algorithm is represented by 2 bytes
			2 + // certificate authorities length field
			certificateAuthoritiesEncodedLength;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		if (!certificateTypes.isEmpty()) {
			sb.append("\t\tClient certificate type:").append(System.lineSeparator());
			for (ClientCertificateType type : certificateTypes) {
				sb.append(THREE_TABS).append(type).append(System.lineSeparator());
			}
		}
		if (!supportedSignatureAlgorithms.isEmpty()) {
			sb.append("\t\tSignature and hash algorithm:").append(System.lineSeparator());
			for (SignatureAndHashAlgorithm algo : supportedSignatureAlgorithms) {
				sb.append(THREE_TABS).append(algo.jcaName()).append(System.lineSeparator());
			}
		}
		if (!certificateAuthorities.isEmpty()) {
			sb.append("\t\tCertificate authorities:").append(System.lineSeparator());
			for (X500Principal subject : certificateAuthorities) {
				sb.append(THREE_TABS).append(subject.getName()).append(System.lineSeparator());
			}
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(certificateTypes.size(), CERTIFICATE_TYPES_LENGTH_BITS);
		for (ClientCertificateType certificateType : certificateTypes) {
			writer.write(certificateType.getCode(), CERTIFICATE_TYPE_BITS);
		}

		writer.write(supportedSignatureAlgorithms.size() * 2, SUPPORTED_SIGNATURE_LENGTH_BITS);
		for (SignatureAndHashAlgorithm signatureAndHashAlgorithm : supportedSignatureAlgorithms) {
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), SUPPORTED_SIGNATURE_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SUPPORTED_SIGNATURE_BITS);
		}

		writer.write(certificateAuthoritiesEncodedLength, CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		for (X500Principal distinguishedName : certificateAuthorities) {
			// since a distinguished name has variable length, we need to write length field for each name as well, has influence on total length!
			byte[] encoded = distinguishedName.getEncoded();
			writer.write(encoded.length, CERTIFICATE_AUTHORITY_LENGTH_BITS);
			writer.writeBytes(encoded);
		}

		return writer.toByteArray();
	}

	/**
	 * Parses a certificate request message from its binary encoding.
	 * 
	 * @param byteArray The encoded message.
	 * @param peerAddress The origin address of the message.
	 * @return The parsed instance.
	 */
	public static HandshakeMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		DatagramReader reader = new DatagramReader(byteArray);

		int length = reader.read(CERTIFICATE_TYPES_LENGTH_BITS);
		List<ClientCertificateType> certificateTypes = new ArrayList<>();
		for (int i = 0; i < length; i++) {
			int code = reader.read(CERTIFICATE_TYPE_BITS);
			certificateTypes.add(ClientCertificateType.getTypeByCode(code));
		}

		length = reader.read(SUPPORTED_SIGNATURE_LENGTH_BITS);
		List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new ArrayList<>();
		for (int i = 0; i < length; i += 2) {
			int codeHash = reader.read(SUPPORTED_SIGNATURE_BITS);
			int codeSignature = reader.read(SUPPORTED_SIGNATURE_BITS);
			supportedSignatureAlgorithms.add(new SignatureAndHashAlgorithm(HashAlgorithm.getAlgorithmByCode(codeHash),
					SignatureAlgorithm.getAlgorithmByCode(codeSignature)));
		}

		length = reader.read(CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		List<X500Principal> certificateAuthorities = new ArrayList<>();
		while (length > 0) {
			int nameLength = reader.read(CERTIFICATE_AUTHORITY_LENGTH_BITS);
			byte[] name = reader.readBytes(nameLength);
			certificateAuthorities.add(new X500Principal(name));

			length -= 2 + name.length;
		}

		return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities, peerAddress);
	}

	// Enums //////////////////////////////////////////////////////////

	/**
	 * Certificate types that the client may offer. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246</a> for
	 * details.
	 */
	public static enum ClientCertificateType {

		RSA_SIGN(1, "RSA", true),
		DSS_SIGN(2, "DSA", true),
		RSA_FIXED_DH(3, "DH", false),
		DSS_FIXED_DH(4, "DH", false),
		RSA_EPHEMERAL_DH_RESERVED(5, "DH", false),
		DSS_EPHEMERAL_DH_RESERVED(6, "DH", false),
		FORTEZZA_DMS_RESERVED(20, "UNKNOWN", false),
		ECDSA_SIGN(64, "EC", true),
		RSA_FIXED_ECDH(65, "DH", false),
		ECDSA_FIXED_ECDH(66, "DH", false);

		private final int code;
		private final String jcaAlgorithm;
		private final boolean requiresSigningCapability;

		private ClientCertificateType(int code, String algorithm, boolean requiresSigningCapability) {
			this.code = code;
			this.jcaAlgorithm = algorithm;
			this.requiresSigningCapability = requiresSigningCapability;
		}

		/**
		 * Gets this certificate type's binary code as defined by
		 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246, Section 7.4.4</a>.
		 * 
		 * @return The code.
		 */
		public int getCode() {
			return code;
		}

		/**
		 * Gets the JCA standard key algorithm name this certificate type is compatible with.
		 * 
		 * @return The algorithm name.
		 */
		public String getJcaAlgorithm() {
			return jcaAlgorithm;
		}

		/**
		 * Indicates whether this certificate type requires the key to allow being used for signing.
		 * 
		 * @return {@code true} if signing capability is required.
		 */
		public boolean requiresSigningCapability() {
			return requiresSigningCapability;
		}

		/**
		 * Checks if this certificate type is compatible with a given JCA standard key algorithm.
		 * 
		 * @param algorithm The key algorithm.
		 * @return {@code true} if this certificate type is compatible with the given key algorithm.
		 */
		public boolean isCompatibleWithKeyAlgorithm(String algorithm) {
			return this.jcaAlgorithm.equals(algorithm);
		}

		/**
		 * Gets a certificate type by its code as defined by
		 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246, Section 7.4.4</a>.
		 * 
		 * @param code The code.
		 * @return The certificate type or {@code null} if the given code is not defined.
		 */
		public static ClientCertificateType getTypeByCode(int code) {
			for (ClientCertificateType type : values()) {
				if (type.code == code) {
					return type;
				}
			}
			return null;
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	/**
	 * Adds a certificate type to the list of supported certificate types.
	 * 
	 * @param certificateType The type to add.
	 */
	public void addCertificateType(ClientCertificateType certificateType) {
		certificateTypes.add(certificateType);
	}

	/**
	 * Appends a signature algorithm to the end of the list of supported algorithms.
	 * <p>
	 * The algorithm's position in list indicates <em>least preference</em> to the
	 * recipient (the DTLS client) of the message.
	 * 
	 * @param signatureAndHashAlgorithm The algorithm to add.
	 */
	public void addSignatureAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
		supportedSignatureAlgorithms.add(signatureAndHashAlgorithm);
	}

	/**
	 * Adds a distinguished name to the list of acceptable certificate authorities.
	 * 
	 * @param authority The authority to add.
	 * @return {@code false} if the authority could not be added because it would exceed the
	 *         maximum encoded length allowed for the certificate request message's
	 *         certificate authorities vector (2^16 - 1 bytes).
	 * @throws NullPointerException if the authority is {@code null}.
	 */
	public boolean addCertificateAuthority(X500Principal authority) {

		if (authority == null) {
			throw new NullPointerException("authority must not be null");
		}
		int encodedAuthorityLength = 2 + // length field
				authority.getEncoded().length;
		if (certificateAuthoritiesEncodedLength + encodedAuthorityLength <= MAX_LENGTH_CERTIFICATE_AUTHORITIES) {
			certificateAuthorities.add(authority);
			certificateAuthoritiesEncodedLength += encodedAuthorityLength;
			return true;
		} else {
			return false;
		}
	}

	private boolean addCerticiateAuthorities(List<X500Principal> authorities) {

		int authoritiesAdded = 0;
		for (X500Principal authority : authorities) {
			if (!addCertificateAuthority(authority)) {
				LOGGER.log(Level.FINE, "could add only {0} of {1} certificate authorities, max length exceeded",
						new Object[]{ authoritiesAdded, authorities.size() });
				return false;
			} else {
				authoritiesAdded++;
			}
		}
		return true;
	}

	/**
	 * Takes a list of trusted certificates, extracts the subject principal and
	 * adds the DER-encoded distinguished name to the certificate authorities.
	 * 
	 * @param trustedCas The trusted certificates to add.
	 * @return {@code false} if not all certificates could not be added because it would exceed the
	 *         maximum encoded length allowed for the certificate request message's
	 *         certificate authorities vector (2^16 - 1 bytes).
	 */
	public boolean addCertificateAuthorities(X509Certificate[] trustedCas) {

		if (trustedCas != null) {
			int authoritiesAdded = 0;
			for (X509Certificate certificate : trustedCas) {
				if (!addCertificateAuthority(certificate.getSubjectX500Principal())) {
					LOGGER.log(Level.FINE, "could add only {0} of {1} certificate authorities, max length exceeded",
							new Object[]{ authoritiesAdded, trustedCas.length });
					return false;
				} else {
					authoritiesAdded++;
				}
			}
		}
		return true;
	}

	/**
	 * Gets the certificate types that the client may offer.
	 *
	 * @return The certificate types (never {@code null}.
	 */
	public List<ClientCertificateType> getCertificateTypes() {
		return Collections.unmodifiableList(certificateTypes);
	}

	/**
	 * Checks if a given key is compatible with the client certificate types supported by the server.
	 * 
	 * @param key The key.
	 * @return {@code true} if the key is compatible.
	 */
	boolean isSupportedKeyType(PublicKey key) {
		for (ClientCertificateType type : certificateTypes) {
			if (type.isCompatibleWithKeyAlgorithm(key.getAlgorithm())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if a given certificate contains a public key that is compatible with the server's requirements.
	 * 
	 * @param cert The certificate.
	 * @return {@code true} if the certificate's public key is compatible.
	 */
	boolean isSupportedKeyType(X509Certificate cert) {

		for (ClientCertificateType type : certificateTypes) {
			boolean isCompatibleType = type.isCompatibleWithKeyAlgorithm(cert.getPublicKey().getAlgorithm());
			boolean meetsSigningRequirements = !type.requiresSigningCapability() ||
					(type.requiresSigningCapability() && cert.getKeyUsage() != null && cert.getKeyUsage()[0]);
			LOGGER.log(Level.FINER, "type: {0}, isCompatibleWithKeyAlgorithm[{1}]: {2}, meetsSigningRequirements: {3}", 
					new Object[]{ type, cert.getPublicKey().getAlgorithm(), isCompatibleType, meetsSigningRequirements});
			if (isCompatibleType && meetsSigningRequirements) {
				return true;
			}
		}
		LOGGER.log(Level.FINER, "certificate [{0}] is not of any supported type", cert);
		return false;
	}

	/**
	 * Gets the signature algorithm that is compatible with a given public key.
	 * 
	 * @param key The public key.
	 * @return A signature algorithm that can be used with the given key or {@code null} if
	 *         the given key is not compatible with any of the supported certificate types
	 *         or any of the supported signature algorithms.
	 */
	public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(PublicKey key) {

		if (isSupportedKeyType(key)) {
			return getSupportedSignatureAlgorithm(key);
		} else {
			return null;
		}
	}

	/**
	 * Gets a signature algorithm that is compatible with a given certificate chain.
	 * 
	 * @param chain The certificate chain.
	 * @return A signature algorithm that can be used with the key contained in the given chain's
	 *         end entity certificate or {@code null} if any of the chain's certificates is not
	 *         compatible with any of the supported certificate types or any of the supported signature algorithms.
	 */
	public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(X509Certificate[] chain) {

		if (isSignedWithSupportedAlgorithm(chain)) {
			if (isSupportedKeyType(chain[0])) {
				return getSupportedSignatureAlgorithm(chain[0].getPublicKey());
			}
		}
		return null;
	}

	/**
	 * Checks if all of a given certificate chain's certificates have been signed using one of the
	 * algorithms supported by the server.
	 * 
	 * @param cert The certificate chain to test.
	 * @return {@code true} if all certificates have been signed using one of the supported algorithms.
	 */
	boolean isSignedWithSupportedAlgorithm(X509Certificate[] chain) {

		for (X509Certificate cert : chain) {
			boolean certSignatureAlgorithmSupported = false;
			for (SignatureAndHashAlgorithm supportedAlgorithm : supportedSignatureAlgorithms) {
				if (supportedAlgorithm.jcaName().equals(cert.getSigAlgName())) {
					certSignatureAlgorithmSupported = true;
					break;
				}
			}
			if (!certSignatureAlgorithmSupported) {
				LOGGER.log(Level.FINE, "certificate chain is NOT signed with supported algorithm(s)");
				return false;
			}
		}
		LOGGER.log(Level.FINE, "certificate chain is signed with supported algorithm(s)");
		return true;
	}

	SignatureAndHashAlgorithm getSupportedSignatureAlgorithm(PublicKey key) {

		for (SignatureAndHashAlgorithm supportedAlgorithm : supportedSignatureAlgorithms) {
			try {
				Signature sign = Signature.getInstance(supportedAlgorithm.jcaName());
				sign.initVerify(key);
				return supportedAlgorithm;
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				// nothing to do
			}
		}
		return null;
	}

	/**
	 * Truncates a given certificate chain at the first certificate encountered having
	 * a subject listed in <em>certificateAuthorities</em>.
	 * 
	 * @param chain The original certificate chain.
	 * @return A (potentially) truncated copy of the original chain.
	 * @throws NullPointerException if the given chain is {@code null}.
	 */
	public X509Certificate[] removeTrustedCertificates(X509Certificate[] chain) {

		if (chain == null) {
			throw new NullPointerException("certificate chain must not be null");
		} else if (chain.length > 1) {
			int i = 1;
			for ( ; i < chain.length; i++) {
				if (certificateAuthorities.contains(chain[i].getSubjectX500Principal())) {
					break;
				}
			}
			return Arrays.copyOf(chain, i);
		} else {
			return Arrays.copyOf(chain, chain.length);
		}
	}

	/**
	 * Gets the signature algorithms that the server is able to verify.
	 * 
	 * @return The supported algorithms in order of preference (never {@code null}).
	 */
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms() {
		return Collections.unmodifiableList(supportedSignatureAlgorithms);
	}

	/**
	 * Gets the distinguished names of certificate authorities trusted by the server.
	 * <p>
	 * The names are provided in DER-encoded ASN.1 format. The list is between 0 and
	 * 2<sup>16</sup>-1 bytes long, while one distinguished name can range from
	 * 1 to 2<sup>16</sup>-1 bytes length. Therefore, the length in the
	 * serialization must be handled carefully.
	 * 
	 * @return The distinguished names (never {@code null}).
	 */
	public List<X500Principal> getCertificateAuthorities() {
		return Collections.unmodifiableList(certificateAuthorities);
	}
}
