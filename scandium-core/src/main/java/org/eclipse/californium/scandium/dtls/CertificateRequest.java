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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix matching of signature algorithm
 *                                                    for android using characters with
 *                                                    different case "SHA256WITHECDSA"
 *                                                    instead of "SHA256withECDSA"
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A non-anonymous server can optionally request a certificate from the client,
 * if appropriate for the selected cipher suite.
 * <p>
 * This message, if sent, will immediately follow the {@link ServerKeyExchange} message (if it is sent;
 * otherwise, this message follows the server's {@link CertificateMessage} message).
 * 
 * @see <a href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246, 7.4.4. Certificate Request</a>
 */
@NoPublicAPI
public final class CertificateRequest extends HandshakeMessage {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateRequest.class);

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
		if (!supportedSignatureAlgorithms.isEmpty()) {
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
			sb.append("\t\tClient certificate type:").append(StringUtil.lineSeparator());
			for (ClientCertificateType type : certificateTypes) {
				sb.append(THREE_TABS).append(type).append(StringUtil.lineSeparator());
			}
		}
		if (!supportedSignatureAlgorithms.isEmpty()) {
			sb.append("\t\tSignature and hash algorithm:").append(StringUtil.lineSeparator());
			for (SignatureAndHashAlgorithm algo : supportedSignatureAlgorithms) {
				sb.append(THREE_TABS).append(algo).append(StringUtil.lineSeparator());
			}
		}
		if (!certificateAuthorities.isEmpty()) {
			sb.append("\t\tCertificate authorities:").append(StringUtil.lineSeparator());
			for (X500Principal subject : certificateAuthorities) {
				sb.append(THREE_TABS).append(subject.getName()).append(StringUtil.lineSeparator());
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
	 * @param reader reader for the binary encoding of the message.
	 * @param peerAddress The origin address of the message.
	 * @return The parsed instance.
	 */
	public static HandshakeMessage fromReader(DatagramReader reader, InetSocketAddress peerAddress) {

		List<ClientCertificateType> certificateTypes = new ArrayList<>();
		int length = reader.read(CERTIFICATE_TYPES_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(length);
		while (rangeReader.bytesAvailable()) {
			int code = rangeReader.read(CERTIFICATE_TYPE_BITS);
			certificateTypes.add(ClientCertificateType.getTypeByCode(code));
		}

		List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new ArrayList<>();
		length = reader.read(SUPPORTED_SIGNATURE_LENGTH_BITS);
		rangeReader = reader.createRangeReader(length);
		while (rangeReader.bytesAvailable()) {
			int codeHash = rangeReader.read(SUPPORTED_SIGNATURE_BITS);
			int codeSignature = rangeReader.read(SUPPORTED_SIGNATURE_BITS);
			supportedSignatureAlgorithms.add(new SignatureAndHashAlgorithm(codeHash, codeSignature));
		}

		List<X500Principal> certificateAuthorities = new ArrayList<>();
		length = reader.read(CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		rangeReader = reader.createRangeReader(length);
		while (rangeReader.bytesAvailable()) {
			int nameLength = rangeReader.read(CERTIFICATE_AUTHORITY_LENGTH_BITS);
			byte[] name = rangeReader.readBytes(nameLength);
			certificateAuthorities.add(new X500Principal(name));
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

		RSA_SIGN(1, true, "RSA"),
		DSS_SIGN(2, true, "DSA"),
		RSA_FIXED_DH(3, false, "DH"),
		DSS_FIXED_DH(4, false, "DH"),
		RSA_EPHEMERAL_DH_RESERVED(5, false, "DH"),
		DSS_EPHEMERAL_DH_RESERVED(6, false, "DH"),
		FORTEZZA_DMS_RESERVED(20, false, "UNKNOWN"),
		ECDSA_SIGN(64, true, "EC", Asn1DerDecoder.EDDSA, Asn1DerDecoder.OID_ED25519, Asn1DerDecoder.OID_ED448),
		RSA_FIXED_ECDH(65, false, "DH"),
		ECDSA_FIXED_ECDH(66, false, "DH");

		private final int code;
		private final boolean requiresSigningCapability;
		private final String[] jcaAlgorithms;

		private ClientCertificateType(int code, boolean requiresSigningCapability, String... algorithms) {
			this.code = code;
			this.jcaAlgorithms = algorithms;
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
		 * @deprecated
		 */
		@Deprecated
		public String getJcaAlgorithm() {
			return jcaAlgorithms[0];
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
			algorithm = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, algorithm);
			for (String jcaAlgorithm : jcaAlgorithms) {
				if (jcaAlgorithm.equalsIgnoreCase(algorithm)) {
					return true;
				}
			}
			return false;
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
	 * Appends a signature and hash algorithm to the end of the list of supported algorithms.
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
	 * Appends a list of signature and hash algorithms to the end of the list of supported algorithms.
	 * <p>
	 * The algorithm's position in list indicates <em>least preference</em> to the
	 * recipient (the DTLS client) of the message.
	 * 
	 * @param signatureAndHashAlgorithms The algorithms to add.
	 * @since 2.3
	 */
	public void addSignatureAlgorithms(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		supportedSignatureAlgorithms.addAll(signatureAndHashAlgorithms);
	}

	/**
	 * Select received supported signature and hash algorithms by the supported
	 * signature and hash algorithms of this peer.
	 * 
	 * Ensure, that the other peer doesn't sent unsupported signature and hash
	 * algorithms by this peer.
	 * 
	 * @param supportedSignatureAndHashAlgorithms supported signature and hash
	 *            algorithms of this peer
	 */
	public void selectSignatureAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
		List<SignatureAndHashAlgorithm> removes = new ArrayList<>();
		for (SignatureAndHashAlgorithm algo :this.supportedSignatureAlgorithms) {
			if (!supportedSignatureAndHashAlgorithms.contains(algo)) {
				removes.add(algo);
			}
		}
		this.supportedSignatureAlgorithms.removeAll(removes);
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
		int encodedAuthorityLength = (CERTIFICATE_AUTHORITY_LENGTH_BITS / Byte.SIZE) + // length field
				authority.getEncoded().length;
		if (certificateAuthoritiesEncodedLength + encodedAuthorityLength <= MAX_LENGTH_CERTIFICATE_AUTHORITIES) {
			certificateAuthorities.add(authority);
			certificateAuthoritiesEncodedLength += encodedAuthorityLength;
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Takes a list of trusted certificates, extracts the subject principal and
	 * adds the DER-encoded distinguished name to the certificate authorities.
	 * 
	 * @param authorities authorities of the trusted certificates to add.
	 * @return {@code false} if not all certificates could not be added because it would exceed the
	 *         maximum encoded length allowed for the certificate request message's
	 *         certificate authorities vector (2^16 - 1 bytes).
	 */
	public boolean addCerticiateAuthorities(List<X500Principal> authorities) {

		int authoritiesAdded = 0;
		for (X500Principal authority : authorities) {
			if (!addCertificateAuthority(authority)) {
				LOGGER.debug("could add only {} of {} certificate authorities, max length exceeded", authoritiesAdded,
						authorities.size());
				return false;
			} else {
				authoritiesAdded++;
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
		String algorithm = key.getAlgorithm();
		for (ClientCertificateType type : certificateTypes) {
			if (type.isCompatibleWithKeyAlgorithm(algorithm)) {
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
		Boolean clientUsage = null;
		String algorithm = cert.getPublicKey().getAlgorithm();
		for (ClientCertificateType type : certificateTypes) {
			if (!type.isCompatibleWithKeyAlgorithm(algorithm)) {
				LOGGER.debug("type: {}, is not compatible with KeyAlgorithm[{}]", type, algorithm);
				continue;
			}
			// KeyUsage is an optional extension which may be used to restrict
			// the way the key can be used.
			// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
			// If this extension is used, we check if digitalsignature usage is
			// present.
			// (For more details see :
			// https://github.com/eclipse/californium/issues/748)
			if (type.requiresSigningCapability()) {
				if (clientUsage == null) {
					clientUsage = CertPathUtil.canBeUsedForAuthentication(cert, true);
				}
				if (!clientUsage) {
					LOGGER.error("type: {}, requires missing signing capability!", type);
					continue;
				}
			}
			LOGGER.debug("type: {}, is compatible with KeyAlgorithm[{}] and meets signing requirements", type,
					algorithm);
			return true;
		}
		LOGGER.debug("certificate [{}] with public key {} is not of any supported type", cert, algorithm);
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
			return SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(supportedSignatureAlgorithms, key);
		} 
		return null;
	}

	/**
	 * Gets a signature algorithm that is compatible with a given certificate chain.
	 * 
	 * @param chain The certificate chain.
	 * @return A signature algorithm that can be used with the key contained in the given chain's
	 *         end entity certificate or {@code null} if any of the chain's certificates is not
	 *         compatible with any of the supported certificate types or any of the supported signature algorithms.
	 */
	public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(List<X509Certificate> chain) {
		X509Certificate certificate = chain.get(0);
		if (isSupportedKeyType(certificate)) {
			SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm
					.getSupportedSignatureAlgorithm(supportedSignatureAlgorithms, certificate.getPublicKey());
			if (signatureAndHashAlgorithm != null
					&& SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(supportedSignatureAlgorithms, chain)) {
				return signatureAndHashAlgorithm;
			}
		}
		return null;
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
