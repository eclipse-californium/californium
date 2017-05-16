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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;
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

	// DTLS-specific constants ////////////////////////////////////////

	/* See http://tools.ietf.org/html/rfc5246#section-7.4.4 for message format. */

	private static final String THREE_TABS = "\t\t\t";

	private static final int CERTIFICATE_TYPES_LENGTH_BITS = 8;

	private static final int CERTIFICATE_TYPE_BITS = 8;

	private static final int SUPPORTED_SIGNATURE_LENGTH_BITS = 16;

	private static final int CERTIFICATE_AUTHORITIES_LENGTH_BITS = 16;

	private static final int CERTIFICATE_AUTHORITY_LENGTH_BITS = 16;

	private static final int SUPPORTED_SIGNATURE_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	private final List<ClientCertificateType> certificateTypes = new ArrayList<>();
	private final List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new ArrayList<>();
	private final List<DistinguishedName> certificateAuthorities = new ArrayList<>();

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
			List<DistinguishedName> certificateAuthorities,
			InetSocketAddress peerAddress) {
		super(peerAddress);
		if (certificateTypes != null) {
			this.certificateTypes.addAll(certificateTypes);
		}
		if (supportedSignatureAlgorithms != null) {
			this.supportedSignatureAlgorithms.addAll(supportedSignatureAlgorithms);
		}
		if (certificateAuthorities != null) {
			this.certificateAuthorities.addAll(certificateAuthorities);
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

		return 5 + certificateTypes.size() + (supportedSignatureAlgorithms.size() * 2) + getCertificateAuthoritiesLength();
	}
	
	private int getCertificateAuthoritiesLength() {
		// each distinguished name has a variable length, therefore we need an
		// additional 2 bytes length field for each name
		int certificateAuthLength = 0;
		for (DistinguishedName distinguishedName : certificateAuthorities) {
			certificateAuthLength += distinguishedName.getName().length + 2;
		}

		return certificateAuthLength;
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
				sb.append(THREE_TABS).append(algo).append(System.lineSeparator());
			}
		}
		if (!certificateAuthorities.isEmpty()) {
			sb.append("\t\tCertificate authorities:").append(System.lineSeparator());
			for (DistinguishedName name : certificateAuthorities) {
				X500Principal principal = new X500Principal(name.getName());
				sb.append(THREE_TABS).append(principal.getName()).append(System.lineSeparator());
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
		
		writer.write(getCertificateAuthoritiesLength(), CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		for (DistinguishedName distinguishedName : certificateAuthorities) {
			// since a distinguished name has variable length, we need to write length field for each name as well, has influence on total length!
			writer.write(distinguishedName.getName().length, CERTIFICATE_AUTHORITY_LENGTH_BITS);
			writer.writeBytes(distinguishedName.getName());
		}

		return writer.toByteArray();
	}

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
		List<DistinguishedName> certificateAuthorities = new ArrayList<>();
		while (length > 0) {
			int nameLength = reader.read(CERTIFICATE_AUTHORITY_LENGTH_BITS);
			byte[] name = reader.readBytes(nameLength);
			certificateAuthorities.add(new DistinguishedName(name));

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

	/**
	 * A distinguished name is between 1 and 2<sup>16</sup>-1 bytes long. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246 -
	 * Certificate Request</a> for details.
	 */
	public static class DistinguishedName {
		private final byte[] name;

		public DistinguishedName(byte[] name) {
			this.name = Arrays.copyOf(name, name.length);
		}

		public byte[] getName() {
			return name;
		}

		/**
		 * Gets this distinguished name as a principal so that it can be compared to
		 * other certificates' issuer.
		 * 
		 * @return The principal.
		 */
		public X500Principal asPrincipal() {
			return new X500Principal(name);
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	public void addCertificateType(ClientCertificateType certificateType) {
		certificateTypes.add(certificateType);
	}

	public void addSignatureAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
		supportedSignatureAlgorithms.add(signatureAndHashAlgorithm);
	}

	public void addCertificateAuthority(DistinguishedName authority) {
		// TODO make sure that the max size (2^16 - 1 bytes) is not exceeded
		certificateAuthorities.add(authority);
	}

	/**
	 * Takes a list of trusted certificates, extracts the subject principal and
	 * adds the DER-encoded distinguished name to the certificate authorities.
	 * 
	 * @param trustedCas
	 *            trusted certificates.
	 */
	public void addCertificateAuthorities(X509Certificate[] trustedCas) {
		if (trustedCas != null){
			for (X509Certificate certificate : trustedCas) {
				byte[] ca = certificate.getSubjectX500Principal().getEncoded();
				addCertificateAuthority(new DistinguishedName(ca));
			}
		}
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
	public List<DistinguishedName> getCertificateAuthorities() {
		return Collections.unmodifiableList(certificateAuthorities);
	}
}
