/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 *                    derived from ECDHECryptography
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;

/**
 * Cipher suites and parameters.
 * 
 * @since 2.3
 */
public class CipherSuiteParameters {

	/**
	 * General negotiation mismatch.
	 * 
	 * @since 3.0
	 */
	public static enum GeneralMismatch {

		/**
		 * Peers have no common cipher suite.
		 */
		CIPHER_SUITE("Peers have no common cipher suite."),
		/**
		 * Peers have no common ec-point format.
		 */
		EC_FORMAT("Peers have no common ec-point format."),
		/**
		 * Peers have no common ec-point format.
		 */
		EC_GROUPS("Peers have no common ec-groups.");

		private final String message;

		private GeneralMismatch(String message) {
			this.message = message;
		}

		public String getMessage() {
			return message;
		}
	}

	/**
	 * Certificate based negotiation mismatch.
	 * 
	 * @since 3.0
	 */
	public static enum CertificateBasedMismatch {

		/**
		 * Peers have no common server certificate type.
		 */
		SERVER_CERT_TYPE("Peers have no common server certificate type."),
		/**
		 * Peers have no common client certificate type.
		 */
		CLIENT_CERT_TYPE("Peers have no common client certificate type."),
		/**
		 * Peers have no common signature and hash algorithm.
		 */
		SIGNATURE_ALGORITHMS("Peers have no common signature and hash algorithm."),
		/**
		 * The peer's node certificate uses no common ec-group.
		 */
		CERTIFICATE_EC_GROUPS("The peer's node certificate uses no common ec-group."),
		/**
		 * The peer's node certificate uses no common signature and hash
		 * algorithm.
		 */
		CERTIFICATE_SIGNATURE_ALGORITHMS("The peer's node certificate uses no common signature and hash algorithm."),
		/**
		 * The peer's certificate-chain uses no common signature and hash
		 * algorithm.
		 */
		CERTIFICATE_PATH_SIGNATURE_ALGORITHMS(
				"The peer's certificate-chain uses no common signature and hash algorithm.");

		private final String message;

		private CertificateBasedMismatch(String message) {
			this.message = message;
		}

		public String getMessage() {
			return message;
		}
	}

	/**
	 * General mismatch.
	 * 
	 * {@link GeneralMismatch#CIPHER_SUITE}, {@link GeneralMismatch#EC_GROUPS}, or
	 * {@link GeneralMismatch#EC_FORMAT}.
	 * 
	 * @since 3.0
	 */
	private GeneralMismatch generalMismatch;
	/**
	 * Certificate based mismatch.
	 * 
	 * @since 3.0
	 */
	private CertificateBasedMismatch certificateMismatch;

	private PublicKey publicKey;
	private List<X509Certificate> certificateChain;
	private CertificateAuthenticationMode clientAuthenticationMode;

	private List<CipherSuite> cipherSuites;
	private List<CertificateType> serverCertTypes;
	private List<CertificateType> clientCertTypes;
	private List<SupportedGroup> supportedGroups;
	private List<SignatureAndHashAlgorithm> signatures;
	private ECPointFormat format;

	private CipherSuite selectedCipherSuite;
	private CertificateType selectedServerCertificateType;
	private CertificateType selectedClientCertificateType;
	private SignatureAndHashAlgorithm selectedSignature;
	private SupportedGroup selectedSupportedGroup;

	/**
	 * Create common cipher suites and parameters.
	 * 
	 * @param publicKey peer's public key. Maybe {@code null}.
	 * @param certificateChain peer's certificate chain. Maybe {@code null}.
	 * @param clientAuthenticationMode client authentication mode.
	 * @param cipherSuites list of common cipher suites.
	 * @param serverCertTypes list of common server certificate types.
	 * @param clientCertTypes list of common client certificate types.
	 * @param supportedGroups list of common supported groups (curves).
	 * @param signatures list of common signatures and algorithms.
	 * @param format common ec point format. Only
	 *            {@link ECPointFormat#UNCOMPRESSED} is supported.
	 */
	public CipherSuiteParameters(PublicKey publicKey, List<X509Certificate> certificateChain,
			CertificateAuthenticationMode clientAuthenticationMode, List<CipherSuite> cipherSuites,
			List<CertificateType> serverCertTypes, List<CertificateType> clientCertTypes,
			List<SupportedGroup> supportedGroups, List<SignatureAndHashAlgorithm> signatures, ECPointFormat format) {
		this.publicKey = publicKey;
		this.certificateChain = certificateChain;
		this.clientAuthenticationMode = clientAuthenticationMode;
		this.cipherSuites = cipherSuites;
		this.serverCertTypes = serverCertTypes;
		this.clientCertTypes = clientCertTypes;
		this.supportedGroups = supportedGroups;
		this.signatures = signatures;
		this.format = format;
	}

	/**
	 * Create common cipher suites and parameters.
	 * 
	 * @param publicKey peer's public key. Maybe {@code null}.
	 * @param certificateChain peer's certificate chain. Maybe {@code null}.
	 * @param others other parameters
	 * @since 3.0
	 */
	public CipherSuiteParameters(PublicKey publicKey, List<X509Certificate> certificateChain,
			CipherSuiteParameters others) {
		this.publicKey = publicKey;
		this.certificateChain = certificateChain;
		this.clientAuthenticationMode = others.clientAuthenticationMode;
		this.cipherSuites = others.cipherSuites;
		this.serverCertTypes = others.serverCertTypes;
		this.clientCertTypes = others.clientCertTypes;
		this.supportedGroups = others.supportedGroups;
		this.signatures = others.signatures;
		this.format = others.format;
		this.selectedCipherSuite = others.selectedCipherSuite;
		this.selectedServerCertificateType = others.selectedServerCertificateType;
		this.selectedClientCertificateType = others.selectedClientCertificateType;
		this.selectedSupportedGroup = others.selectedSupportedGroup;
		this.selectedSignature = others.selectedSignature;
	}

	public List<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}

	public List<CertificateType> getServerCertTypes() {
		return serverCertTypes;
	}

	public List<CertificateType> getClientCertTypes() {
		return clientCertTypes;
	}

	public List<SupportedGroup> getSupportedGroups() {
		return supportedGroups;
	}

	public List<SignatureAndHashAlgorithm> getSignatures() {
		return signatures;
	}

	public ECPointFormat getFormat() {
		return format;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public List<X509Certificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Gets general mismatch.
	 * 
	 * @return general mismatch, or {@code null}.
	 * @since 3.0
	 */
	public GeneralMismatch getGeneralMismatch() {
		return generalMismatch;
	}

	/**
	 * Gets certificate based mismatch.
	 * 
	 * @return certificate based mismatch, or {@code null}.
	 * @since 3.0
	 */
	public CertificateBasedMismatch getCertificateMismatch() {
		return certificateMismatch;
	}

	public CertificateAuthenticationMode getClientAuthenticationMode() {
		return clientAuthenticationMode;
	}

	/**
	 * Get selected cipher suite.
	 * 
	 * @return selected cipher suite
	 */
	public CipherSuite getSelectedCipherSuite() {
		return selectedCipherSuite;
	}

	/**
	 * Get selected server certificate type
	 * 
	 * @return selected server certificate type, or {@code null}, if not
	 *         available.
	 */
	public CertificateType getSelectedServerCertificateType() {
		return selectedServerCertificateType;
	}

	/**
	 * Get selected client certificate type
	 * 
	 * @return selected client certificate type, or {@code null}, if not
	 *         available.
	 */
	public CertificateType getSelectedClientCertificateType() {
		return selectedClientCertificateType;
	}

	/**
	 * Get selected supported group for ECDHE.
	 * 
	 * @return supported group, or {@code null}, if not available.
	 */
	public SupportedGroup getSelectedSupportedGroup() {
		return selectedSupportedGroup;
	}

	/**
	 * Get selected signature and hash algorithm for signing.
	 * 
	 * @return selected signature and hash algorithm, or {@code null}, if not
	 *         available.
	 */
	public SignatureAndHashAlgorithm getSelectedSignature() {
		return selectedSignature;
	}

	/**
	 * Sets general mismatch.
	 * 
	 * @param mismatch general mismatch
	 * @since 3.0
	 */
	public void setGeneralMismatch(GeneralMismatch mismatch) {
		generalMismatch = mismatch;
	}

	/**
	 * Sets certificate based mismatch.
	 * 
	 * Once set, this mismatch skips to test other certificate based cipher
	 * suites for this handshake.
	 * 
	 * @param mismatch certificate based mismatch
	 * @since 3.0
	 */
	public void setCertificateMismatch(CertificateBasedMismatch mismatch) {
		certificateMismatch = mismatch;
	}

	/**
	 * Select cipher suite.
	 * 
	 * @param cipherSuite selected cipher suite
	 * @throws NullPointerException if the cipher suite is {@code null}
	 * @throws IllegalArgumentException if the cipher suite is not in the list
	 *             of common cipher suites
	 * @since 3.0 (added NullPointerException and IllegalArgumentException)
	 */
	public void select(CipherSuite cipherSuite) {
		if (cipherSuite == null) {
			throw new NullPointerException("Cipher suite must not be null!");
		}
		if (!cipherSuites.contains(cipherSuite)) {
			throw new IllegalArgumentException(cipherSuite + " is no common cipher suite!");
		}
		selectedCipherSuite = cipherSuite;
	}

	/**
	 * Select server certificate type.
	 * 
	 * @param type selected server certificate type. Maybe {@code null}, if not
	 *            available.
	 * @throws IllegalArgumentException if the certificate type is not in the
	 *             list of common server certificate types
	 * @since 3.0 (added IllegalArgumentException)
	 */
	public void selectServerCertificateType(CertificateType type) {
		if (type != null && !serverCertTypes.contains(type)) {
			throw new IllegalArgumentException(type + " server certificate type is no common certificate type.");
		}
		selectedServerCertificateType = type;
	}

	/**
	 * Select client certificate type.
	 * 
	 * @param type selected client certificate type. Maybe {@code null}, if not
	 *            available or client certificate not requested.
	 * @throws IllegalArgumentException if the certificate type is not in the
	 *             list of common client certificate types
	 * @since 3.0 (added IllegalArgumentException)
	 */
	public void selectClientCertificateType(CertificateType type) {
		if (type != null && !clientCertTypes.contains(type)) {
			throw new IllegalArgumentException(type + " client certificate type is no common certificate type.");
		}
		selectedClientCertificateType = type;
	}

	/**
	 * Select supported group / curve.
	 * 
	 * @param group selected supported group. Maybe {@code null}, if not
	 *            available.
	 * @throws IllegalArgumentException if the supported group is not in the
	 *             list of common supported group
	 * @since 3.0
	 */
	public void selectSupportedGroup(SupportedGroup group) {
		if (group != null && !supportedGroups.contains(group)) {
			throw new IllegalArgumentException(group + " is no common group/curve.");
		}
		this.selectedSupportedGroup = group;
	}

	/**
	 * Select signature and hash algorithm.
	 * 
	 * @param signature selected signature and hash algorithm. Maybe
	 *            {@code null}, if not available.
	 * @throws IllegalArgumentException if the signature and hash algorithm is
	 *             not in the list of common signature and hash algorithms
	 * @since 3.0 (added IllegalArgumentException)
	 */
	public void selectSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signature) {
		if (signature != null && !signatures.contains(signature)) {
			throw new IllegalArgumentException(signature + " is no common signature and hash algorithm.");
		}
		this.selectedSignature = signature;
	}

	/**
	 * Gets mismatch summary.
	 * 
	 * @return mismatch summary, or {@code null}, if not available.
	 * @since 3.0
	 */
	public String getMismatchSummary() {
		if (generalMismatch != null) {
			return generalMismatch.getMessage();
		} else if (certificateMismatch != null) {
			return certificateMismatch.getMessage();
		}
		return null;
	}

	/**
	 * Get details description of mismatch.
	 * 
	 * @return mismatch details description, or {@code null}, if not available.
	 * @since 3.0
	 */
	public String getMismatchDescription() {
		String summary = getMismatchSummary();
		if (summary != null) {
			StringBuilder builder = new StringBuilder(summary);
			builder.append(StringUtil.lineSeparator());
			builder.append("\tcipher suites: ");
			for (CipherSuite cipherSuite : cipherSuites) {
				builder.append(cipherSuite.name()).append(",");
			}
			builder.setLength(builder.length() - 1);
			if (certificateMismatch == CertificateBasedMismatch.CERTIFICATE_EC_GROUPS) {
				builder.append(StringUtil.lineSeparator()).append("\t\tec-groups: ");
				for (SupportedGroup group : supportedGroups) {
					builder.append(group.name()).append(",");
				}
				builder.setLength(builder.length() - 1);
			} else if (certificateMismatch == CertificateBasedMismatch.CERTIFICATE_SIGNATURE_ALGORITHMS
					|| certificateMismatch == CertificateBasedMismatch.CERTIFICATE_PATH_SIGNATURE_ALGORITHMS) {
				builder.append(StringUtil.lineSeparator()).append("\t\tsignatures: ");
				for (SignatureAndHashAlgorithm sign : signatures) {
					builder.append(sign.getJcaName()).append(",");
				}
				builder.setLength(builder.length() - 1);
			}
			return builder.toString();
		}
		return summary;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("cipher suites: ");
		for (CipherSuite cipherSuite : cipherSuites) {
			if (selectedCipherSuite == cipherSuite) {
				builder.append("#");
			}
			builder.append(cipherSuite.name()).append(",");
		}
		builder.setLength(builder.length() - 1);
		builder.append(StringUtil.lineSeparator());
		if (certificateChain != null && !certificateChain.isEmpty()) {
			builder.append("x509-DN: [").append(certificateChain.get(0).getSubjectX500Principal().getName());
			builder.append("]").append(StringUtil.lineSeparator());
		}
		if (publicKey != null) {
			if (clientAuthenticationMode == CertificateAuthenticationMode.NEEDED) {
				builder.append("client certificate required");
			} else if (clientAuthenticationMode == CertificateAuthenticationMode.WANTED) {
				builder.append("client certificate wanted");
			} else {
				builder.append("no client certificate");
			}
			builder.append(StringUtil.lineSeparator());
		}
		builder.append("server certificate types: ");
		for (CertificateType cerType : serverCertTypes) {
			if (selectedServerCertificateType == cerType) {
				builder.append("#");
			}
			builder.append(cerType.name()).append(",");
		}
		builder.setLength(builder.length() - 1);
		builder.append(StringUtil.lineSeparator());
		builder.append("client certificate types: ");
		for (CertificateType cerType : clientCertTypes) {
			if (selectedClientCertificateType == cerType) {
				builder.append("#");
			}
			builder.append(cerType.name()).append(",");
		}
		builder.setLength(builder.length() - 1);
		builder.append(StringUtil.lineSeparator());
		builder.append("ec-groups: ");
		for (SupportedGroup group : supportedGroups) {
			if (selectedSupportedGroup == group) {
				builder.append("#");
			}
			builder.append(group.name()).append(",");
		}
		builder.setLength(builder.length() - 1);
		builder.append(StringUtil.lineSeparator());
		builder.append("signatures: ");
		for (SignatureAndHashAlgorithm sign : signatures) {
			if (selectedSignature == sign) {
				builder.append("#");
			}
			builder.append(sign.getJcaName()).append(",");
		}
		builder.setLength(builder.length() - 1);
		builder.append(StringUtil.lineSeparator());

		return builder.toString();
	}
}
