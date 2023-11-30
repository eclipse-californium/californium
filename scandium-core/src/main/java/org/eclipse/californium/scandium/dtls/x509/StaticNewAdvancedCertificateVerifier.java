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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateRequest;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * New advanced certificate verifier based on collections of trusted x509
 * certificates and RPKs.
 * 
 * @since 2.5
 */
public class StaticNewAdvancedCertificateVerifier implements NewAdvancedCertificateVerifier, ConfigurationHelperSetup {

	private static final X509Certificate[] X509_TRUST_ALL = new X509Certificate[0];
	private static final RawPublicKeyIdentity[] RPK_TRUST_ALL = new RawPublicKeyIdentity[0];

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

	/**
	 * Trusted x509 certificates.
	 */
	private final X509Certificate[] trustedCertificates;

	/**
	 * RPK certificate verifier to delegate verification.
	 */
	private final Set<RawPublicKeyIdentity> trustedRPKs;

	/**
	 * List of supported certificate type in order of preference.
	 */
	private final List<CertificateType> supportedCertificateTypes;

	/**
	 * Use empty list of accepted issuers instead of a list based on the
	 * {@link #trustedCertificates}.
	 * 
	 * @since 3.3
	 */
	private final boolean useEmptyAcceptedIssuers;

	/**
	 * Create delegating certificate verifier for x509 and RPK.
	 * 
	 * @param trustedCertificates trusted x509 certificates. {@code null} not
	 *            support x.509, empty, to trust all.
	 * @param trustedRPKs trusted RPK identities. {@code null} not support RPK,
	 *            empty, to trust all.
	 * @param supportedCertificateTypes list of supported certificate type in
	 *            order of preference. {@code null} to create a list based on
	 *            the provided trusts with Raw Public key before x509.
	 * @throws IllegalArgumentException if both, trustedCertificates and
	 *             trustedRPKs, are {@code null}, the supportedCertificateTypes
	 *             is empty, or the trusts for an provided certificate type are
	 *             {@code null}.
	 */
	public StaticNewAdvancedCertificateVerifier(X509Certificate[] trustedCertificates,
			RawPublicKeyIdentity[] trustedRPKs, List<CertificateType> supportedCertificateTypes) {
		this(trustedCertificates, trustedRPKs, supportedCertificateTypes, false);
	}

	/**
	 * Create delegating certificate verifier for x509 and RPK.
	 * 
	 * @param trustedCertificates trusted x509 certificates. {@code null} not
	 *            support x.509, empty, to trust all.
	 * @param trustedRPKs trusted RPK identities. {@code null} not support RPK,
	 *            empty, to trust all.
	 * @param supportedCertificateTypes list of supported certificate type in
	 *            order of preference. {@code null} to create a list based on
	 *            the provided trusts with Raw Public key before x509.
	 * @param useEmptyAcceptedIssuers {@code true} to enable to use a empty list
	 *            of accepted issuers instead of a list based on the provided
	 *            certificates.
	 * @throws IllegalArgumentException if both, trustedCertificates and
	 *             trustedRPKs, are {@code null}, the supportedCertificateTypes
	 *             is empty, or the trusts for an provided certificate type are
	 *             {@code null}.
	 * @since 3.3
	 */
	public StaticNewAdvancedCertificateVerifier(X509Certificate[] trustedCertificates,
			RawPublicKeyIdentity[] trustedRPKs, List<CertificateType> supportedCertificateTypes,
			boolean useEmptyAcceptedIssuers) {
		if (trustedCertificates == null && trustedRPKs == null) {
			throw new IllegalArgumentException("no trusts provided!");
		}
		if (supportedCertificateTypes == null) {
			supportedCertificateTypes = new ArrayList<>(2);
			if (trustedRPKs != null) {
				supportedCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			}
			if (trustedCertificates != null) {
				supportedCertificateTypes.add(CertificateType.X_509);
			}
		} else if (supportedCertificateTypes.isEmpty()) {
			throw new IllegalArgumentException("list of supported certificate types must not be empty!");
		} else {
			if (supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY) && trustedRPKs == null) {
				throw new IllegalArgumentException("RPK support requires RPK trusts!");
			}
			if (supportedCertificateTypes.contains(CertificateType.X_509) && trustedCertificates == null) {
				throw new IllegalArgumentException("x509support requires x509 trusts!");
			}
		}
		this.trustedCertificates = trustedCertificates == null ? null
				: Arrays.copyOf(trustedCertificates, trustedCertificates.length);
		this.trustedRPKs = trustedRPKs == null ? null : new HashSet<>(Arrays.asList(trustedRPKs));
		this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
		this.useEmptyAcceptedIssuers = useEmptyAcceptedIssuers;
	}

	@Override
	public void setupConfigurationHelper(CertificateConfigurationHelper helper) {
		helper.addConfigurationDefaultsForTrusts(trustedCertificates);
		if (trustedRPKs != null) {
			for (RawPublicKeyIdentity identity : trustedRPKs) {
				helper.addConfigurationDefaultsForTrusts(identity.getKey());
			}
		}
	}

	@Override
	public List<CertificateType> getSupportedCertificateTypes() {
		return supportedCertificateTypes;
	}

	@Override
	public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverNames,
			InetSocketAddress remotePeer, boolean clientUsage, boolean verifySubject, boolean truncateCertificatePath,
			CertificateMessage message) {
		LOGGER.debug("Verify for SNI: {}, IP: {}", serverNames, StringUtil.toLog(remotePeer));
		try {
			CertPath certChain = message.getCertificateChain();
			if (certChain == null) {
				if (trustedRPKs == null) {
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE);
					throw new HandshakeException("RPK verification not enabled!", alert);
				}
				PublicKey publicKey = message.getPublicKey();
				if (!trustedRPKs.isEmpty()) {
					RawPublicKeyIdentity rpk = new RawPublicKeyIdentity(publicKey);
					if (!trustedRPKs.contains(rpk)) {
						LOGGER.debug("Certificate validation failed: Raw public key is not trusted");
						AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
						throw new HandshakeException("Raw public key is not trusted!", alert);
					}
				}
				return new CertificateVerificationResult(cid, publicKey, null);
			} else {
				if (trustedCertificates == null) {
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE);
					throw new HandshakeException("x509 verification not enabled!", alert);
				}
				try {
					if (!message.isEmpty()) {
						Certificate certificate = certChain.getCertificates().get(0);
						if (certificate instanceof X509Certificate) {
							X509Certificate x509Certificate = (X509Certificate) certificate;
							if (!CertPathUtil.canBeUsedForAuthentication(x509Certificate, clientUsage)) {
								LOGGER.debug("Certificate validation failed: key usage doesn't match");
								AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
										AlertDescription.BAD_CERTIFICATE);
								throw new HandshakeException("Key Usage doesn't match!", alert);
							}
							if (verifySubject) {
								verifyCertificatesSubject(serverNames, remotePeer, x509Certificate);
							}
						}
						certChain = CertPathUtil.validateCertificatePathWithIssuer(truncateCertificatePath, certChain,
								trustedCertificates);
					}
					return new CertificateVerificationResult(cid, certChain, null);
				} catch (CertPathValidatorException e) {
					Throwable cause = e.getCause();
					if (cause instanceof CertificateExpiredException) {
						LOGGER.debug("Certificate expired: {}", cause.getMessage());
						AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.CERTIFICATE_EXPIRED);
						throw new HandshakeException("Certificate expired", alert);
					} else if (cause != null) {
						LOGGER.debug("Certificate validation failed: {}/{}", e.getMessage(), cause.getMessage());
					} else {
						LOGGER.debug("Certificate validation failed: {}", e.getMessage());
					}
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
					throw new HandshakeException("Certificate chain could not be validated", alert, e);
				} catch (GeneralSecurityException e) {
					if (LOGGER.isTraceEnabled()) {
						LOGGER.trace("Certificate validation failed", e);
					} else if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Certificate validation failed due to {}", e.getMessage());
					}
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
					throw new HandshakeException("Certificate chain could not be validated", alert, e);
				}
			}
		} catch (HandshakeException e) {
			LOGGER.debug("Certificate validation failed!", e);
			return new CertificateVerificationResult(cid, e, null);
		}
	}

	/**
	 * Verify the certificate's subject.
	 * 
	 * Considers both destination variants, server names and inet address and
	 * verifies that using the certificate's subject CN and subject alternative
	 * names.
	 * 
	 * @param serverNames server names
	 * @param peer remote peer
	 * @param certificate server's certificate
	 * @throws HandshakeException if the verification fails.
	 * @throws NullPointerException if the certificate or both identities, the
	 *             servernames and peer, is {@code null}.
	 * @since 3.0
	 */
	public void verifyCertificatesSubject(ServerNames serverNames, InetSocketAddress peer, X509Certificate certificate)
			throws HandshakeException {
		if (certificate == null) {
			throw new NullPointerException("Certficate must not be null!");
		}
		if (serverNames == null && peer == null) {
			// nothing to verify
			return;
		}
		String literalIp = null;
		String hostname = null;
		if (peer != null) {
			hostname = StringUtil.toHostString(peer);
			InetAddress destination = peer.getAddress();
			if (destination != null) {
				literalIp = destination.getHostAddress();
			}
		}
		if (serverNames != null) {
			ServerName serverName = serverNames.getServerName(ServerName.NameType.HOST_NAME);
			if (serverName != null) {
				hostname = serverName.getNameAsString();
			}
		}
		if (hostname != null && hostname.equals(literalIp)) {
			hostname = null;
		}
		if (hostname != null) {
			if (!CertPathUtil.matchDestination(certificate, hostname)) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOGGER.debug("Certificate {} validation failed: destination doesn't match", cn);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				throw new HandshakeException("Certificate " + cn + ": Destination '" + hostname + "' doesn't match!",
						alert);
			}
		} else {
			if (!CertPathUtil.matchLiteralIP(certificate, literalIp)) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOGGER.debug("Certificate {} validation failed: literal IP doesn't match", cn);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				throw new HandshakeException("Certificate " + cn + ": Literal IP " + literalIp + " doesn't match!",
						alert);
			}
		}
	}

	@Override
	public List<X500Principal> getAcceptedIssuers() {
		if (!useEmptyAcceptedIssuers && trustedCertificates != null) {
			return CertPathUtil.toSubjects(Arrays.asList(trustedCertificates));
		} else {
			return CertPathUtil.toSubjects(null);
		}
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}

	/**
	 * Get a builder.
	 * 
	 * @return builder.
	 */
	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		/**
		 * x509 certificate verifier to delegate verification.
		 */
		protected X509Certificate[] trustedCertificates;
		/**
		 * RPK certificate verifier to delegate verification.
		 */
		protected RawPublicKeyIdentity[] trustedRPKs;
		/**
		 * List of supported certificate type in order of preference.
		 */
		protected List<CertificateType> supportedCertificateTypes;

		/**
		 * Use empty list of accepted issuers instead of a list based on the
		 * {@link #trustedCertificates}.
		 * 
		 * @since 3.3
		 */
		protected boolean useEmptyAcceptedIssuers;

		/**
		 * Set trusted x509 certificates
		 * 
		 * @param trustedCertificates trusted x509 certificates. {@code null},
		 *            trust no one. If no trusted certificates are provided
		 *            (empty array), all valid x509 certificates will be trusted
		 *            (same as {@link #setTrustAllCertificates()}).
		 * @return this builder for chaining
		 * @throws IllegalArgumentException if trustedCertificates contains
		 *             duplicates
		 * @see SslContextUtil#ensureUniqueCertificates(X509Certificate[])
		 */
		public Builder setTrustedCertificates(Certificate... trustedCertificates) {
			if (trustedCertificates == null) {
				this.trustedCertificates = null;
			} else if (trustedCertificates.length == 0) {
				this.trustedCertificates = X509_TRUST_ALL;
			} else {
				X509Certificate[] certificates = SslContextUtil.asX509Certificates(trustedCertificates);
				SslContextUtil.ensureUniqueCertificates(certificates);
				this.trustedCertificates = certificates;
			}
			return this;
		}

		/**
		 * Set to trust all valid certificates.
		 * 
		 * @return this builder for chaining
		 */
		public Builder setTrustAllCertificates() {
			this.trustedCertificates = X509_TRUST_ALL;
			return this;

		}

		/**
		 * Set trusted RPK (Raw Public Key) identities.
		 * 
		 * @param trustedRPKs trusted RPK identities. {@code null}, trust no
		 *            one. If no trusted RPK identities are provided (empty
		 *            array), all RPK identities will be trusted (same as
		 *            {@link #setTrustAllRPKs()}).
		 * @return this builder for chaining
		 * @throws IllegalArgumentException if trustedRPKs contains duplicates
		 */
		public Builder setTrustedRPKs(RawPublicKeyIdentity... trustedRPKs) {
			// Search for duplicates
			Set<RawPublicKeyIdentity> set = new HashSet<>();
			for (RawPublicKeyIdentity identity : trustedRPKs) {
				if (!set.add(identity)) {
					throw new IllegalArgumentException(
							"Truststore contains raw public key certificates duplicates: " + identity.getName());
				}
			}
			this.trustedRPKs = trustedRPKs;
			return this;
		}

		/**
		 * Set to trust all RPK (Raw Public Key) identities.
		 * 
		 * @return this builder for chaining
		 */
		public Builder setTrustAllRPKs() {
			this.trustedRPKs = RPK_TRUST_ALL;
			return this;
		}

		/**
		 * Set list of supported certificate types in order of preference.
		 * 
		 * @param supportedCertificateTypes list of supported certificate types
		 * @return this builder for chaining
		 */
		public Builder setSupportedCertificateTypes(List<CertificateType> supportedCertificateTypes) {
			this.supportedCertificateTypes = supportedCertificateTypes;
			return this;
		}

		/**
		 * Set to use a empty accepted issuers list.
		 * 
		 * The list of accepted issuers is send to the client in the
		 * {@link CertificateRequest} in order to help the client to select a
		 * trusted client certificate. In some case, that list may get larger.
		 * If the client has a priori knowledge, which certificate is trusted,
		 * using an empty list may save traffic. One consequence of sending an
		 * empty list may be, that the client sends an untrusted certificate,
		 * which then may be rejected. With an accepted issuers, the client may
		 * chose to send a empty certificate chain instead.
		 * 
		 * @param useEmptyAcceptedIssuers {@code true}, to use an empty accepted
		 *            issuers list, {@code false}, to generate that list based
		 *            on the trusted x509 certificates.
		 * @return this builder for chaining
		 */
		public Builder setUseEmptyAcceptedIssuers(boolean useEmptyAcceptedIssuers) {
			this.useEmptyAcceptedIssuers = useEmptyAcceptedIssuers;
			return this;
		}

		/**
		 * Check, if any trust is available.
		 * 
		 * @return {@code true}, if trusts are available, {@code false}, if not.
		 */
		public boolean hasTrusts() {
			return trustedCertificates != null || trustedRPKs != null;
		}

		/**
		 * Build NewAdvancedCertificateVerifier.
		 * 
		 * @return NewAdvancedCertificateVerifier
		 */
		public NewAdvancedCertificateVerifier build() {
			return new StaticNewAdvancedCertificateVerifier(trustedCertificates, trustedRPKs, supportedCertificateTypes,
					useEmptyAcceptedIssuers);
		}
	}
}
