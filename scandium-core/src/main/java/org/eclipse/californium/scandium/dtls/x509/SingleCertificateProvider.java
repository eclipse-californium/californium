/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Certificate identity provider based on a single certificate identity.
 * 
 * @since 3.0
 */
public class SingleCertificateProvider implements CertificateProvider, ConfigurationHelperSetup {

	private static final Logger LOGGER = LoggerFactory.getLogger(SingleCertificateProvider.class);

	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private final List<X509Certificate> certificateChain;

	/**
	 * List of supported certificate type in order of preference.
	 */
	private final List<CertificateType> supportedCertificateTypes;
	private final List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms;

	/**
	 * Enable key pair verification.
	 * 
	 * Check, if key-pair is supported by JCE and the public key is
	 * corresponding to the private key. Enabled by default.
	 * 
	 * @since 3.6
	 */
	private boolean verifyKeyPair = true;

	/**
	 * Create static certificate provider from private key and certificate
	 * chain.
	 * 
	 * The private key and the public key of the node's certificate (at index 0)
	 * must be a key pair, otherwise signing and verification will fail.
	 * 
	 * @param privateKey private key of identity.
	 * @param certificateChain certificate chain for identity. The public key of
	 *            the node's certificate (at index 0) must be related with the
	 *            private key.
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the private key or certificate chain is
	 *             {@code null}
	 * @throws IllegalArgumentException if the certificate chain is empty
	 */
	public SingleCertificateProvider(PrivateKey privateKey, Certificate[] certificateChain,
			CertificateType... supportedCertificateTypes) {
		this(privateKey, certificateChain, asList(supportedCertificateTypes));
	}

	/**
	 * Create static certificate provider from private key and certificate
	 * chain.
	 * 
	 * The private key and the public key of the node's certificate (at index 0)
	 * must be a key pair, otherwise signing and verification will fail.
	 * 
	 * @param privateKey private key of identity.
	 * @param certificateChain certificate chain for identity. The public key of
	 *            the node's certificate (at index 0) must be related with the
	 *            private key.
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the private key or certificate chain is
	 *             {@code null}
	 * @throws IllegalArgumentException if the certificate chain is empty or the
	 *             list of certificate types contains unsupported types.
	 */
	public SingleCertificateProvider(PrivateKey privateKey, Certificate[] certificateChain,
			List<CertificateType> supportedCertificateTypes) {
		if (privateKey == null) {
			throw new NullPointerException("Private key must not be null!");
		}
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		if (certificateChain.length == 0) {
			throw new IllegalArgumentException("Certificate chain must not be empty!");
		}
		if (supportedCertificateTypes != null) {
			if (supportedCertificateTypes.isEmpty()) {
				throw new IllegalArgumentException("Certificate types must not be empty!");
			}
			for (CertificateType certificateType : supportedCertificateTypes) {
				if (!certificateType.isSupported()) {
					throw new IllegalArgumentException("Certificate type " + certificateType + " is not supported!");
				}
			}
		}

		this.privateKey = privateKey;
		this.publicKey = certificateChain[0].getPublicKey();
		if (supportedCertificateTypes == null) {
			// default x509
			supportedCertificateTypes = new ArrayList<>(1);
			supportedCertificateTypes.add(CertificateType.X_509);
		}
		if (supportedCertificateTypes.contains(CertificateType.X_509)) {
			this.certificateChain = Arrays.asList(SslContextUtil.asX509Certificates(certificateChain));
		} else {
			this.certificateChain = null;
		}
		this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
		this.supportedCertificateKeyAlgorithms = Collections
				.unmodifiableList(Arrays.asList(CertificateKeyAlgorithm.getAlgorithm(publicKey)));
	}

	/**
	 * Create static certificate provider from private and public key.
	 * 
	 * Only supports {@link CertificateType#RAW_PUBLIC_KEY}.
	 * 
	 * The private key and the public key must be a key pair, otherwise signing
	 * and verification will fail.
	 * 
	 * @param privateKey private key of identity
	 * @param publicKey public key of identity
	 * @throws NullPointerException if the private or public key is {@code null}
	 */
	public SingleCertificateProvider(PrivateKey privateKey, PublicKey publicKey) {
		if (privateKey == null) {
			throw new NullPointerException("Private key must not be null!");
		}
		if (publicKey == null) {
			throw new NullPointerException("Public key must not be null!");
		}

		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.certificateChain = null;
		this.supportedCertificateTypes = Collections.unmodifiableList(Arrays.asList(CertificateType.RAW_PUBLIC_KEY));
		this.supportedCertificateKeyAlgorithms = Collections
				.unmodifiableList(Arrays.asList(CertificateKeyAlgorithm.getAlgorithm(publicKey)));
	}

	/**
	 * Enable/Disable the verification of the provided key pair.
	 * 
	 * A key pair consists of a private and related public key. Signing and
	 * verification will fail, if the keys are not related.
	 * 
	 * @param enable {@code true} to enable verification (default),
	 *            {@code false}, to disable it.
	 * @return this certificate provider for command chaining.
	 * @since 3.6
	 */
	public SingleCertificateProvider setVerifyKeyPair(boolean enable) {
		this.verifyKeyPair = enable;
		return this;
	}

	@Override
	public void setupConfigurationHelper(CertificateConfigurationHelper helper) {
		if (helper == null) {
			throw new NullPointerException("Certificate configuration helper must not be null!");
		}
		try {
			helper.verifyKeyPair(privateKey, publicKey);
		} catch (IllegalArgumentException ex) {
			if (verifyKeyPair) {
				throw new IllegalStateException(ex.getMessage());
			} else {
				LOGGER.warn("Mismatching key-pair, causing failure when used!", ex);
			}
		}
		if (certificateChain != null) {
			helper.addConfigurationDefaultsFor(this.certificateChain);
		} else {
			helper.addConfigurationDefaultsFor(this.publicKey);
		}
	}

	@Override
	public List<CertificateKeyAlgorithm> getSupportedCertificateKeyAlgorithms() {
		return supportedCertificateKeyAlgorithms;
	}

	@Override
	public List<CertificateType> getSupportedCertificateTypes() {
		return supportedCertificateTypes;
	}

	@Override
	public CertificateIdentityResult requestCertificateIdentity(ConnectionId cid, boolean client,
			List<X500Principal> issuers, ServerNames serverNames,
			List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, List<SupportedGroup> curves) {
		if (certificateChain != null) {
			return new CertificateIdentityResult(cid, privateKey, certificateChain, null);
		} else {
			return new CertificateIdentityResult(cid, privateKey, publicKey, null);
		}
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}

	private static List<CertificateType> asList(CertificateType[] types) {
		if (types == null || types.length == 0) {
			return null;
		}
		return Arrays.asList(types);
	}
}
