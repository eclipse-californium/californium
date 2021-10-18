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

/**
 * Certificate identity provider based on a single certificate identity.
 * 
 * @since 3.0
 */
public class SingleCertificateProvider implements CertificateProvider, ConfigurationHelperSetup {

	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private final List<X509Certificate> certificateChain;

	/**
	 * List of supported certificate type in order of preference.
	 */
	private final List<CertificateType> supportedCertificateTypes;
	private final List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms;

	/**
	 * Create static certificate provider from private key and certificate
	 * chain.
	 * 
	 * @param privateKey private key of identity.
	 * @param chain certificate chain for identity.
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the private key or certificate chain is
	 *             {@code null}
	 * @throws IllegalArgumentException if the certificate chain is empty
	 */
	public SingleCertificateProvider(PrivateKey privateKey, Certificate[] chain,
			CertificateType... supportedCertificateTypes) {
		this(privateKey, chain, asList(supportedCertificateTypes));
	}

	/**
	 * Create static certificate provider from private key and certificate
	 * chain.
	 * 
	 * @param privateKey private key of identity.
	 * @param certificateChain certificate chain for identity.
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
	 * @param privateKey private key of identity
	 * @param publicKey public key of identity
	 * @throws NullPointerException if the private or public key is {@code null}
	 * @throws IllegalArgumentException if the public key doesn't use a
	 *             supported group
	 * @see SupportedGroup#fromPublicKey(PublicKey)
	 */
	public SingleCertificateProvider(PrivateKey privateKey, PublicKey publicKey) {
		if (privateKey == null) {
			throw new NullPointerException("Private key must not be null!");
		}
		if (publicKey == null) {
			throw new NullPointerException("Public key must not be null!");
		}
		SupportedGroup group = SupportedGroup.fromPublicKey(publicKey);
		if (group == null) {
			throw new IllegalArgumentException("Public key's ec-group must be supported!");
		}

		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.certificateChain = null;
		this.supportedCertificateTypes = Collections.unmodifiableList(Arrays.asList(CertificateType.RAW_PUBLIC_KEY));
		this.supportedCertificateKeyAlgorithms = Collections
				.unmodifiableList(Arrays.asList(CertificateKeyAlgorithm.getAlgorithm(publicKey)));
	}

	@Override
	public void setupConfigurationHelper(CertificateConfigurationHelper helper) {
		if (helper == null) {
			throw new NullPointerException("Certificate configuration helper must not be null!");
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
			List<X500Principal> issuers, ServerNames serverNames, List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
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
