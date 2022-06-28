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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ListUtils;

/**
 * Certificate configuration helper.
 * 
 * {@link DtlsConnectorConfig} generally tries, to find the best default values
 * for the not provided configuration values using the provided ones. Estimating
 * the proper signature and hash algorithms and the supported curves for
 * ECDSA/ECDHE is implemented here.
 * 
 * For all public keys passed to
 * {@link #addConfigurationDefaultsFor(PublicKey)}, the supported curve, and a
 * signature and hash algorithm is added to the default parameters.
 *
 * For all x509 certificate chains passed to
 * {@link #addConfigurationDefaultsFor(List)}, the public key of the head
 * certificate (node's certificate) is passed to
 * {@link #addConfigurationDefaultsFor(PublicKey)}. Also all used signature and
 * hash algorithms in the certificate chain are added to the defaults
 * parameters. And all used curves of public keys in the chain are added to the
 * default parameters as well.
 * 
 * For all trusted x509 certificates passed to
 * {@link #addConfigurationDefaultsForTrusts(PublicKey)}, the supported curve
 * and a signature and hash algorithms are added to the default parameters.
 * 
 * For all trusted x509 certificates passed to
 * {@link #addConfigurationDefaultsForTrusts(X509Certificate[])}, the supported
 * curve and a signature and hash algorithms of all public keys are added to the
 * default parameters.
 * 
 * @since 3.0
 */
public class CertificateConfigurationHelper {

	/**
	 * List of provided public keys.
	 * 
	 * @see #addConfigurationDefaultsFor(PublicKey)
	 * @see #addConfigurationDefaultsFor(List)
	 */
	private final List<PublicKey> keys = new ArrayList<>();
	/**
	 * List of provided certificate chains.
	 * 
	 * @see #addConfigurationDefaultsFor(List)
	 */
	private final List<List<X509Certificate>> chains = new ArrayList<>();
	/**
	 * List of provided trusted certificates.
	 * 
	 * @see #addConfigurationDefaultsForTrusts(X509Certificate[])
	 */
	private final List<X509Certificate> trusts = new ArrayList<>();
	/**
	 * Indicates, that one of the node's certificates provided with
	 * {@link #addConfigurationDefaultsFor(List)} supports the usage for
	 * clients.
	 */
	private boolean clientUsage;
	/**
	 * Indicates, that one of the node's certificates provided with
	 * {@link #addConfigurationDefaultsFor(List)} supports the usage for
	 * servers.
	 */
	private boolean serverUsage;
	/**
	 * List of supported signature and hash algorithms.
	 */
	private final List<SignatureAndHashAlgorithm> defaultSignatureAndHashAlgorithms = new ArrayList<>();
	/**
	 * List of supported groups.
	 */
	private final List<SupportedGroup> defaultSupportedGroups = new ArrayList<>();

	/**
	 * Add parameters for the provided public key.
	 * 
	 * The supported curve and a signature and hash algorithm is added to the
	 * default parameters.
	 * 
	 * @param key the public key to add
	 * @throws IllegalArgumentException if the public key is not supported
	 */
	public void addConfigurationDefaultsFor(PublicKey key) {
		String algorithm = key.getAlgorithm();
		if (!JceProviderUtil.isSupported(algorithm)) {
			throw new IllegalArgumentException("Public key algorithm " + algorithm + " is not supported!");
		}
		if (Asn1DerDecoder.isEcBased(algorithm)) {
			SupportedGroup group = SupportedGroup.fromPublicKey(key);
			if (group == null) {
				throw new IllegalArgumentException("Public key's ec-group must be supported!");
			}
			ListUtils.addIfAbsent(defaultSupportedGroups, group);
		}
		SignatureAndHashAlgorithm.ensureSignatureAlgorithm(defaultSignatureAndHashAlgorithms, key);
		ListUtils.addIfAbsent(keys, key);
	}

	/**
	 * Add parameters for the provided certificate chain.
	 * 
	 * The public key of the head certificate (node's certificate) is passed to
	 * {@link #addConfigurationDefaultsFor(PublicKey)}. Also all used signature
	 * and hash algorithms in the certificate chain are added to the defaults
	 * parameters. And all used curves of public keys in the chain are added to
	 * the default parameters as well.
	 * 
	 * @param certificateChain the certificate chain to add
	 * @throws IllegalArgumentException if a public key or signature and hash
	 *             algorithm is not supported
	 */
	public void addConfigurationDefaultsFor(List<X509Certificate> certificateChain) {
		if (!certificateChain.isEmpty()) {
			X509Certificate certificate = certificateChain.get(0);
			addConfigurationDefaultsFor(certificate.getPublicKey());
			if (CertPathUtil.canBeUsedForAuthentication(certificate, false)) {
				serverUsage = true;
			}
			if (CertPathUtil.canBeUsedForAuthentication(certificate, true)) {
				clientUsage = true;
			}
			ListUtils.addIfAbsent(defaultSignatureAndHashAlgorithms,
					SignatureAndHashAlgorithm.getSignatureAlgorithms(certificateChain));
			for (int index = 1; index < certificateChain.size(); ++index) {
				certificate = certificateChain.get(index);
				PublicKey certPublicKey = certificate.getPublicKey();
				if (Asn1DerDecoder.isEcBased(certPublicKey.getAlgorithm())) {
					SupportedGroup group = SupportedGroup.fromPublicKey(certPublicKey);
					if (group == null) {
						throw new IllegalArgumentException("CA's public key ec-group must be supported!");
					}
					ListUtils.addIfAbsent(defaultSupportedGroups, group);
				}
			}
			chains.add(certificateChain);
		}
	}

	/**
	 * Add parameters for the provided trusted certificates.
	 * 
	 * The supported curve and a signature and hash algorithms of all public
	 * keys are added to the default parameters.
	 * 
	 * @param trusts trusted certificates
	 */
	public void addConfigurationDefaultsForTrusts(X509Certificate[] trusts) {
		if (trusts != null) {
			for (X509Certificate certificate : trusts) {
				addConfigurationDefaultsForTrusts(certificate.getPublicKey());
				this.trusts.add(certificate);
			}
		}
	}

	/**
	 * Add parameters for the provided trusted public key.
	 * 
	 * The supported curve and a signature and hash algorithms are added to the
	 * default parameters.
	 * 
	 * @param publicKey trusted public key
	 */
	public void addConfigurationDefaultsForTrusts(PublicKey publicKey) {
		if (publicKey != null) {
			SignatureAndHashAlgorithm.ensureSignatureAlgorithm(defaultSignatureAndHashAlgorithms, publicKey);
			if (Asn1DerDecoder.isEcBased(publicKey.getAlgorithm())) {
				SupportedGroup group = SupportedGroup.fromPublicKey(publicKey);
				if (group == null) {
					throw new IllegalArgumentException("CA's public key ec-group must be supported!");
				}
				ListUtils.addIfAbsent(defaultSupportedGroups, group);
			}
		}
	}

	/**
	 * Gets list of signatures and hash algorithms for the provided public keys,
	 * certificate chains and trusted certificates.
	 * 
	 * @return list of signatures and hash algorithms
	 */
	public List<SignatureAndHashAlgorithm> getDefaultSignatureAndHashAlgorithms() {
		return defaultSignatureAndHashAlgorithms;
	}

	/**
	 * Gets list of supported groups for the provided public keys, certificate
	 * chains and trusted certificates.
	 * 
	 * @return list of supported groups
	 */
	public List<SupportedGroup> getDefaultSupportedGroups() {
		return defaultSupportedGroups;
	}

	/**
	 * Verify the provided algorithms match the added public key, certificate
	 * chains and trusted certificates.
	 * 
	 * @param algorithms list of configured signature and hash algorithms
	 */
	public void verifySignatureAndHashAlgorithmsConfiguration(List<SignatureAndHashAlgorithm> algorithms) {
		for (PublicKey key : keys) {
			if (SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(algorithms, key) == null) {
				throw new IllegalStateException("supported signature and hash algorithms " + algorithms
						+ " doesn't match the public " + key.getAlgorithm() + " key!");
			}
		}
		for (List<X509Certificate> chain : chains) {
			if (!SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(algorithms, chain)) {
				throw new IllegalStateException("supported signature and hash algorithms " + algorithms
						+ " doesn't match the certificate chain!");
			}
		}
		for (X509Certificate trust : trusts) {
			PublicKey publicKey = trust.getPublicKey();
			if (SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(algorithms, publicKey) == null) {
				throw new IllegalStateException("supported signature and hash algorithms " + algorithms
						+ " doesn't match the trust's public key " + publicKey.getAlgorithm() + "!");
			}
		}
	}

	/**
	 * Verify the provided groups match the added public key and trusted
	 * certificates.
	 * 
	 * @param groups list of configured supported groups
	 */
	public void verifySupportedGroupsConfiguration(List<SupportedGroup> groups) {
		for (SupportedGroup group : defaultSupportedGroups) {
			if (!group.isUsable()) {
				throw new IllegalStateException("public key used with unsupported group (curve) " + group.name() + "!");
			}
			if (!groups.contains(group)) {
				throw new IllegalStateException(
						"public key used with not configured group (curve) " + group.name() + "!");
			}
		}
	}

	/**
	 * Checks, if one of the node certificates of the added chains can be used
	 * in a specific role.
	 * 
	 * @param client {@code true}, for client role, {@code false}, for server
	 *            role.
	 * @return {@code true}, if role is supported, {@code false}, if not.
	 */
	public boolean canBeUsedForAuthentication(boolean client) {
		return chains.isEmpty() || (client ? clientUsage : serverUsage);
	}

	/**
	 * Verify the provided key pair.
	 * 
	 * @param privateKey private key
	 * @param publicKey public key
	 * @throws IllegalArgumentException if key pair is not valid or not
	 *             supported by the JCE
	 * @since 3.6
	 */
	public void verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) {
		String algorithm = publicKey.getAlgorithm();
		for (SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
			if (signatureAlgorithm.isSupported(algorithm)) {
				SignatureAndHashAlgorithm signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(
						HashAlgorithm.INTRINSIC, signatureAlgorithm);
				if (!signatureAlgorithm.isIntrinsic()) {
					for (HashAlgorithm hashAlgorithm : HashAlgorithm.values()) {
						if (HashAlgorithm.INTRINSIC != hashAlgorithm && HashAlgorithm.NONE != hashAlgorithm) {
							signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(hashAlgorithm,
									signatureAlgorithm);
							if (signatureAndHashAlgorithm.isSupported()) {
								break;
							}
						}
					}
				}
				if (signatureAndHashAlgorithm.isSupported(publicKey)) {
					ThreadLocalSignature threadLocalSignature = signatureAndHashAlgorithm.getThreadLocalSignature();
					Signature signature = threadLocalSignature.current();
					byte[] data = "Just a signature test".getBytes();
					try {
						signature.initSign(privateKey);
						signature.update(data);
						byte[] sign = signature.sign();

						signature.initVerify(publicKey);
						signature.update(data);
						if (signature.verify(sign)) {
							// key pair verified
							return;
						}
						throw new IllegalArgumentException(publicKey.getAlgorithm() + " key pair is not valid!");
					} catch (GeneralSecurityException e) {
					}
					break;
				}
			}
		}
		throw new IllegalArgumentException(algorithm + " is not supported by the JCE!");
	}
}
