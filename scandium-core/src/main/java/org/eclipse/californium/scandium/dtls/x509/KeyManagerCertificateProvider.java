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

import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ListUtils;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Example certificate identity provider based on a {@link X509KeyManager}.
 * <p>
 * Selects the certificate based on the issuers and server name, if provided.
 * The provided signature and hash algorithms and the supported curves are also
 * considered. If more than one certificate fits, the provided signature and
 * hash algorithms are used the select the best fit.
 * </p>
 * May be used as template to implement a solution for more specific use-cases.
 * 
 * @since 3.0
 */
public class KeyManagerCertificateProvider implements CertificateProvider, ConfigurationHelperSetup {

	private static final Logger LOGGER = LoggerFactory.getLogger(KeyManagerCertificateProvider.class);
	private static AtomicInteger ID = new AtomicInteger();
	/**
	 * Special Bouncy Castle key types for server credentials.
	 */
	private static final Map<String, String> BC_SERVER_KEY_TYPES_MAP = new HashMap<>();

	static {
		BC_SERVER_KEY_TYPES_MAP.put(Asn1DerDecoder.EC, "ECDHE_ECDSA");
		BC_SERVER_KEY_TYPES_MAP.put(Asn1DerDecoder.RSA, "ECDHE_RSA");
	}

	/**
	 * Key types for credentials.
	 */
	private static final List<String> ALL_KEY_TYPES = Arrays.asList(Asn1DerDecoder.EC, Asn1DerDecoder.RSA,
			Asn1DerDecoder.EDDSA, Asn1DerDecoder.ED25519, Asn1DerDecoder.ED448);
	/**
	 * Default alias. May be {@code null}.
	 */
	private final String defaultAlias;
	/**
	 * Key manager.
	 */
	private final X509KeyManager keyManager;
	/**
	 * Instance ID for logging. 
	 */
	private final int id;
	/**
	 * List of supported certificate type in order of preference.
	 */
	private final List<CertificateType> supportedCertificateTypes;
	/**
	 * List of supported certificate key algorithms.
	 */
	private final List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms;

	/**
	 * Create certificate provider based on key manager.
	 * 
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes array of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public KeyManagerCertificateProvider(X509KeyManager keyManager, CertificateType... supportedCertificateTypes) {
		this(null, keyManager, asList(supportedCertificateTypes));
	}

	/**
	 * Create certificate provider based on key manager.
	 * 
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public KeyManagerCertificateProvider(X509KeyManager keyManager, List<CertificateType> supportedCertificateTypes) {
		this(null, keyManager, supportedCertificateTypes);
	}

	/**
	 * Create certificate provider based on key manager with default alias.
	 * 
	 * @param defaultAlias default alias. May be {@code null}.
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes array of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public KeyManagerCertificateProvider(String defaultAlias, X509KeyManager keyManager,
			CertificateType... supportedCertificateTypes) {
		this(defaultAlias, keyManager, asList(supportedCertificateTypes));
	}

	/**
	 * Create certificate provider based on key manager with default alias.
	 * 
	 * @param defaultAlias default alias. May be {@code null}.
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public KeyManagerCertificateProvider(String defaultAlias, X509KeyManager keyManager,
			List<CertificateType> supportedCertificateTypes) {
		if (keyManager == null) {
			throw new NullPointerException("KeyManager must not be null!");
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
		this.id = ID.incrementAndGet();
		this.defaultAlias = defaultAlias;
		this.keyManager = keyManager;
		if (supportedCertificateTypes == null) {
			// default x509
			supportedCertificateTypes = new ArrayList<>(1);
			supportedCertificateTypes.add(CertificateType.X_509);
		}
		this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
		List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms = new ArrayList<>();
		List<String> aliases = getAliases(false, ALL_KEY_TYPES, null);
		for (String alias : aliases) {
			setup(alias, supportedCertificateKeyAlgorithms);
		}
		aliases = getAliases(true, ALL_KEY_TYPES, null);
		for (String alias : aliases) {
			setup(alias, supportedCertificateKeyAlgorithms);
		}
		this.supportedCertificateKeyAlgorithms = Collections.unmodifiableList(supportedCertificateKeyAlgorithms);
	}

	private void setup(String alias, List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms) {
		X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
		if (certificateChain != null && certificateChain.length > 0) {
			PublicKey key = certificateChain[0].getPublicKey();
			CertificateKeyAlgorithm keyAlgorithm = CertificateKeyAlgorithm.getAlgorithm(key);
			ListUtils.addIfAbsent(supportedCertificateKeyAlgorithms, keyAlgorithm);
		}
	}

	@Override
	public void setupConfigurationHelper(CertificateConfigurationHelper helper) {
		if (helper == null) {
			throw new NullPointerException("Certificate configuration helper must not be null!");
		}
		List<String> aliases = getAliases(false, ALL_KEY_TYPES, null);
		for (String alias : aliases) {
			setupConfigurationHelperForAlias(helper, alias);
		}
		aliases = getAliases(true, ALL_KEY_TYPES, null);
		for (String alias : aliases) {
			setupConfigurationHelperForAlias(helper, alias);
		}
	}

	/**
	 * Setup {@link #supportedCertificateKeyAlgorithms} and the optional
	 * configuration helper using the credentials of the provided alias.
	 * 
	 * @param helper configuration helper. May be {@code null}.
	 * @param alias alias of the credentials.
	 */
	private void setupConfigurationHelperForAlias(CertificateConfigurationHelper helper, String alias) {
		X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
		if (certificateChain != null && certificateChain.length > 0) {
			if (supportedCertificateTypes.contains(CertificateType.X_509)) {
				helper.addConfigurationDefaultsFor(Arrays.asList(certificateChain));
			} else if (supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
				helper.addConfigurationDefaultsFor(certificateChain[0].getPublicKey());
			}
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
		String role = client ? "Client" : "Server";
		LOGGER.debug("[{}]: {} certificate for {}", id, role, serverNames == null ? "<n.a.>" : serverNames);
		if (issuers != null && !issuers.isEmpty()) {
			LOGGER.debug("[{}]: {} certificate issued by {}", id, role, issuers);
		}
		Principal[] principals = issuers == null ? null : issuers.toArray(new Principal[issuers.size()]);
		List<String> keyTypes = new ArrayList<>();
		if (certificateKeyAlgorithms != null) {
			for (CertificateKeyAlgorithm algorithm : certificateKeyAlgorithms) {
				if (algorithm != CertificateKeyAlgorithm.NONE) {
					ListUtils.addIfAbsent(keyTypes, algorithm.name());
				}
			}
		}
		if (signatureAndHashAlgorithms != null && !signatureAndHashAlgorithms.isEmpty()) {
			if (keyTypes.isEmpty()) {
				if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatureAndHashAlgorithms, Asn1DerDecoder.EC)) {
					ListUtils.addIfAbsent(keyTypes, Asn1DerDecoder.EC);
				}
				if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatureAndHashAlgorithms, Asn1DerDecoder.RSA)) {
					ListUtils.addIfAbsent(keyTypes, Asn1DerDecoder.RSA);
				}
				addEdDsaSupport(keyTypes, signatureAndHashAlgorithms);
			} else if (keyTypes.contains(Asn1DerDecoder.EC)) {
				addEdDsaSupport(keyTypes, signatureAndHashAlgorithms);
			}
		} else if (keyTypes.isEmpty()) {
			keyTypes.add(Asn1DerDecoder.EC);
		}

		LOGGER.debug("[{}]: {} certificate public key types {}", id, role, keyTypes);
		if (signatureAndHashAlgorithms != null && !signatureAndHashAlgorithms.isEmpty()) {
			LOGGER.debug("[{}]: {} certificate signed with {}", id, role, signatureAndHashAlgorithms);
		}
		if (curves != null && !curves.isEmpty()) {
			LOGGER.debug("[{}]: {} certificate using {}", id, role, curves);
		}

		List<String> aliases = getAliases(client, keyTypes, principals);
		if (!aliases.isEmpty()) {
			List<String> matchingServerNames = new ArrayList<>();
			List<String> matchingSignatures = new ArrayList<>();
			List<String> matchingCurves = new ArrayList<>();
			// after issuers, check the servernames
			int index = 1;
			for (String alias : aliases) {
				LOGGER.debug("[{}]: Apply select {} - {} of {}", id, alias, index, aliases.size());
				X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
				List<X509Certificate> chain = Arrays.asList(certificateChain);
				if (serverNames != null && matchServerNames(serverNames, certificateChain[0])) {
					matchingServerNames.add(alias);
				}
				if (signatureAndHashAlgorithms != null
						&& matchSignatureAndHashAlgorithms(signatureAndHashAlgorithms, chain)) {
					matchingSignatures.add(alias);
				}
				if (curves != null && matchCurves(curves, chain)) {
					matchingCurves.add(alias);
				}
				++index;
			}
			if (!matchingServerNames.isEmpty()) {
				LOGGER.debug("[{}]: {} selected by {}", id, matchingServerNames.size(), serverNames);
				aliases.retainAll(matchingServerNames);
			}
			if (signatureAndHashAlgorithms != null) {
				LOGGER.debug("[{}]: {} selected by signature and hash algorithms", id, matchingSignatures.size());
				aliases.retainAll(matchingSignatures);
			}
			if (curves != null) {
				LOGGER.debug("[{}]: {} selected by curves", id, matchingCurves.size());
				aliases.retainAll(matchingCurves);
			}
			if (aliases.size() > 0) {
				String id = null;
				if (aliases.size() > 1 && signatureAndHashAlgorithms != null && signatureAndHashAlgorithms.size() > 1) {
					aliases = selectPriorized(aliases, signatureAndHashAlgorithms);
				}
				if (aliases.size() > 1 && defaultAlias != null && aliases.contains(defaultAlias)) {
					id = defaultAlias;
				} else {
					id = aliases.get(0);
				}
				X509Certificate[] certificateChain = keyManager.getCertificateChain(id);
				List<X509Certificate> chain = Arrays.asList(certificateChain);
				PrivateKey privateKey = keyManager.getPrivateKey(id);
				return new CertificateIdentityResult(cid, privateKey, chain, id);
			}
		} else {
			LOGGER.debug("[{}]: no matching credentials", id);
		}
		return new CertificateIdentityResult(cid, null);
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		// empty implementation
	}

	/**
	 * Get aliases for matching credentials.
	 * 
	 * @param client {@code true}, for client side certificates, {@code false},
	 *            for server side certificates.
	 * @param keyTypes list of key types.
	 * @param issuers list of trusted issuers. May be {@code null}.
	 * @return list of aliases to matching credentials. Empty, if no matching
	 *         credentials are found.
	 */
	private List<String> getAliases(boolean client, List<String> keyTypes, Principal[] issuers) {
		List<String> all = new ArrayList<>();
		for (String keyType : keyTypes) {
			String[] alias = null;
			if (client) {
				alias = keyManager.getClientAliases(keyType, issuers);
			} else {
				alias = keyManager.getServerAliases(keyType, issuers);
				if (alias == null && JceProviderUtil.usesBouncyCastle()) {
					// replace sun keyTypes as defined in
					// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#jssenames
					// by the ones Bouncy Castle chose to use for the server-side
					// https://github.com/bcgit/bc-java/issues/1053
					String bcKeyType = BC_SERVER_KEY_TYPES_MAP.get(keyType);
					if (bcKeyType != null) {
						alias = keyManager.getServerAliases(bcKeyType, issuers);
						if (alias != null) {
							keyType = bcKeyType;
						}
					}
				}
			}
			if (alias != null) {
				LOGGER.debug("[{}]: found {} {} keys for {}", id, alias.length, keyType, client ? "client" : "server");
				ListUtils.addIfAbsent(all, Arrays.asList(alias));
			} else {
				LOGGER.debug("[{}]: found no {} keys for {}", id, keyType, client ? "client" : "server");
			}
		}
		return all;
	}

	/**
	 * Check, if provided node certificate matches the serverNames.
	 * 
	 * @param serverNames server names
	 * @param node node certificate
	 * @return {@code true}, if matching, {@code false}, if not.
	 * @see CertPathUtil#matchDestination(X509Certificate, String)
	 */
	private boolean matchServerNames(ServerNames serverNames, X509Certificate node) {
		ServerName serverName = serverNames.getServerName(ServerName.NameType.HOST_NAME);
		if (serverName != null) {
			// currently only hostnames are defined (and supported)
			String name = serverName.getNameAsString();
			return CertPathUtil.matchDestination(node, name);
		} else {
			return false;
		}
	}

	/**
	 * Checks, if provided certificate chain matches the signature and hash
	 * algorithms.
	 * 
	 * @param signatureAndHashAlgorithms list of signature and hash algorithms
	 * @param chain the certificate chain to check
	 * @return {@code true}, if matching, {@code true}, if not.
	 */
	private boolean matchSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms,
			List<X509Certificate> chain) {
		if (SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(signatureAndHashAlgorithms,
				chain.get(0).getPublicKey()) == null) {
			return false;
		}
		if (!SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(signatureAndHashAlgorithms, chain)) {
			return false;
		}
		return true;
	}

	/**
	 * Checks, if provided certificate chain matches the curves.
	 * 
	 * @param curves list of supported groups (curves)
	 * @param chain the certificate chain to check
	 * @return {@code true}, if matching, {@code true}, if not.
	 */
	private boolean matchCurves(List<SupportedGroup> curves, List<X509Certificate> chain) {
		for (X509Certificate certificate : chain) {
			PublicKey certPublicKey = certificate.getPublicKey();
			if (Asn1DerDecoder.isEcBased(certPublicKey.getAlgorithm())) {
				SupportedGroup group = SupportedGroup.fromPublicKey(certPublicKey);
				if (group == null) {
					return false;
				}
				if (!curves.contains(group)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Select the set of aliases, which node certificate matches the first
	 * matching signature and hash algorithms.
	 * 
	 * @param alias preselected aliases
	 * @param signatureAndHashAlgorithms list of signature and hash algorithms
	 *            ordered by priority
	 * @return (sub) set of aliases matching the first matching signature and
	 *         hash algorithms in the ordered list.
	 */
	private List<String> selectPriorized(List<String> alias,
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		List<String> result = new ArrayList<>();
		for (SignatureAndHashAlgorithm signatureAndHashAlgorithm : signatureAndHashAlgorithms) {
			for (String id : alias) {
				X509Certificate[] certificateChain = keyManager.getCertificateChain(id);
				if (certificateChain != null && certificateChain.length > 0) {
					String algorithm = certificateChain[0].getPublicKey().getAlgorithm();
					if (signatureAndHashAlgorithm.isSupported(algorithm)) {
						result.add(id);
						LOGGER.debug("Select by signature {} - {} == {}", id, signatureAndHashAlgorithm.getJcaName(),
								algorithm);
					} else {
						LOGGER.debug("Signature doesn't match {} - {} != {}", id,
								signatureAndHashAlgorithm.getJcaName(), algorithm);
					}
				}
			}
			if (!result.isEmpty()) {
				break;
			}
		}
		return result;
	}

	private static void addEdDsaSupport(List<String> publicKeyTypes,
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		if (signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519)) {
			ListUtils.addIfAbsent(publicKeyTypes, Asn1DerDecoder.EDDSA);
			ListUtils.addIfAbsent(publicKeyTypes, Asn1DerDecoder.ED25519);
		}
		if (signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448)) {
			ListUtils.addIfAbsent(publicKeyTypes, Asn1DerDecoder.EDDSA);
			ListUtils.addIfAbsent(publicKeyTypes, Asn1DerDecoder.ED448);
		}
	}

	private static List<CertificateType> asList(CertificateType[] types) {
		if (types == null || types.length == 0) {
			return null;
		}
		return Arrays.asList(types);
	}
}
