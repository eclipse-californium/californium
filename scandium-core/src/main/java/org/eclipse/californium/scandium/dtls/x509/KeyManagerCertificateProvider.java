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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ListUtils;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Example certificate identity provider based on a
 * {@link X509ExtendedKeyManager}.
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

	/**
	 * Key type for credentials.
	 */
	private static final String[] KEY_TYPE_EC = { "EC" };
	/**
	 * Key type for credentials.
	 */
	private static final String[] KEY_TYPE_EC_EDDSA = { "EC", "EdDSA" };

	/**
	 * Default alias. May be {@code null}.
	 */
	private final String defaultAlias;

	/**
	 * Key manager.
	 */
	private final X509ExtendedKeyManager keyManager;

	/**
	 * List of supported certificate type in order of preference.
	 */
	private final List<CertificateType> supportedCertificateTypes;

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
	public KeyManagerCertificateProvider(X509ExtendedKeyManager keyManager,
			CertificateType... supportedCertificateTypes) {
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
	public KeyManagerCertificateProvider(X509ExtendedKeyManager keyManager,
			List<CertificateType> supportedCertificateTypes) {
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
	public KeyManagerCertificateProvider(String defaultAlias, X509ExtendedKeyManager keyManager,
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
	public KeyManagerCertificateProvider(String defaultAlias, X509ExtendedKeyManager keyManager,
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
		this.defaultAlias = defaultAlias;
		this.keyManager = keyManager;
		if (supportedCertificateTypes == null) {
			// default x509
			supportedCertificateTypes = new ArrayList<>(1);
			supportedCertificateTypes.add(CertificateType.X_509);
		}
		this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
	}

	@Override
	public void setupConfigurationHelper(CertificateConfigurationHelper helper) {
		List<String> aliases = getAliases(false, KEY_TYPE_EC_EDDSA, null);
		for (String alias : aliases) {
			X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
			helper.addConfigurationDefaultsFor(Arrays.asList(certificateChain));
		}
		aliases = getAliases(true, KEY_TYPE_EC_EDDSA, null);
		for (String alias : aliases) {
			X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
			helper.addConfigurationDefaultsFor(Arrays.asList(certificateChain));
		}
	}

	@Override
	public List<CertificateType> getSupportedCertificateTypes() {
		return supportedCertificateTypes;
	}

	@Override
	public CertificateIdentityResult requestCertificateIdentity(ConnectionId cid, boolean client,
			List<X500Principal> issuers, ServerNames serverNames,
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, List<SupportedGroup> curves) {
		List<String> alias;
		Principal[] principals = issuers == null ? null : issuers.toArray(new Principal[issuers.size()]);
		if (signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519)
				|| signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448)) {
			alias = getAliases(client, KEY_TYPE_EC_EDDSA, principals);
		} else {
			alias = getAliases(client, KEY_TYPE_EC, principals);
		}
		if (!alias.isEmpty()) {
			List<String> matchingServerNames = new ArrayList<>();
			List<String> matchingSignatures = new ArrayList<>();
			List<String> matchingCurves = new ArrayList<>();
			// after issuers, check the servernames
			for (String id : alias) {
				LOGGER.debug("try {} of {}", id, alias.size());
				X509Certificate[] certificateChain = keyManager.getCertificateChain(id);
				List<X509Certificate> chain = Arrays.asList(certificateChain);
				if (serverNames != null && matchServerNames(serverNames, certificateChain[0])) {
					matchingServerNames.add(id);
				}
				if (signatureAndHashAlgorithms != null
						&& matchSignatureAndHashAlgorithms(signatureAndHashAlgorithms, chain)) {
					matchingSignatures.add(id);
				}
				if (curves != null && matchCurves(curves, chain)) {
					matchingCurves.add(id);
				}
			}
			if (!matchingServerNames.isEmpty()) {
				LOGGER.debug("{} selected by {}", matchingServerNames.size(), serverNames);
				alias.retainAll(matchingServerNames);
			}
			if (signatureAndHashAlgorithms != null) {
				LOGGER.debug("{} selected by signature and hash algorithms", matchingSignatures.size());
				alias.retainAll(matchingSignatures);
			}
			if (curves != null) {
				LOGGER.debug("{} selected by curves", matchingCurves.size());
				alias.retainAll(matchingCurves);
			}
			if (alias.size() > 0) {
				String id = null;
				if (alias.size() > 1 && signatureAndHashAlgorithms != null && signatureAndHashAlgorithms.size() > 1) {
					alias = selectPriorized(alias, signatureAndHashAlgorithms);
				}
				if (alias.size() > 1 && defaultAlias != null && alias.contains(defaultAlias)) {
					id = defaultAlias;
				} else {
					id = alias.get(0);
				}
				X509Certificate[] certificateChain = keyManager.getCertificateChain(id);
				List<X509Certificate> chain = Arrays.asList(certificateChain);
				PrivateKey privateKey = keyManager.getPrivateKey(id);
				return new CertificateIdentityResult(cid, privateKey, chain, id);
			}
		} else {
			LOGGER.debug("no matching credentials");
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
	private List<String> getAliases(boolean client, String[] keyTypes, Principal[] issuers) {
		List<String> all = new ArrayList<>();
		for (String keyType : keyTypes) {
			String[] alias = null;
			if (client) {
				alias = keyManager.getClientAliases(keyType, issuers);
			} else {
				alias = keyManager.getServerAliases(keyType, issuers);
			}
			if (alias != null) {
				LOGGER.debug("found {} {} keys", alias.length, keyType);
				ListUtils.addIfAbsent(all, Arrays.asList(alias));
			}
		}
		return all;
	}

	/**
	 * Check, if provided node certificate matches the serverNames.
	 * 
	 * Checks, if the CN part of the subject DN or one of the subject
	 * alternative names matches the server name (SNI).
	 * 
	 * <pre>
	 * GeneralName ::= CHOICE {
	 *      otherName                       [0]     OtherName,
	 *      rfc822Name                      [1]     IA5String,
	 *      dNSName                         [2]     IA5String,
	 *      x400Address                     [3]     ORAddress,
	 *      directoryName                   [4]     Name,
	 *      ediPartyName                    [5]     EDIPartyName,
	 *      uniformResourceIdentifier       [6]     IA5String,
	 *      iPAddress                       [7]     OCTET STRING,
	 *      registeredID                    [8]     OBJECT IDENTIFIER}
	 * </pre>
	 * 
	 * @param serverNames server names
	 * @param node node certificate
	 * @return {@code true}, if matching, {@code true}, if not.
	 */
	private boolean matchServerNames(ServerNames serverNames, X509Certificate node) {
		ServerName serverNname = serverNames.getServerName(ServerName.NameType.HOST_NAME);
		String name = serverNname.getNameAsString();
		try {
			Collection<List<?>> alternativeNames = node.getSubjectAlternativeNames();
			if (alternativeNames != null) {
				for (List<?> alternativeName : alternativeNames) {
					int type = (Integer) alternativeName.get(0);
					String value = (String) alternativeName.get(1);
					if (type == 2 || type == 7) {
						if (name.equalsIgnoreCase((String) value)) {
							return true;
						}
					}
				}
			}
		} catch (ClassCastException e) {
		} catch (CertificateParsingException e) {
		}
		if (!name.contains("CN=")) {
			X500Principal principal = node.getSubjectX500Principal();
			if (principal.getName().endsWith("CN=" + name)) {
				return true;
			}
		}
		return false;
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
			if (Asn1DerDecoder.isSupported(certPublicKey.getAlgorithm())) {
			    // for rsa key we only check whether server support certain curves for key exchange.
				// As curves is already negotiated based on server config so we always return true
				if ("RSA".equals(certPublicKey.getAlgorithm())) {
					return true;
				}

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
				LOGGER.debug("select sign {} - {}", id, signatureAndHashAlgorithm.getJcaName());
				X509Certificate[] certificateChain = keyManager.getCertificateChain(id);
				if (signatureAndHashAlgorithm.isSupported(certificateChain[0].getPublicKey())) {
					result.add(id);
				}
			}
			if (!result.isEmpty()) {
				break;
			}
		}
		return result;
	}

	private static List<CertificateType> asList(CertificateType[] types) {
		if (types == null || types.length == 0) {
			return null;
		}
		return Arrays.asList(types);
	}
}
