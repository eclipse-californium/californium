/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      Moved from DtlsTestTools
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

public class TestCertificatesTools {

	public static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	public static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	public static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	public static final String EDDSA_KEY_STORE_LOCATION = "certs/eddsaKeyStore.jks";
	public static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	public static final String KEY_STORE_URI = SslContextUtil.CLASSPATH_SCHEME + "certs/keyStore.jks";
	public static final String EDDSA_KEY_STORE_URI = SslContextUtil.CLASSPATH_SCHEME + "certs/eddsaKeyStore.jks";
	public static final String TRUST_STORE_URI = SslContextUtil.CLASSPATH_SCHEME + "certs/trustStore.jks";
	public static final String SERVER_NAME = "server";
	/**
	 * Alias for mixed signed server certificate chain. Include ECDSA and RSA
	 * certificates.
	 * 
	 * @since 2.3
	 */
	public static final String SERVER_RSA_NAME = "serverrsa";
	public static final String CLIENT_NAME = "client";
	public static final String ROOT_CA_ALIAS = "root";
	public static final String CA_ALIAS = "ca";
	public static final String CA_ALT_ALIAS = "caalt";
	public static final String NO_SIGNING_ALIAS = "nosigning";

	private static final SecureRandom random = new SecureRandom();

	private static SslContextUtil.Credentials clientCredentials;
	private static SslContextUtil.Credentials serverCredentials;
	private static SslContextUtil.Credentials serverRsaCredentials;
	private static X509Certificate[] trustedCertificates;
	private static X509Certificate rootCaCertificate;
	private static X509Certificate caCertificate;
	private static X509Certificate caAlternativeCertificate;
	// a certificate without digitalSignature value in keyusage
	private static X509Certificate nosigningCertificate;
	
	static {
		try {
			// load key stores once only
			clientCredentials = SslContextUtil.loadCredentials(KEY_STORE_URI,
					CLIENT_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			serverCredentials = SslContextUtil.loadCredentials(KEY_STORE_URI,
					SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			serverRsaCredentials = SslContextUtil.loadCredentials(KEY_STORE_URI,
					SERVER_RSA_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			Certificate[] certificates = SslContextUtil.loadTrustedCertificates(
					TRUST_STORE_URI, null, TRUST_STORE_PASSWORD);

			trustedCertificates = SslContextUtil.asX509Certificates(certificates);
			certificates = SslContextUtil.loadTrustedCertificates(
					TRUST_STORE_URI, ROOT_CA_ALIAS, TRUST_STORE_PASSWORD);
			rootCaCertificate = (X509Certificate) certificates[0];
			certificates = SslContextUtil.loadTrustedCertificates(
					TRUST_STORE_URI, CA_ALIAS, TRUST_STORE_PASSWORD);
			caCertificate = (X509Certificate) certificates[0];
			certificates = SslContextUtil.loadTrustedCertificates(
					TRUST_STORE_URI, CA_ALT_ALIAS, TRUST_STORE_PASSWORD);
			caAlternativeCertificate = (X509Certificate) certificates[0];
			X509Certificate[] chain = SslContextUtil.loadCertificateChain(
					KEY_STORE_URI, NO_SIGNING_ALIAS, KEY_STORE_PASSWORD);
			nosigningCertificate = chain[0];
		} catch (IOException | GeneralSecurityException e) {
			// nothing we can do
		}
	}

	protected TestCertificatesTools() {
	}

	public static X509Certificate[] getServerCertificateChain() {
		X509Certificate[] certificateChain = serverCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	public static List<X509Certificate> getServerCertificateChainAsList() {
		X509Certificate[] certificateChain = serverCredentials.getCertificateChain();
		return Arrays.asList(certificateChain);
	}

	/**
	 * Get mixed server certificate chain. Contains ECDSA and RSA certificates.
	 * 
	 * @return mixed server certificate chain
	 * @since 2.3
	 */
	public static X509Certificate[] getServerRsaCertificateChain() {
		X509Certificate[] certificateChain = serverRsaCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	/**
	 * Get mixed server certificate chain. Contains ECDSA and RSA certificates.
	 * 
	 * @return mixed server certificate chain
	 * @since 2.5
	 */
	public static List<X509Certificate> getServerRsaCertificateChainAsList() {
		X509Certificate[] certificateChain = serverRsaCredentials.getCertificateChain();
		return Arrays.asList(certificateChain);
	}

	public static X509Certificate[] getClientCertificateChain() {
		X509Certificate[] certificateChain = clientCredentials.getCertificateChain();
		return Arrays.copyOf(certificateChain, certificateChain.length);
	}

	public static List<X509Certificate> getClientCertificateChainAsList() {
		X509Certificate[] certificateChain = clientCredentials.getCertificateChain();
		return Arrays.asList(certificateChain);
	}

	/**
	 * Get credentials for alias.
	 * 
	 * @param alias alias for credentials
	 * @return loaded credentials, or {@code null}, if not available.
	 * @since 2.4
	 */
	public static SslContextUtil.Credentials getCredentials(String alias) {
		try {
			try {
				return SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, alias,
						KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			} catch (IllegalArgumentException ex) {
				return SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + EDDSA_KEY_STORE_LOCATION, alias,
						KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			}
		} catch (IOException | GeneralSecurityException e) {
			return null;
		}
	}

	/**
	 * Get server's key pair.
	 * 
	 * @return server's key pair
	 * @since 2.4
	 */
	public static KeyPair getServerKeyPair() {
		return new KeyPair(serverCredentials.getPubicKey(), serverCredentials.getPrivateKey());
	}

	/**
	 * Gets the server's private key from the example key store.
	 * 
	 * @return the key
	 */
	public static PrivateKey getPrivateKey() {
		return serverCredentials.getPrivateKey();
	}

	/**
	 * Gets the server's private key from the example key store. Use the server
	 * with mixed certificate chain wiht ECDSA and RSA certificates.
	 * 
	 * @return the key
	 * @since 2.3
	 */
	public static PrivateKey getServerRsPrivateKey() {
		return serverRsaCredentials.getPrivateKey();
	}

	/**
	 * Gets the client's private key from the example key store.
	 * 
	 * @return the key
	 */
	public static PrivateKey getClientPrivateKey() {
		return clientCredentials.getPrivateKey();
	}

	/**
	 * Gets the server's public key from the example key store.
	 * 
	 * @return The key.
	 */
	public static PublicKey getPublicKey() {
		return serverCredentials.getCertificateChain()[0].getPublicKey();
	}

	/**
	 * Gets the client's public key from the example key store.
	 * 
	 * @return The key.
	 */
	public static PublicKey getClientPublicKey() {
		return clientCredentials.getCertificateChain()[0].getPublicKey();
	}

	/**
	 * Gets the trusted anchor certificates from the example trust store.
	 * 
	 * @return The trusted certificates.
	 */
	public static X509Certificate[] getTrustedCertificates() {
		return trustedCertificates;
	}

	/**
	 * Gets the trusted root CA certificate.
	 * 
	 * @return The certificate.
	 */
	public static X509Certificate getTrustedRootCA() {
		return rootCaCertificate;
	}

	/**
	 * Gets the trusted CA certificate.
	 * 
	 * @return The certificate.
	 */
	public static X509Certificate getTrustedCA() {
		return caCertificate;
	}

	/**
	 * Gets the alternative CA certificate.
	 * 
	 * This certificate has the same DN as {@link #getTrustedCA()}, but uses a
	 * different key-pair and is not used to sign other certificates.
	 * 
	 * @return The certificate.
	 */
	public static X509Certificate getAlternativeCA() {
		return caAlternativeCertificate;
	}

	/**
	 * @return a certificate without digitalSignature in keyusage extension
	 */
	public static X509Certificate getNoSigningCertificate() {
		return nosigningCertificate;
	}

	/**
	 * Assert, that the provided key could be used for signing and verification.
	 * 
	 * @param message message for failure
	 * @param privateKey private key to sign
	 * @param pulbicKey public key to verify
	 * @param algorithm the standard name of the algorithm requested. See the
	 *            Signature section in the <a href=
	 *            "https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature">
	 *            Java Cryptography Architecture Standard Algorithm Name
	 *            Documentation</a> for information about standard algorithm
	 *            names. EdDSA variants may be available by third-party library,
	 *            see {@link Asn1DerDecoder#getEdDsaProvider()}).
	 * @since 3.0
	 */
	public static void assertSigning(String message, PrivateKey privateKey, PublicKey pulbicKey, String algorithm) {
		try {
			Signature signature = getSignatureInstance(algorithm);
			assertSigning(message, privateKey, pulbicKey, signature);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			fail(algorithm + " failed with " + e);
		}
	}

	/**
	 * Assert, that the provided key could be used for signing and verification.
	 * 
	 * @param message message for failure
	 * @param privateKey private key to sign
	 * @param pulbicKey public key to verify
	 * @param signature signature variant.
	 * @since 3.0
	 * @param signature
	 */
	public static void assertSigning(String message, PrivateKey privateKey, PublicKey pulbicKey, Signature signature) {
		String algorithm = signature.getAlgorithm();
		try {
			int len = 256;
			if (algorithm.startsWith("NONEwith") && !algorithm.equals("NONEwithEdDSA")) {
				len = 64;
			}
			byte[] data = Bytes.createBytes(random, len);
			signature.initSign(privateKey);
			signature.update(data, 0, len);
			byte[] sign = signature.sign();

			signature.initVerify(pulbicKey);
			signature.update(data, 0, len);
			if (!signature.verify(sign)) {
				fail(message + ":" + algorithm + " failed!");
			}
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			fail(message + ":" + algorithm + " failed with " + e);
		} catch (RuntimeException e) {
			e.printStackTrace();
			fail(message + ":" + algorithm + " failed with " + e);
		}
	}

	/**
	 * Get signature for algorithm.
	 * 
	 * For EdDSA use {@link Asn1DerDecoder#getEdDsaProvider()}.
	 * 
	 * @param algorithm the standard name of the algorithm requested. See the
	 *            Signature section in the <a href=
	 *            "https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature">
	 *            Java Cryptography Architecture Standard Algorithm Name
	 *            Documentation</a> for information about standard algorithm
	 *            names. EdDSA variants may be available by third-party library,
	 *            see {@link Asn1DerDecoder#getEdDsaProvider()}).
	 * @return signature
	 * @throws NoSuchAlgorithmException if algorithm is not supported.
	 * @since 3.0
	 */
	private static Signature getSignatureInstance(String algorithm) throws NoSuchAlgorithmException {
		String oid = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, null);
		if (oid != null) {
			Provider provider = Asn1DerDecoder.getEdDsaProvider();
			if (provider != null) {
				// signature still requires specific EdDSA provider
				return Signature.getInstance(oid, provider);
			}
		}
		return Signature.getInstance(algorithm);
	}

	public static void assertEquals(List<? extends Certificate> list1, List<? extends Certificate> list2) {
		assertEquals("", list1, list2);
	}

	public static void assertEquals(String message, List<? extends Certificate> list1,
			List<? extends Certificate> list2) {
		String diff = diff(list1, list2);
		if (!diff.isEmpty()) {
			fail(message + diff);
		}
	}

	public static void assertEquals(X509Certificate[] list1, X509Certificate[] list2) {
		assertEquals(Arrays.asList(list1), Arrays.asList(list2));
	}

	public static void assertEquals(String message, X509Certificate[] list1, X509Certificate[] list2) {
		assertEquals(message, Arrays.asList(list1), Arrays.asList(list2));
	}

	public static void assertEquals(X509Certificate[] list1, List<? extends Certificate> list2) {
		assertEquals(Arrays.asList(list1), list2);
	}

	public static void assertEquals(String message, X509Certificate[] list1, List<? extends Certificate> list2) {
		assertEquals(message, Arrays.asList(list1), list2);
	}

	private static String diff(List<? extends Certificate> list1, List<? extends Certificate> list2) {
		boolean found = false;
		StringBuilder diff = new StringBuilder();
		int size1 = list1.size();
		int size2 = list2.size();
		int size = Math.min(size1, size2);
		if (size1 != size2) {
			diff.append("size ").append(size1).append("!=").append(size2).append(", ");
		}
		for (int index = 0; index < size; ++index) {
			Certificate cert1 = list1.get(index);
			Certificate cert2 = list2.get(index);
			if (!cert1.equals(cert2)) {
				found = true;
				if (cert1 instanceof X509Certificate && cert2 instanceof X509Certificate) {
					X500Principal dn1 = ((X509Certificate) cert1).getSubjectX500Principal();
					X500Principal dn2 = ((X509Certificate) cert2).getSubjectX500Principal();
					if (!dn1.equals(dn2)) {
						diff.append("DN [").append(index).append("] ").append(dn1).append("!=").append(dn2)
								.append(", ");
						break;
					}
				}
				diff.append("cert [").append(index).append("] ").append(cert1).append("!=").append(cert2).append(", ");
				break;
			}
		}
		if (!found && size1 != size2) {
			String tag;
			Certificate cert;
			if (size1 < size2) {
				tag = "list-2";
				cert = list2.get(size);
			} else {
				tag = "list-1";
				cert = list1.get(size);
			}
			if (cert instanceof X509Certificate) {
				X500Principal dn = ((X509Certificate) cert).getSubjectX500Principal();
				diff.append(tag).append(" additional DN [").append(size).append("] ").append(dn).append(", ");
			} else {
				diff.append(tag).append(" additional cert [").append(size).append("] ").append(cert).append(", ");
			}
		}
		if (diff.length() > 0) {
			diff.setLength(diff.length() - 2);
		}
		return diff.toString();
	}

}
