/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.eclipse.californium.elements.util.TestCertificatesTools.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class SslContextUtilCredentialsTest {

	public static final String KEY_STORE_PASSWORD_HEX = "656E6450617373";

	public static final String SERVER_P12_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/server.p12";
	public static final String SERVER_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/server.pem";
	public static final String SERVER_LARGE_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/serverLarge.pem";
	public static final String PUBLIC_KEY_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/ec_public.pem";

	public static final String ALIAS_SERVER = "server";
	public static final String ALIAS_CLIENT = "client";
	public static final String ALIAS_MISSING = "missing";
	public static final X500Principal DN_SERVER = new X500Principal("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-server");

	@Test
	public void testLoadCredentials() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getPrivateKey(), is(notNullValue()));
		assertThat(credentials.getCertificateChain(), is(notNullValue()));
		assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
		assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) credentials.getCertificateChain()[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
	}

	/**
	 * Test, if a exception is thrown, when no credentials matches the alias.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testLoadCredentialsNotFound() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_MISSING, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri doesn't point to a
	 * keystore.
	 */
	@Test(expected = IOException.class)
	public void testLoadCredentialsNoFile() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI + "no-file", ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri is null.
	 */
	@Test(expected = NullPointerException.class)
	public void testLoadCredentialsNullUri() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(null, ALIAS_SERVER, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the store password is null.
	 */
	@Test(expected = NullPointerException.class)
	public void testLoadCredentialsNoStorePassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, null, KEY_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the key password is null.
	 */
	@Test(expected = NullPointerException.class)
	public void testLoadCredentialsNoKeyPassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD, null);
	}

	/**
	 * Test, if a exception is thrown, when the store password is wrong.
	 */
	@Test(expected = IOException.class)
	public void testLoadCredentialsWrongStorePassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD_HEX.toCharArray(),
				KEY_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the key password is wrong.
	 */
	@Test(expected = GeneralSecurityException.class)
	public void testLoadCredentialsWrongKeyPassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD_HEX.toCharArray());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testLoadCredentialsSingleParameterWithoutAlias() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(KEY_STORE_URI + SslContextUtil.PARAMETER_SEPARATOR + KEY_STORE_PASSWORD_HEX
				+ SslContextUtil.PARAMETER_SEPARATOR + KEY_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR);
	}

	@Test
	public void testLoadCredentialsSingleParameter() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + KEY_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR
				+ KEY_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR + ALIAS_SERVER);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getPrivateKey(), is(notNullValue()));
		assertThat(credentials.getCertificateChain(), is(notNullValue()));
		assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
		assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) credentials.getCertificateChain()[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
	}

	@Test
	public void testLoadCertificateChain() throws IOException, GeneralSecurityException {
		X509Certificate[] chain = SslContextUtil.loadCertificateChain(KEY_STORE_URI, ALIAS_SERVER,
				KEY_STORE_PASSWORD);
		assertThat(chain, is(notNullValue()));
		assertThat(chain.length, is(greaterThan(0)));
		assertThat(chain[0].getPublicKey(), is(notNullValue()));
		assertThat(chain[0].getSubjectX500Principal(), is(DN_SERVER));
	}

	@Test(expected = NullPointerException.class)
	public void testLoadCertificateChainMissingAlias() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCertificateChain(KEY_STORE_URI, null, KEY_STORE_PASSWORD);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testLoadCertificateChainEmptyAlias() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCertificateChain(KEY_STORE_URI, "", KEY_STORE_PASSWORD);
	}

	@Test
	public void testLoadKeyManager() throws IOException, GeneralSecurityException {
		KeyManager[] manager = SslContextUtil.loadKeyManager(KEY_STORE_URI, null, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
	}

	/**
	 * Test, if a exception is thrown, when no certificate matches the filter.
	 */
	@Test(expected = GeneralSecurityException.class)
	public void testLoadKeyManagerCertificateNotFound() throws IOException, GeneralSecurityException {
		SslContextUtil.loadKeyManager(KEY_STORE_URI, "missing", KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
	}

	@Test
	public void testCreateKeyManager() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		KeyManager[] manager = SslContextUtil.createKeyManager("test", credentials.getPrivateKey(),
				credentials.getCertificateChain());
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateKeytManagerNullPrivateKey() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		SslContextUtil.createKeyManager("test", null, credentials.getCertificateChain());
	}

	@Test(expected = NullPointerException.class)
	public void testCreateKeytManagerNullCertChain() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		SslContextUtil.createKeyManager("test", credentials.getPrivateKey(), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateKeyManagerEmptyCertChain() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		SslContextUtil.createKeyManager("test", credentials.getPrivateKey(), new X509Certificate[0]);
	}

	@Test
	public void testLoadP12Credentials() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(SERVER_P12_LOCATION, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getPrivateKey(), is(notNullValue()));
		assertThat(credentials.getCertificateChain(), is(notNullValue()));
		assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
		assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) credentials.getCertificateChain()[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
	}

	@Test
	public void testLoadP12KeyManager() throws IOException, GeneralSecurityException {
		KeyManager[] manager = SslContextUtil.loadKeyManager(SERVER_P12_LOCATION, null, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
	}

	@Test
	public void testLoadPemCredentials() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(SERVER_PEM_LOCATION, null, null, null);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getPrivateKey(), is(notNullValue()));
		assertThat(credentials.getCertificateChain(), is(notNullValue()));
		assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
		assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) credentials.getCertificateChain()[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
	}

	@Test
	public void testLoadPemKeyManager() throws IOException, GeneralSecurityException {
		KeyManager[] manager = SslContextUtil.loadKeyManager(SERVER_PEM_LOCATION, null, null,
				null);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
	}

	@Test
	public void testLoadLargePemKeyManager() throws IOException, GeneralSecurityException {
		KeyManager[] manager = SslContextUtil.loadKeyManager(SERVER_LARGE_PEM_LOCATION, null, null,
				null);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
	}

	@Test
	public void testLoadPemPublicKey() throws IOException, GeneralSecurityException {
		PublicKey publicKey = SslContextUtil.loadPublicKey(PUBLIC_KEY_PEM_LOCATION, null, null);
		assertThat(publicKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemPrivateKey() throws IOException, GeneralSecurityException {
		PrivateKey privateKey = SslContextUtil.loadPrivateKey(SERVER_PEM_LOCATION, null, null, null);
		assertThat(privateKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemPrivateKeyV2() throws IOException, GeneralSecurityException {
		PrivateKey privateKey = SslContextUtil.loadPrivateKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ec_private.pem", null, null, null);
		assertThat(privateKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemCredentialsV2() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + "certs/ec_private.pem", null, null, null);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getPrivateKey(), is(notNullValue()));
		assertThat(credentials.getPublicKey(), is(notNullValue()));
		assertSigning("PEMv2", credentials.getPrivateKey(), credentials.getPublicKey(), "SHA256withECDSA");
	}

	@Test
	public void testLoadEdDsaCredentials() throws IOException, GeneralSecurityException {
		assumeTrue("ED25519 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED25519));
		assumeTrue(EDDSA_KEY_STORE_URI + " missing!", SslContextUtil.isAvailableFromUri(EDDSA_KEY_STORE_URI));

		Credentials credentials = SslContextUtil.loadCredentials(EDDSA_KEY_STORE_URI, "clienteddsa",
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
		assertThat(credentials.getCertificateChain(), is(notNullValue()));
		assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
		assertThat(credentials.getCertificateChain()[0].getPublicKey(), is(notNullValue()));
		assertSigning("JKS", credentials.getPrivateKey(), credentials.getPublicKey(), "ED25519");
	}

	@Test
	public void testLoadPemPrivateKeyEd25519() throws IOException, GeneralSecurityException {
		assumeTrue("ED25519 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED25519));
		PrivateKey privateKey = SslContextUtil.loadPrivateKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_private.pem", null, null, null);
		assertThat(privateKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemPublicKeyEd25519() throws IOException, GeneralSecurityException {
		assumeTrue("ED25519 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED25519));
		PublicKey publicKey = SslContextUtil.loadPublicKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_public.pem", null, null);
		assertThat(publicKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemPrivateKeyEd448() throws IOException, GeneralSecurityException {
		assumeTrue("ED448 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED448));
		PrivateKey privateKey = SslContextUtil.loadPrivateKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_private.pem", null, null, null);
		assertThat(privateKey, is(notNullValue()));
	}

	@Test
	public void testLoadPemPublicKeyEd448() throws IOException, GeneralSecurityException {
		assumeTrue("ED448 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED448));
		PublicKey publicKey = SslContextUtil.loadPublicKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_public.pem", null, null);
		assertThat(publicKey, is(notNullValue()));
	}

}
