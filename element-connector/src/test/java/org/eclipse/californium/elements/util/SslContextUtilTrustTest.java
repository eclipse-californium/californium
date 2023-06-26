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
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class SslContextUtilTrustTest {

	public static final String TRUST_STORE_PASSWORD_HEX = "726F6F7450617373";
	public static final String TRUST_P12_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/trustStore.p12";
	public static final String TRUST_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/trustStore.pem";
	public static final String SINGLE_TRUST_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/rootTrustStore.pem";

	public static final char[] TRUST_STORE_WRONG_PASSWORD = "wrongPass".toCharArray();

	public static final String ALIAS_CA = "ca";
	public static final String ALIAS_MISSING = "missing";
	public static final X500Principal DN_CA = new X500Principal("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-ca");
	public static final X500Principal DN_CA2 = new X500Principal("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-ca2");
	public static final X500Principal DN_CA_RSA = new X500Principal("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-ca-rsa");
	public static final X500Principal DN_ROOT = new X500Principal("C=CA, L=Ottawa, O=Eclipse IoT, OU=Californium, CN=cf-root");

	@Test
	public void testLoadTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, null,
				TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		assertThat(trustedCertificates[0].getPublicKey(), is(notNullValue()));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	public void testLoadFilteredTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, ALIAS_CA,
				TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	/**
	 * Test, if a exception is thrown, when no certificate matches the filter.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testLoadFilteredTrustedCertificatesNotFound() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, ALIAS_MISSING, TRUST_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri doesn't point to a
	 * keystore.
	 */
	@Test(expected = IOException.class)
	public void testLoadTrustedCertificatesNoFile() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI + "no-file", null, TRUST_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri is null.
	 */
	@Test(expected = NullPointerException.class)
	public void testLoadTrustedCertificatesNullUri() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(null, null, TRUST_STORE_PASSWORD);
	}

	/**
	 * Test, if a exception is thrown, when the password is null.
	 */
	@Test(expected = NullPointerException.class)
	public void testLoadTrustedCertificatesNoPassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, null, null);
	}

	/**
	 * Test, if a exception is thrown, when the password is wrong.
	 */
	@Test(expected = IOException.class)
	public void testLoadTrustedCertificatesWrongPassword() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, null, TRUST_STORE_WRONG_PASSWORD);
	}

	@Test
	public void testLoadTrustedCertificatesSingleParameterWithoutAlias() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(greaterThan(0)));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		assertThat(trustedCertificates[0].getPublicKey(), is(notNullValue()));
	}

	@Test
	public void testLoadTrustedCertificatesSingleParameter() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR
				+ ALIAS_CA);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testLoadTrustedCertificatesSingleParameterError() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX);
	}

	@Test
	public void testLoadTrustManager() throws IOException, GeneralSecurityException {
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_STORE_URI, null, TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	/**
	 * Test, if a exception is thrown, when no certificate matches the filter.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testLoadTrustManagerCertificateNotFound() throws IOException, GeneralSecurityException {
		SslContextUtil.loadTrustManager(TRUST_STORE_URI, ALIAS_MISSING, TRUST_STORE_PASSWORD);
	}

	@Test
	public void testCreateTrustManager() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_STORE_URI, null,
				TRUST_STORE_PASSWORD);
		TrustManager[] manager = SslContextUtil.createTrustManager("test", trustedCertificates);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test(expected = NullPointerException.class)
	public void testCreateTrustManagerNullCertificates() throws IOException, GeneralSecurityException {
		SslContextUtil.createTrustManager("test", null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateTrustManagerEmptyCertificates() throws IOException, GeneralSecurityException {
		SslContextUtil.createTrustManager("test", new Certificate[0]);
	}

	@Test
	public void testLoadP12TrustedCertificates() throws IOException, GeneralSecurityException {
		assumeTrue("requires strong encryption", JceProviderUtil.hasStrongEncryption());
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_P12_LOCATION, null, TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	public void testLoadP12TrustedCertificatesWithAlias() throws IOException, GeneralSecurityException {
		assumeTrue("requires strong encryption", JceProviderUtil.hasStrongEncryption());
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_P12_LOCATION, ALIAS_CA, TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	@Test
	public void testLoadP12TrustManager() throws IOException, GeneralSecurityException {
		assumeTrue("requires strong encryption", JceProviderUtil.hasStrongEncryption());
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_P12_LOCATION, null, TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	public void testLoadP12TrustManagerWithAlias() throws IOException, GeneralSecurityException {
		assumeTrue("requires strong encryption", JceProviderUtil.hasStrongEncryption());
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_P12_LOCATION, ALIAS_CA, TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	public void testLoadPemTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_PEM_LOCATION, null, null);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	public void testLoadPemTrustManager() throws IOException, GeneralSecurityException {
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_PEM_LOCATION, null, null);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	public void testLoadPemTrustedSingleCertificate() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(SINGLE_TRUST_PEM_LOCATION);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_ROOT));
	}

}
