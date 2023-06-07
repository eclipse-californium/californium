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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.SslContextUtil.KeyStoreType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class SslContextUtilConfigurationTest {

	public static final String KEY_STORE_PASSWORD_HEX = "656E6450617373";
	public static final String ALIAS_SERVER = "server";
	public static final String CUSTOM_SCHEME = "test://";
	public static final String CUSTOM_SCHEME_KEY_STORE_LOCATION = CUSTOM_SCHEME + "keyStore.jks";
	public static final String FILE_KEY_STORE_LOCATION = "../demo-certs/src/main/resources/keyStore.jks";
	public static final String INVALID_FILE_KEY_STORE_LOCATION = "keyStore.jks";

	public static final String CUSTOM_ENDING = ".cks";
	public static final String CUSTOM_TYPE = "CKS";

	private TestInputStreamFactory testFactory;

	@Before
	public void init() {
		SslContextUtil.configureDefaults();
		testFactory = new TestInputStreamFactory();
		testFactory.stream = SslContextUtil.class.getClassLoader().getResourceAsStream("certs/keyStore.jks");
	}

	@After
	public void close() {
		try {
			testFactory.close();
		} catch (IOException e) {
		}
	}

	@Test
	public void testLoadKeyStoreFromClasspath() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
	}

	@Test
	public void testValidKeyStoreWithoutScheme() throws IOException, GeneralSecurityException {
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER,
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
	}

	@Test(expected = IOException.class)
	public void testInvalidKeyStoreWithoutScheme() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(INVALID_FILE_KEY_STORE_LOCATION, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
	}

	@Test(expected = MalformedURLException.class)
	public void testNotConfiguredScheme() throws IOException, GeneralSecurityException {
		SslContextUtil.loadCredentials(CUSTOM_SCHEME_KEY_STORE_LOCATION, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
	}

	@Test(expected = NullPointerException.class)
	public void testConfigureInputStreamFactoryWithoutScheme() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(null, testFactory);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigureInputStreamFactoryWithInvalidScheme() throws IOException, GeneralSecurityException {
		SslContextUtil.configure("test:", testFactory);
	}

	@Test(expected = NullPointerException.class)
	public void testConfigureInputStreamFactoryWithoutFactory() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(CUSTOM_SCHEME, (SslContextUtil.InputStreamFactory) null);
	}

	@Test
	public void testConfigureInputStreamFactory() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(CUSTOM_SCHEME, testFactory);
		Credentials credentials = SslContextUtil.loadCredentials(CUSTOM_SCHEME_KEY_STORE_LOCATION, ALIAS_SERVER,
				KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
		assertThat(testFactory.uri, is(CUSTOM_SCHEME_KEY_STORE_LOCATION));
	}

	@Test
	public void testLoadKeyStoreFromClasspathWithCustomConfiguration() throws IOException, GeneralSecurityException {
		testFactory.close();
		SslContextUtil.configure(CUSTOM_SCHEME, testFactory);
		Credentials credentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		assertThat(credentials, is(notNullValue()));
	}

	@Test(expected = NullPointerException.class)
	public void testConfigureKeyStoreTypeWithoutEnding() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(null, new KeyStoreType(CUSTOM_TYPE));
	}

	@Test(expected = NullPointerException.class)
	public void testConfigureKeyStoreTypeWithoutType() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(CUSTOM_ENDING, (KeyStoreType) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigureKeyStoreTypeWithInvalidEnding() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(CUSTOM_TYPE, new KeyStoreType(CUSTOM_TYPE));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConfigureKeyStoreTypeWithInvalidType() throws IOException, GeneralSecurityException {
		SslContextUtil.configure(CUSTOM_ENDING, new KeyStoreType(""));
	}

	@Test
	public void testConfigureKeyStoreType() throws IOException, GeneralSecurityException {
		try {
			SslContextUtil.configure(SslContextUtil.JKS_ENDING, new KeyStoreType(CUSTOM_TYPE));
			SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_SERVER, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			fail("custom key store type \"" + CUSTOM_TYPE + "\" is not intended to be supported!");
		} catch (GeneralSecurityException ex) {
			assertThat(ex.getMessage(), containsString(CUSTOM_TYPE));
		}
	}

	private class TestInputStreamFactory implements SslContextUtil.InputStreamFactory {

		public String uri;
		public InputStream stream;

		public void close() throws IOException {
			if (stream != null) {
				stream.close();
				stream = null;
			}
		}

		@Override
		public InputStream create(String uri) throws IOException {
			this.uri = uri;
			InputStream result = stream;
			stream = null;
			return result;
		}

	}
}
