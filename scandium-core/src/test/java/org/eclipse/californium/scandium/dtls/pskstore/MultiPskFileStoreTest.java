/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class MultiPskFileStoreTest {

	/**
	 * {@code me=secret},{@code you=public}.
	 */
	private static final byte[] DATA = ("me=c2VjcmV0" + StringUtil.lineSeparator + "you=cHVibGlj"
			+ StringUtil.lineSeparator).getBytes();

	@Rule
	public LoggingRule logging = new LoggingRule();

	private MultiPskFileStore store;
	private SecretKey secret;

	@Before
	public void setUp() throws Exception {
		store = new MultiPskFileStore();
		secret = SecretUtil.create("secure".getBytes(), "PW");
	}

	@After
	public void tearDownp() throws Exception {
		store.destroy();
		SecretUtil.destroy(secret);
	}

	@Test
	public void testLoadPlainPskStore() {
		InputStream in = new ByteArrayInputStream(DATA);
		store.loadPskCredentials(in);
		assertThat(store.size(), is(2));

		SecretKey key = store.getSecret("me");
		SecretKey expected = SecretUtil.create("secret".getBytes(), PskSecretResult.ALGORITHM_PSK);
		assertThat(key, is(expected));
		SecretUtil.destroy(key);
		SecretUtil.destroy(expected);

		key = store.getSecret("you");
		expected = SecretUtil.create("public".getBytes(), PskSecretResult.ALGORITHM_PSK);
		assertThat(key, is(expected));
		SecretUtil.destroy(key);
		SecretUtil.destroy(expected);
	}

	@Test
	public void testSavePlainPskStore() {
		InputStream in = new ByteArrayInputStream(DATA);
		store.loadPskCredentials(in);
		assertThat(store.size(), is(2));

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		store.savePskCredentials(out);

		assertArrayEquals(DATA, out.toByteArray());
	}

	@Test
	public void testSaveAndLoadEncryptedPskStore() {
		InputStream in = new ByteArrayInputStream(DATA);
		store.loadPskCredentials(in);
		assertThat(store.size(), is(2));

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		store.savePskCredentials(out, secret);
		byte[] encrypted = out.toByteArray();

		assertThat(encrypted, is(not(DATA)));
		MultiPskFileStore store2 = new MultiPskFileStore();
		store2.loadPskCredentials(new ByteArrayInputStream(encrypted), secret);
		assertThat(store2.size(), is(store.size()));

		for (int index = 0; index < store.size(); ++index) {
			assertThat(store2.getIdentity(index), is(store.getIdentity(index)));
			assertThat(store2.getSecret(index), is(store.getSecret(index)));
		}
	}

	@Test
	public void testSaveAndLoadEncryptedPskStoreWithWrongPassword() {
		InputStream in = new ByteArrayInputStream(DATA);
		store.loadPskCredentials(in);
		assertThat(store.size(), is(2));

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		store.savePskCredentials(out, secret);
		byte[] encrypted = out.toByteArray();

		assertThat(encrypted, is(not(DATA)));

		SecretKey key2 = SecretUtil.create("broken".getBytes(), "PW");

		logging.setLoggingLevel("ERROR", MultiPskFileStore.class);

		MultiPskFileStore store2 = new MultiPskFileStore();
		store2.loadPskCredentials(new ByteArrayInputStream(encrypted), key2);
		assertThat(store2.size(), is(0));

		SecretUtil.destroy(key2);
	}

}
