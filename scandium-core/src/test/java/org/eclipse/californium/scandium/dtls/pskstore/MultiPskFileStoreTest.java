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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

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
	 * {@code me=secret}, {@code you=public}, {@code it=hex} .
	 */
	private static final byte[] DATA = (
			"me=c2VjcmV0" + StringUtil.lineSeparator + 
			"you=cHVibGlj" + StringUtil.lineSeparator +
			"it=:0x686578" + StringUtil.lineSeparator
			).getBytes();

	/**
	 * {@code me=secret}, {@code you=public}, {@code it=hex} .
	 */
	private static final byte[] DATA_STRICT_BASE64 = (
			"me=c2VjcmV0" + StringUtil.lineSeparator + 
			"you=cHVibGlj" + StringUtil.lineSeparator +
			"it=aGV4" + StringUtil.lineSeparator
			).getBytes();

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
	public void tearDown() throws Exception {
		store.destroy();
		SecretUtil.destroy(secret);
	}

	@Test
	public void testLoadPlainPskStore() {
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

		SecretKey expected = SecretUtil.create("secret".getBytes(), PskSecretResult.ALGORITHM_PSK);
		SecretKey key = store.getSecret("me");
		assertThat(key, is(expected));
		SecretUtil.destroy(key);

		key = store.getSecret(0);
		assertThat(key, is(expected));
		SecretUtil.destroy(key);
		SecretUtil.destroy(expected);

		expected = SecretUtil.create("public".getBytes(), PskSecretResult.ALGORITHM_PSK);
		key = store.getSecret("you");
		assertThat(key, is(expected));
		SecretUtil.destroy(key);

		key = store.getSecret(1);
		assertThat(key, is(expected));
		SecretUtil.destroy(key);
		SecretUtil.destroy(expected);

		expected = SecretUtil.create("hex".getBytes(), PskSecretResult.ALGORITHM_PSK);
		key = store.getSecret("it");
		assertThat(key, is(expected));
		SecretUtil.destroy(key);

		key = store.getSecret(2);
		assertThat(key, is(expected));
		SecretUtil.destroy(key);
		SecretUtil.destroy(expected);
	}

	@Test
	public void testSavePlainPskStore() {
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		store.savePskCredentials(out);

		assertArrayEquals(DATA_STRICT_BASE64, out.toByteArray());
	}

	@Test
	public void testSaveAndLoadEncryptedPskStore() {
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

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
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		store.savePskCredentials(out, secret);
		byte[] encrypted = out.toByteArray();

		assertThat(encrypted, is(not(DATA)));

		SecretKey key2 = SecretUtil.create("broken".getBytes(), "PW");

		logging.setLoggingLevel("ERROR", MultiPskFileStore.class);

		MultiPskFileStore store2 = new MultiPskFileStore();
		store2.loadPskCredentials(new ByteArrayInputStream(encrypted), key2);
		assertThat(store2.size(), is(0));
		assertThat(store2.isDestroyed(), is(true));

		SecretUtil.destroy(key2);
	}

	@Test
	public void testPskStoreRemove() {
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

		store.removeKey("me");
		assertThat(store.size(), is(2));
		assertThat(store.getSecret("me"), is(nullValue()));

		store.removeKey("you");
		assertThat(store.size(), is(1));
		assertThat(store.getSecret("your"), is(nullValue()));

		
		store.loadPskCredentials(new ByteArrayInputStream(DATA));
		assertThat(store.size(), is(3));

		store.removeKey(0);
		assertThat(store.size(), is(2));
		assertThat(store.getSecret("me"), is(nullValue()));
	}

}
