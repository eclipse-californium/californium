/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Verifies behavior of {@link EncryptedStreamUtil}.
 * 
 * @since 3.9
 */
@Category(Small.class)
@RunWith(Parameterized.class)
public class EncryptedStreamUtilTest {

	private static boolean supportGcm;
	private static int maxKeyLengthBits;

	@BeforeClass
	public static void init() {
		JceProviderUtil.init();
		try {
			maxKeyLengthBits = Cipher.getMaxAllowedKeyLength("AES");
			Cipher.getInstance("AES/GCM/NoPadding");
			supportGcm = true;
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchPaddingException e) {
		}
	}

	@Rule
	public LoggingRule logging = new LoggingRule();

	@Parameter
	public byte[] data;

	private SecretKey key;
	private EncryptedStreamUtil util;

	private byte[] read(byte[] data, SecretKey key) throws IOException {
		byte[] buffer = new byte[256];
		int len = 0;
		int pos = 0;
		InputStream in = new ByteArrayInputStream(data);
		InputStream istream = util.prepare(in, key);
		while ((len = istream.read(buffer, pos, buffer.length - pos)) > 0) {
			pos += len;
			if (pos == buffer.length) {
				buffer = Arrays.copyOf(buffer, pos + pos);
			}
		}
		return Arrays.copyOf(buffer, pos);
	}

	private byte[] write(byte[] data, SecretKey key) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OutputStream ostream = util.prepare(out, key);
		ostream.write(data);
		ostream.close();
		return out.toByteArray();
	}

	@Parameters
	public static List<byte[]> params() {
		return Arrays.asList(Bytes.createBytes(new Random(), 142), Bytes.createBytes(new Random(), 128),
				Bytes.createBytes(new Random(), 1023), Bytes.createBytes(new Random(), 1025));
	}

	@Before
	public void setup() {
		key = new SecretKeySpec("1234567".getBytes(), "PW");
		util = new EncryptedStreamUtil();
	}

	@Test
	public void testSaveAndLoad() throws IOException {
		byte[] encrypted = write(data, key);
		byte[] read = read(encrypted, key);
		assertThat(read.length, is(data.length));
		assertArrayEquals(data, read);
	}

	@Test
	public void testSaveAndLoadInvalidPassword() throws IOException {
		byte[] encrypted = write(data, key);
		try {
			byte[] result = read(encrypted, new SecretKeySpec("abcdefg".getBytes(), "PW"));
			// AES/CBC/PKCS5Padding seems to have weak checksum
			assertThat(result, is(not(data)));
		} catch(IOException ex) {
			// valid result
		}
	}

	@Test
	public void testSaveAndLoadInvalidData() throws IOException {
		byte[] encrypted = write(data, key);
		encrypted[encrypted.length - 1] ^= 0x55;
		try {
			byte[] result = read(encrypted, key);
			// AES/CBC/PKCS5Padding seems to have weak checksum
			assertThat(result, is(not(data)));
		} catch(IOException ex) {
			// valid result
		}
	}

	@Test
	public void testSaveAndLoadAesGcm() throws IOException {
		assumeTrue("Requires GCM support by JCE", supportGcm);
		if (maxKeyLengthBits >= 256) {
			util.setWriteCipher("AES/GCM/NoPadding", 256);
		} else {
			util.setWriteCipher("AES/GCM/NoPadding", 128);
		}
		byte[] encrypted = write(data, key);
		byte[] read = read(encrypted, key);
		assertThat(read.length, is(data.length));
		assertArrayEquals(data, read);
	}

	@Test(expected = IOException.class)
	public void testSaveAndLoadAesGcmInvalidPassword() throws IOException {
		assumeTrue("Requires GCM support by JCE", supportGcm);
		if (maxKeyLengthBits >= 256) {
			util.setWriteCipher("AES/GCM/NoPadding", 256);
		} else {
			util.setWriteCipher("AES/GCM/NoPadding", 128);
		}
		byte[] encrypted = write(data, key);
		read(encrypted, new SecretKeySpec("abcdefg".getBytes(), "PW"));
		// AES/GCM/NoPadding has a strong checksum 
	}

	@Test(expected = IOException.class)
	public void testSaveAndLoadAesGcmInvalidData() throws IOException {
		assumeTrue("Requires GCM support by JCE", supportGcm);
		if (maxKeyLengthBits >= 256) {
			util.setWriteCipher("AES/GCM/NoPadding", 256);
		} else {
			util.setWriteCipher("AES/GCM/NoPadding", 128);
		}
		byte[] encrypted = write(data, key);
		encrypted[encrypted.length - 1] ^= 0x55;
		read(encrypted, key);
		// AES/GCM/NoPadding has a strong checksum 
	}

	@Test
	public void testSetWriteCipher() throws IOException {
		util.setWriteCipher("AES/CBC/PKCS5Padding", 128);
		String cipher = util.getWriteCipher();
		assertThat(cipher, is("AES/CBC/128"));
		if (maxKeyLengthBits >= 256) {
			util.setWriteCipher("AES/CBC/256");
			if (supportGcm) {
				util.setWriteCipher("AES/GCM/NoPadding", 256);
				cipher = util.getWriteCipher();
				assertThat(cipher, is("AES/GCM/256"));
				util.setWriteCipher("AES/GCM/128");
			}
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetWriteCipherFails() throws IOException {
		util.setWriteCipher("AES/CBC/512");
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testSetCipherFails() throws IOException {
		String cipher = util.getWriteCipher();
		util.setCipher("AES/CBC/PKCS5Padding", 512);
		assertThat(util.getWriteCipher(), is(cipher));
	}

	@Test
	public void testGetReadCipher() throws IOException {
		String cipher = util.getWriteCipher();
		byte[] encrypted = write(data, key);
		read(encrypted, key);
		assertThat(util.getReadCipher(), is(cipher));
	}

}
