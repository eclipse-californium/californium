/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial test, derived from RecordTest
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@Category(Small.class)
@RunWith(Parameterized.class)
public class CbcBlockCipherTest {

	static final long SEQUENCE_NO = 5;
	static final int TYPE_APPL_DATA = 23;
	static final int EPOCH = 0;
	
	static final Random random = new SecureRandom();
	
	// byte representation of a 128 bit AES symmetric key
	static final SecretKey aesKey = new SecretKeySpec(Bytes.createBytes(random, 16), "AES");
	static final SecretKey aesKey256 = new SecretKeySpec(Bytes.createBytes(random, 32), "AES");

	static final SecretKey aesMacKey = new SecretKeySpec(Bytes.createBytes(random, 16), "AES");
	static final SecretKey aesMacKey256 = new SecretKeySpec(Bytes.createBytes(random, 32), "AES");

	static boolean strongEncryptionAvailable;

	@BeforeClass
	public static void checksetUp() throws Exception {
		strongEncryptionAvailable = Cipher.getMaxAllowedKeyLength("AES") > 128;
	}

	@Parameterized.Parameters
	public static List<Object[]> parameters() {
		// Trying different messages size to hit sharp corners in Coap-over-TCP
		// spec
		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[] { 0, 2 });
		parameters.add(new Object[] { 5, 2 });
		parameters.add(new Object[] { 13, 2 });
		parameters.add(new Object[] { 15, 13 });
		parameters.add(new Object[] { 16, 14 });
		parameters.add(new Object[] { 17, 15 });
		parameters.add(new Object[] { 31, 30 });
		parameters.add(new Object[] { 32, 31 });
		parameters.add(new Object[] { 33, 32 });
		parameters.add(new Object[] { 65805, 256 });
		parameters.add(new Object[] { 389805, 500 });

		return parameters;
	}

	byte[] additionalData;

	byte[] payloadData;
	int payloadLength = 50;
	int aLength = 13;

	public CbcBlockCipherTest(int payloadLength, int aLength) {
		this.payloadLength = payloadLength;
		this.aLength = aLength;
	}

	@Before
	public void setUp() throws Exception {
		// salt: 32bit client write init vector (can be any four bytes)
		ProtocolVersion protocolVer = ProtocolVersion.VERSION_DTLS_1_2;
		payloadData = Bytes.createBytes(random, payloadLength);

		// 64bit sequence number, consisting of 16bit epoch (0) + 48bit sequence number (5)
		byte[] seq_num = new byte[]{0x00, (byte) EPOCH, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) SEQUENCE_NO};

		// additional data based on sequence number, type (APPLICATION DATA) and protocol version
		additionalData = new byte[]{TYPE_APPL_DATA, (byte) protocolVer.getMajor(), (byte) protocolVer.getMinor(), 0, (byte) payloadLength};
		additionalData = Bytes.concatenate(seq_num, additionalData);
		additionalData = adjustLength(additionalData, aLength);
		int additionalIndex = additionalData.length - (Record.LENGTH_BITS / 8);
		additionalData[additionalIndex] = (byte) ((payloadLength >> 8) & 0xff);
		additionalData[additionalIndex + 1] = (byte) (payloadLength & 0xff);
	}

	private byte[] adjustLength(byte[] data, int len) {
		byte[] adjusted = Arrays.copyOf(data, len);
		if (data.length < len) {
			byte[] temp = Bytes.createBytes(random, len - data.length);
			System.arraycopy(temp, 0, adjusted, data.length, temp.length);
		}
		return adjusted;
	}

	@Test
	public void testAes128Sha256Cryption() throws Exception {

		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, payloadData);
		byte[] decryptedData = CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, encryptedData);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	/**
	 * Test, if using a 256 key fore encryption and 128 key for decryption fails with invalid MAC.
	 * Check AES 256 with 1.8.0_144 requires strong encryption enabled
	 * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
	 * 1.8.0_171 seems to work out of box.
	 */
	@Test(expected = InvalidMacException.class)
	public void testAes256and128CryptionFails() throws Exception {
		assumeTrue("requires strong encryption enabled", strongEncryptionAvailable);
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, aesKey256, aesMacKey256, additionalData, payloadData);
		CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, encryptedData);
	}

	/**
	 * Check AES 256 with 1.8.0_144 requires strong encryption enabled
	 * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
	 * 1.8.0_171 seems to work out of box.
	 */
	@Test
	public void testAes256Sha384ryption() throws Exception {
		assumeTrue("requires strong encryption enabled", strongEncryptionAvailable);
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, aesKey256, aesMacKey256, additionalData, payloadData);
		byte[] decryptedData = CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, aesKey256, aesMacKey256, additionalData, encryptedData);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	/**
	 * Check AES 256 with 1.8.0_144 requires strong encryption enabled
	 * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
	 * 1.8.0_171 seems to work out of box.
	 */
	@Test
	public void testAes256ShaCryption() throws Exception {
		assumeTrue("requires strong encryption enabled", strongEncryptionAvailable);
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, aesKey256, aesMacKey256, additionalData, payloadData);
		byte[] decryptedData = CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, aesKey256, aesMacKey256, additionalData, encryptedData);
		assertTrue(Arrays.equals(decryptedData, payloadData));
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentNonce() throws Exception {
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, payloadData);
		encryptedData[0] ^= 0x55;
		CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, encryptedData);
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentAdditionalData() throws Exception {
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, payloadData);
		byte[] additionalData2 = Arrays.copyOf(additionalData, additionalData.length + 1);
		additionalData2[0] ^= 0x55;
		CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData2, encryptedData);
	}

	@Test(expected = InvalidMacException.class)
	public void testDifferentKey() throws Exception {
		byte[] encryptedData = CbcBlockCipher.encrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, aesKey, aesMacKey, additionalData, payloadData);
		byte[] aesKeyBytes = aesKey.getEncoded();
		aesKeyBytes[0] ^= 0x55;
		CbcBlockCipher.decrypt(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, new SecretKeySpec(aesKeyBytes, "AES"), aesMacKey, additionalData, encryptedData);
	}

	@Test
	public void testPaddingCheck() throws Exception {
		int padding = aLength;
		while (padding > 256) {
			padding >>>= 1;
		}
		byte[] data = Arrays.copyOf(payloadData, payloadLength + padding + 256);
		for (int index = payloadLength; index <= payloadLength + padding; ++index) {
			data[index] = (byte) padding;
		}
		assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength));
		if (payloadLength > 0) {
			data[payloadLength - 1] ^= 0x55;
			assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength));
		}
		data[payloadLength + padding + 1] ^= 0x55;
		assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength));
		byte[] broken = Arrays.copyOf(data, data.length);
		broken[payloadLength] ^= 0x55;
		assertFalse(CbcBlockCipher.checkPadding(padding, broken, payloadLength));
		broken = Arrays.copyOf(data, data.length);
		broken[payloadLength + padding] ^= 0x55;
		assertFalse(CbcBlockCipher.checkPadding(padding, broken, payloadLength));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPaddingException() throws Exception {
		CbcBlockCipher.checkPadding(1, payloadData, payloadLength - 256);
	}
	
}
