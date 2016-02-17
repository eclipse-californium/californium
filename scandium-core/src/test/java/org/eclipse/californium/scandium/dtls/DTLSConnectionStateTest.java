/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class DTLSConnectionStateTest {

	private static final Random RANDOM = new Random();

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testSerialization() {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DTLSConnectionState orig = newConnectionState(cipherSuite);
		DatagramWriter writer = new DatagramWriter();
		orig.serialize(writer);
		byte[] serializedState = writer.toByteArray();
		assertThat(serializedState, is(notNullValue()));

		DTLSConnectionState unmarshalled = DTLSConnectionState.deserialize(new DatagramReader(serializedState));
		assertThat(unmarshalled.getCipherSuite(), is(orig.getCipherSuite()));
		assertThat(unmarshalled.getCompressionMethod(), is(orig.getCompressionMethod()));
		assertThat(unmarshalled.getEncryptionKey().getEncoded(), is(orig.getEncryptionKey().getEncoded()));
		assertThat(unmarshalled.getIv().getIV(), is(orig.getIv().getIV()));
		if (cipherSuite.getMacKeyLength() > 0) {
			assertThat(unmarshalled.getMacKey(), is(orig.getMacKey()));
		}
	}

	static DTLSConnectionState newConnectionState(CipherSuite cipherSuite) {
		SecretKey macKey = null;
		if (cipherSuite.getMacKeyLength() > 0) {
			macKey = new SecretKeySpec(getRandomBytes(cipherSuite.getMacKeyLength()), "AES");
		}
		SecretKey encryptionKey = new SecretKeySpec(getRandomBytes(cipherSuite.getEncKeyLength()), "AES");
		IvParameterSpec iv = new IvParameterSpec(getRandomBytes(cipherSuite.getFixedIvLength()));
		return new DTLSConnectionState(cipherSuite, CompressionMethod.NULL, encryptionKey, iv, macKey);
	}

	static byte[] getRandomBytes(int length) {
		byte[] result = new byte[length];
		RANDOM.nextBytes(result);
		return result;
	}

}
