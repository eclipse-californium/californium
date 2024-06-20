/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.cloud.util;

import static org.junit.Assert.assertNotNull;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The ASN.1 signatures.
 * 
 * See
 * <a href="https://tools.ietf.org/html/rfc4492#section-5.4" target="_blank">
 * RFC 4492, section 5.4 Server Key Exchange</a> for details regarding the
 * message format.
 * 
 * According <a href="https://tools.ietf.org/html/rfc8422#section-5.1.1" target=
 * "_blank">RFC 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named
 * curves" are valid, the "prime" and "char2" curve descriptions are deprecated.
 * Also only "UNCOMPRESSED" as point format is valid, the other formats have
 * been deprecated.
 * 
 * @since 3.13
 */
public final class SignedMessageTest {

	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final Logger LOGGER = LoggerFactory.getLogger(SignedMessageTest.class);

	/**
	 * ASN.1 header for plain {@code secp256r1} public key.
	 */
	private static final byte[] ECC_SECP256R1_HEADER;

	static {
		// initialize header for secp256r1
		byte[] header = null;
		try {
			String oid = JceProviderUtil.getEdDsaStandardAlgorithmName("EC", "EC");
			KeyPairGenerator generator = KeyPairGenerator.getInstance(oid);
			generator.initialize(new ECGenParameterSpec("secp256r1"), RandomManager.currentSecureRandom());
			KeyPair keyPair = generator.generateKeyPair();
			byte[] encoded = keyPair.getPublic().getEncoded();
			header = Arrays.copyOf(encoded, encoded.length - 64);
		} catch (GeneralSecurityException ex) {
			header = null;
			LOGGER.error("EC failed!", ex);
		}
		ECC_SECP256R1_HEADER = header;
	}

	private static PublicKey parsePublicKey(byte[] publicKey) {
		Throwable error;
		try {
			return Asn1DerDecoder.readSubjectPublicKey(publicKey);
		} catch (GeneralSecurityException e) {
			error = e;
		} catch (IllegalArgumentException e) {
			error = e;
		}
		if (publicKey.length == 64) {
			publicKey = Bytes.concatenate(ECC_SECP256R1_HEADER, publicKey);
			try {
				return Asn1DerDecoder.readSubjectPublicKey(publicKey);
			} catch (GeneralSecurityException i) {
			} catch (IllegalArgumentException e) {
			}
		}
		LOGGER.warn("Parse public key failed:", error);
		return null;
	}

	/*
	 * cali.351358811124772=Demo .psk='cali.351358811124772',c3VwZXItMjAyMg==
	 * .dom=cloudcoap .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENt/
	 * ixvny7SnaCpqPYmhOkWN1uhAwDCjF5Hz78l+lj1JxoNT83hq4eFo8eGk1p8+r6T+
	 * Ycgna7QtPq8Nvx3L4KQ==
	 * .dig=BAMASDBGAiEAsBXrzRDrvFXcPGilUdH7FCblwxtwb4679k2PMtBjKVwCIQDsXtM4rU+
	 * Lu/RHNH++vgmW7B2hE8XdHcoCTcZQU8OayQ==
	 */

	/*
	 * .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZRd+
	 * 6w2dbCoDlIhrbkBkQdEHkiayS3CUgWYOanlU5curNy3H+MOheCqbmPZJdQud8KNvXXYTUyeYX
	 * /IqyOk8nQ== .sig=
	 * BAMARzBFAiEAioj8fh5VrTYMz93XakmlCS283zAv8JxWcpADnbwlhGwCIDwm5mEXP8MBV1o7w08a79d
	 * +y84w81vW9LgP8QbDCp/p
	 * 
	 */

	public static void main(String[] args) {
		SignedMessageTest test = new SignedMessageTest();
		try {
			test.testVerifySignature();
			System.out.println("Verfied!");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		byte[] k = StringUtil.hex2ByteArray("41C1CB6B51247A144321435B7A80E714896A33BBAD7294CA401455A194A949FA");
		System.out.println(k.length + " bytes.");
		System.out.println(StringUtil.byteArrayToBase64(k));
	}

	@Test
	public void testVerifySignature() throws GeneralSecurityException {
		byte[] data1 = null; // "cloudcoap".getBytes();
		byte[] data2 = StringUtil.base64ToByteArray(
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZRd+6w2dbCoDlIhrbkBkQdEHkiayS3CUgWYOanlU5curNy3H+MOheCqbmPZJdQud8KNvXXYTUyeYX/IqyOk8nQ==");
		byte[] data3 = StringUtil.base64ToByteArray(
				"BAMARzBFAiEAioj8fh5VrTYMz93XakmlCS283zAv8JxWcpADnbwlhGwCIDwm5mEXP8MBV1o7w08a79d+y84w81vW9LgP8QbDCp/p");
		PublicKey key = parsePublicKey(data2);
		assertNotNull(key);
		DatagramReader reader = new DatagramReader(data3);
		byte[] data0 = new byte[] { data1 == null ? 0 : (byte) data1.length };
		SignedMessage sign = SignedMessage.fromReader(reader);
		sign.verifySignature(key, data0, data1, data2);
	}

}
