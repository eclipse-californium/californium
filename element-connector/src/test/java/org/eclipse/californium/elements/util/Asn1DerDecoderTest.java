/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verifies behavior of {@link Asn1DerDecoder}.
 */
public class Asn1DerDecoderTest {

	/**
	 * DH subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DH_BASE64 = "MIIBpjCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoCAgIAA4GEAAKBgH5J+o19W2ct7iGFz0/dLMaYLjCuw7TdaU2QtzZb5FmGj1TyglARYb9V3nKoqifSKlgnwFU8RBu61Sw5/gZYhAeap8kvPH7dwIrBNc4wbt5CMdicCZlSluOPrX6mYn9HzvuIaS0V8G11soSHikCCIp9gFeMLfI0AtbPOYDYD0jHA";
	/**
	 * EC subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EC_BASE64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx4ABEJuzneP12mmh/RLlE6lM58MIrngQtfOK/eguzwNuTEP0wrE3H0p9rg1fZywtwleyl7lYUcxa8mQPOi4mRA==";
	/**
	 * DSA subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DSA_BASE64 = "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAdp65TFSOhis6Ezu3Hq5LmKuu1eVDFkb1G/YuLOCYnkjG976B8G+W4TIVdM5yg7+Q0DU35mb2jrKHnRqnf5hRODnlp7kmUE2y1VBpgkx/9y+NYVMmfCqFqEn3c4DbWJvDcmvlKxG0okcSUdHcfxsF7grsyKB0RUTaXpwzdskHYo0=";
	/**
	 * RSA subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String RSA_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNPpjuSuq6BQ3/YGWbVpmNa0q+/vURtkbwPJIocT/b8QqmqdebnQxvADv9UpwWSrEyPkzY8Mq9bJRzRokJ8KQKbf9DTVFQmRmzikIk/Jwcm4+ST2plfHxDnywT9EYPrnNf6TrL/6fZsN0x1NMtr5unnlTND66HGNp+YMjqFgfnWwIDAQAB";

	/**
	 * Sequence, ASN.1 DER encoded.
	 */
	private static byte[] sequence;

	/**
	 * Creates a ASN.1 SEQUENCE.
	 * 
	 * @throws IOException
	 */
	@BeforeClass
	public static void init() throws IOException {
		// use subject public key as SEQUENCE
		sequence = Base64.decode(RSA_BASE64);
	}

	/**
	 * Test, if decoder can read entity (tag, length, and value).
	 */
	@Test
	public void testSequenceEntityDecoder() throws NoSuchAlgorithmException {
		DatagramReader reader = new DatagramReader(sequence);
		byte[] sequenceEntity = Asn1DerDecoder.readSequenceEntity(reader);
		assertThat(sequenceEntity, is(sequence));
	}

	/**
	 * Test, if decoder can read entity (tag, length, and value), when more data
	 * is available.
	 */
	@Test
	public void testSequenceEntityDecoderProvideMoreData() throws NoSuchAlgorithmException {
		byte[] more = Arrays.copyOf(sequence, sequence.length * 2);
		DatagramReader reader = new DatagramReader(more);
		byte[] sequenceEntity = Asn1DerDecoder.readSequenceEntity(reader);
		assertThat(sequenceEntity, is(sequence));
	}

	/**
	 * Test, if decoder can read RSA subject public key algorithm.
	 */
	@Test
	public void testKeyAlgorithmRsa() throws IOException {
		byte[] data = Base64.decode(RSA_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("RSA"));
	}

	/**
	 * Test, if decoder can read DSA subject public key algorithm.
	 */
	@Test
	public void testKeyAlgorithmDsa() throws IOException {
		byte[] data = Base64.decode(DSA_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("DSA"));
	}

	/**
	 * Test, if decoder can read EC subject public key algorithm.
	 */
	@Test
	public void testKeyAlgorithmEc() throws IOException {
		byte[] data = Base64.decode(EC_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("EC"));
	}

	/**
	 * Test, if decoder can read DH subject public key algorithm.
	 */
	@Test
	public void testKeyAlgorithmDH() throws IOException {
		byte[] data = Base64.decode(DH_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("DH"));
	}

	/**
	 * Test, if decoder handles the key algorithm synonym proper.
	 */
	@Test
	public void testEqualKeyAlgorithmSynonyms() throws NoSuchAlgorithmException {
		assertSynonym(true, "RSA", "RSA");
		assertSynonym(true, "DH", "DiffieHellman");
		assertSynonym(true, "DiffieHellman", "DiffieHellman");
		assertSynonym(true, "DiffieHellman", "DH");
		assertSynonym(false, "DH", "RSA");
		assertSynonym(false, "DSA", "DiffieHellman");
	}

	/**
	 * Assert, that the provided key algorithms are handled as synonyms.
	 * 
	 * @param expected {@code true}, if key algorithms should be valid synonyms,
	 *            {@code false}, otherwise.
	 * @param keyAlgorithm1 key algorithm
	 * @param keyAlgorithm2 key algorithm
	 */
	private void assertSynonym(boolean expected, String keyAlgorithm1, String keyAlgorithm2) {
		if (expected != Asn1DerDecoder.equalKeyAlgorithmSynonyms(keyAlgorithm1, keyAlgorithm2)) {
			if (expected) {
				fail(keyAlgorithm1 + " should be a valid synonym for " + keyAlgorithm2);
			} else {
				fail(keyAlgorithm1 + " should not be a valid synonym for " + keyAlgorithm2);
			}
		}
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data is too
	 * short.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testViolatesMinimumEntityLength() {
		byte[] data = { 0x30 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * no sequence.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testNoSequence() {
		byte[] data = { 0x31, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a too large length field.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testSequenceExceedsSupportedLengthBytes() {
		byte[] data = { 0x30, (byte) 0x85, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a length, which exceeds the provided data.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testSequenceExceedsSupportedLength() {
		byte[] data = { 0x30, (byte) 0x83, 0x01, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * no OID.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testNoOid() {
		byte[] data = { 0x31, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readOidValue(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a too large OID.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testOidExceedsSupportedLength() {
		byte[] data = { 0x30, 0x63, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readOidValue(reader);
	}
}
