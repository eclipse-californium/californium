/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class SignatureAndHashAlgorithmTest {

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	private static KeyPair ecdsa;
	private static KeyPair eddsa25519;
	private static KeyPair eddsa448;
	private static byte[] data;

	@BeforeClass
	public static void setup() {
		data = new byte[128];
		for (int index = 0; index < data.length; ++index) {
			data[index] = (byte) index;
		}
		ecdsa = TestCertificatesTools.getServerKeyPair();
		try {
			KeyPairGenerator kpg = new ThreadLocalKeyPairGenerator("Ed25519").currentWithCause();
			eddsa25519 = kpg.generateKeyPair();
		} catch (GeneralSecurityException e) {
		}
		try {
			KeyPairGenerator kpg = new ThreadLocalKeyPairGenerator("Ed448").currentWithCause();
			eddsa448 = kpg.generateKeyPair();
		} catch (GeneralSecurityException e) {
		}
	}

	@Test
	public void testEd25519Signature() throws GeneralSecurityException {
		assumeTrue("Ed25519 not supported!", eddsa25519 != null);
		Signature signature = new ThreadLocalSignature("Ed25519").currentWithCause();
		signAndVerify(signature, eddsa25519);
	}

	@Test
	public void testEd448Signature() throws GeneralSecurityException {
		assumeTrue("Ed448 not supported!", eddsa448 != null);
		Signature signature = new ThreadLocalSignature("Ed448").currentWithCause();
		signAndVerify(signature, eddsa448);
	}

	@Test
	public void testSignatureAndHashs() throws GeneralSecurityException {
		int count = 0;
		int countEcdsa = 0;
		int countEddsa = 0;
		for (HashAlgorithm hashAlgorithm : HashAlgorithm.values()) {
			for (SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
				SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm,
						signatureAlgorithm);
				Signature signature = signAndHash.getThreadLocalSignature().current();
				if (signature != null) {
					assertTrue(signAndHash.isSupported());
					++count;
					if (signatureAlgorithm == SignatureAlgorithm.ECDSA) {
						++countEcdsa;
						signAndVerify(signature, ecdsa);
					} else if (signatureAlgorithm == SignatureAlgorithm.ED25519) {
						++countEddsa;
						signAndVerify(signature, eddsa25519);
					} else if (signatureAlgorithm == SignatureAlgorithm.ED448) {
						++countEddsa;
						signAndVerify(signature, eddsa448);
					}
				} else {
					assertFalse(signAndHash.isSupported());
				}
			}
		}
		assertTrue("no signatures available!", count > 0);
		assertTrue("no ECDSA signatures available!", countEcdsa > 0);
		System.out.println("Signatures: " + count + " over all, " + countEcdsa + " ECDSA, " + countEddsa + " EdDSA.");
	}

	@Test
	public void testUnknownSignatureAndHashAlgorithm() {
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(80, 64);
		assertEquals("0x50with0x40", algo.toString());
		assertNull(algo.getJcaName());
		assertNotEquals(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA, algo);
	}

	@Test
	public void testUnknownSignatureAndHashAlgorithmCauseException() throws GeneralSecurityException {
		exception.expect(GeneralSecurityException.class);
		exception.expectMessage(containsString("UNKNOWN"));
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(80, 64);
		algo.getThreadLocalSignature().currentWithCause();
	}

	private void signAndVerify(Signature signature, KeyPair pair) throws GeneralSecurityException {
		TestCertificatesTools.assertSigning("", pair.getPrivate(), pair.getPublic(), signature);
	}
}
