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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.CoreMatchers.*;

import java.security.GeneralSecurityException;
import java.security.Signature;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class SignatureAndHashAlgorithmTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void testSignatureAndHashs() {
		int count = 0;
		int countEcdsa = 0;
		for (HashAlgorithm hash : HashAlgorithm.values()) {
			for (SignatureAlgorithm sign : SignatureAlgorithm.values()) {
				SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(hash,  sign);
				Signature signature = algo.getThreadLocalSignature().current();
				if (signature != null) {
					assertTrue(algo.isSupported());
					++count;
					if (sign == SignatureAlgorithm.ECDSA) {
						++countEcdsa;
					}
				} else {
					assertFalse(algo.isSupported());
				}
			}
		}
		assertTrue("no signatures available!", count > 0);
		assertTrue("no ECDSA signatures available!", countEcdsa > 0);
	}

	@Test
	public void testUnknownSignatureAndHashAlgorithm() {
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(80,  64);
		assertEquals("0x50with0x40", algo.toString());
		assertNull(algo.getJcaName());
		assertNotEquals(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA, algo);
	}

	@Test
	public void testUnknownSignatureAndHashAlgorithmCauseException() throws GeneralSecurityException {
		exception.expect(GeneralSecurityException.class);
		exception.expectMessage(containsString("UNKNOWN"));
		SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(80,  64);
		algo.getThreadLocalSignature().currentWithCause();
	}
}
