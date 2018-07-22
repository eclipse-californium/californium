/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verifies behavior of {@link RawPublicKeyIdentity}.
 *
 */
public class RawPublicKeyIdentityTest {

	private static final String URI_PREFIX = "ni:///sha-256;";
	private static PublicKey publicKey;

	/**
	 * Creates a public key.
	 */
	@BeforeClass
	public static void init() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = generator.generateKeyPair();
			publicKey = keyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// should not happen because every VM is required to support RSA
		}
	}

	@Test
	public void testGetNameReturnsNamedInterfaceUri() {
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(publicKey);
		assertThatNameIsValidNamedInterfaceUri(id.getName());
	}

	@Test
	public void testGetSubjectInfoReturnsEncodedKey() {
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(publicKey);
		assertArrayEquals(id.getKey().getEncoded(), id.getSubjectInfo());
	}

	@Test
	public void testConstructorCreatesPublicKeyFromSubjectInfo() throws GeneralSecurityException {

		// GIVEN a SubjectPublicKeyInfo object
		byte[] subjectInfo = publicKey.getEncoded();

		// WHEN creating a RawPublicKeyIdentity from it
		RawPublicKeyIdentity principal = new RawPublicKeyIdentity(subjectInfo, publicKey.getAlgorithm());

		// THEN the principal contains the public key corresponding to the subject info
		assertThat(principal.getKey(), is(publicKey));
	}

	private static void assertThatNameIsValidNamedInterfaceUri(String name) {
		assertTrue(name.startsWith(URI_PREFIX));
		String hash = name.substring(URI_PREFIX.length());
		assertFalse(hash.endsWith("="));
		assertFalse(hash.contains("+"));
		assertFalse(hash.contains("/"));
		assertFalse(hash.endsWith("\n"));
		assertFalse(hash.endsWith("\r"));
	}
}
